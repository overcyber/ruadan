# 2026-09-28 — Camada de Evasão Ruadan (anti-bloqueio + anti-fita)

## Contexto

O usuário instalou uma **defesa ativa no lab** que:
1. **Emula portas e serviços** ("fita") — respondem como se fossem reais para sugar o atacante e queimar seu budget de tentativas
2. **Bloqueia por IP** depois de X tentativas (ou X tempo sem resposta)
3. O container de ataque precisa **rotacionar de IP** quando bloqueado

A versão anterior dos fuzzers não tinha NENHUM mecanismo contra isso: tudo saía de um único IP (192.168.50.210 via `--network host`), sem rate, sem detecção de bloqueio, sem estado compartilhado entre ferramentas.

## Diagnóstico do comportamento antigo

| Problema | Evidência |
|---|---|
| IP único de origem | docker-run.sh usa `--network host`; enp5s0 tem só 192.168.50.210 |
| Budget queimado em portas emuladas | param_fuzz rodou em **13 portas** do juice.octopux (80, 443, 3128, 5800, 8000, 8008, 8080, 8081, 8443, 8888, ...) — maioria fita |
| Bug de request duplo | param_fuzz/api_fuzz/recursive_fuzz enviavam cada payload **2x** (um curl pro body, outro pro status) → 2x o budget |
| 40 threads concorrentes | web_fuzz: `ffuf -t 40` sem rate → bloqueio instantâneo |
| Sem detecção de bloqueio | recursive_fuzz pendurou **1594s (26min)** numa porta — a maior parte já bloqueado, esperando timeouts de 15s um a um |
| Sem estado entre ferramentas | cada fuzzer começava do zero; a defesa conta por IP, o Ruadan contava por ferramenta |

## Arquitetura implementada

```
┌────────────────────────────────────────────────────────────────┐
│ config.ini [EVASION]  ← fonte única (enabled, ip_pool, budgets) │
├────────────────────────────────────────────────────────────────┤
│ evasion_lib.sh        ← núcleo sourced por todos os fuzzers    │
│  • Budget GLOBAL por alvo (todas as ferramentas compartilham)   │
│  • Janela deslizante de códigos HTTP → detecção de bloqueio    │
│    (K1× 403/429, K2× timeout 000, K3× misto — sua regra do X)   │
│  • Rotação de identidade: 0=IP direto, 1..N=pool ip_pool       │
│    curl --interface <ip>; ffuf -x socks5://127.0.0.1:108xx     │
│  • Cooldown APRENDIDO empiricamente (quando a defesa desbloqueia)│
│  • Rotação PROATIVA (70% do threshold observado da defesa)     │
│  • Jitter + rate limit desde o primeiro request                 │
│  • Pula portas emuladas + aborto gracioso (exit 0)              │
│  • MODO DESLIGADO (enabled=0): padrão de requests IDÊNTICO ao  │
│    original (roda o run forense sem mudar nada)                │
├────────────────────────────────────────────────────────────────┤
│ evasion_pool.sh       ← aliases de IP + 3proxy SOCKS5 (-e <ip>) │
│ emulation_check.sh    ← detector de fita: TTL (nping), timing   │
│   sintético, body-clone, cross-port-clone → EMULATED_SERVICE    │
│ defense_fingerprint.sh← como a defesa bloqueia: silent_drop/   │
│   reset/tarpit/http_403 + teste de IPS inline (assinatura)      │
├────────────────────────────────────────────────────────────────┤
│ 6 fuzzers reescritos: param_fuzz, web_fuzz, api_fuzz,           │
│   recursive_fuzz, api_route_extract, spa_route_extract          │
│ Dockerfile: +3proxy │ docker-run.sh: lifecycle do pool          │
│ test/: mock_blocker.py + evasion_selftest.sh (bateria 16 tests) │
└────────────────────────────────────────────────────────────────┘
```

### Decisões-chave
- **`enabled=0` = paridade forense**: o run em andamento (PASSO 9/40) continua com o comportamento antigo byte-a-byte — inclusive o bug de request duplo e o `-t 40`. Só troca pra `1` quando o run terminar.
- **Estado em `output/<alvo>/evasion_state.env`** (flock): sobrevive entre fases e containers (output é mount do host). IPs queimados com timestamp, cooldown aprendido, budget gasto, portas emuladas, threshold observado da defesa.
- **Pool NÃO sobe com evasão desligada** (docker-run.sh `ensure_evasion_pool` checa o config) — nenhum alias aparece na rede do lab enquanto o run forense roda.
- **curl usa `--interface` direto** (sem proxy, menor latência); só ffuf/gobuster (sem source-bind) usam o SOCKS5 do pool. Se o 3proxy estiver ausente, curl continua rotacionando e ffuf roda direto (degradação graciosa).
- **Findings novos no config.ini**: EMULATED_SERVICE, TARGET_BLOCKED, IP_ROTATED, FIREWALL_DETECTED, IPS_SIGNATURE_DETECTED, EVASION_BUDGET_EXHAUSTED, EVASION_POOL_EXHAUSTED.

## Bugs encontrados e corrigidos DURANTE os testes

1. **Env-clobber na lib** (crítico): os defaults de source-time (`EV_ENABLED=""` etc.) sobrescreviam as variáveis de ambiente do processo pai → ev_init lia `enabled=0` mesmo com `EV_ENABLED=1`. Fix: todos os defaults viraram `${VAR:-}`.
2. **Expansor de range**: só suportava `A.B.C.240-249`; o teste usava forma IP-completo `127.0.0.2-127.0.0.11` → alias literal inválido. Fix: suporte às duas formas.
3. **Floor de aprendizado**: cooldown só era registrado com delta ≥ 30s — defesas que desbloqueiam rápido nunca aprendiam. Fix: floor configurável (`cooldown_learn_min = 5`).
4. **Subscript negativo**: `EV_POOL_IPS[-1]` no ev_on_block quando identidade=0 → erro bash. Fix: guard.
5. **URLs com payload cru** (achado na integração): curl falha no lado cliente com espaço/aspas na URL → rajada de falsos 000 → falso bloqueio. O param_fuzz/api_fuzz ORIGINAL tinha o mesmo defeito (por isso o forense mostra `HTTP 000` em findings XSS). Fix: `ev_urlencode()` aplicado ao payload **só no modo ligado**; no modo desligado o padrão idêntico ao histórico é preservado (paridade forense).
6. **Scripts standalone** (emulation_check/defense_fingerprint) não criavam o state_dir → estado silenciosamente não persistia. Fix: mkdir -p.

## Resultados dos testes (16/16 PASS — bateria completa)

| Teste | Resultado |
|---|---|
| T1 Modo desligado = padrão de requests original (8 reqs: 2+2+2+1+1), sem estado | PASS |
| T2 Budget aborta exatamente no limite + EVASION_BUDGET_EXHAUSTED | PASS |
| T3 Bloqueio 403 → TARGET_BLOCKED(5x) + IP_ROTATED(14x), **11 IPs de origem distintos no mock** | PASS |
| T4 Bloqueio por DROP (sem resposta) → detecção via timeouts (regra "sem resposta em X tempo") | PASS |
| T5a Fita (corpo idêntico p/ qualquer path) → EMULATED_SERVICE **high** | PASS |
| T5b emulated_ports persistido no estado | PASS |
| T5c porta wildcard-403 REAL não marcada (sem falso positivo) | PASS |
| T5d fuzzer pula porta emulada (ev_skip_port) | PASS |
| T6 Fingerprint: FIREWALL_DETECTED behavior=http_responds block_layer=http_403 + defense_profile persistido | PASS |
| T7 Cooldown APRENDIDO empiricamente (6-7s; defesa desbloqueou e voltamos ao IP queimado) | PASS |
| T8 Pool lifecycle: up adiciona aliases, down remove | PASS |
| Integração: param_fuzz real vs mock — 84 requests, **0 falsos bloqueios**, budget contado (82), todas as seções completas | PASS |

Logs completos: `/tmp/opencode/evselftest/` + `/tmp/opencode/selftest_final.log`.

## Procedimento de ATIVAÇÃO (após o run forense terminar)

```bash
# 1. Rebuild da imagem (só adiciona a layer do 3proxy — cache barato)
cd /system/ruadan-new/ruadan && docker build -t ruadan:kali .

# 2. Ligar a evasão
sed -i 's/^enabled = 0/enabled = 1/' config.ini   # seção [EVASION]

# 3. Rodar normalmente — o pool (aliases 192.168.50.240-249 + SOCKS5) sobe sozinho
./start.sh -hostFile /ruadan/targets/meu_lab.txt
```

O docker-run.sh derruba o pool no fim (trap) e o próximo `up` é idempotente.

## Estado do run forense no momento da escrita

- Container: 10h+, **PASSO 9/40** — EXPLOIT_REMOTE em **192.168.50.222** (o VMware, o alvo com CVEs reais)
- **A ponte vulscan→F2.6 FUNCIONOU**: 39 CVEs ≥ 7.0 extraídas dos 2 alvos, 42 candidatas no .222, exploits executados (CVE-2023-48795, CVE-2020-11950, CVE-2026-*)
- .222: **SUCCESS (2 findings confirmados: dns_version_disclosure + reflection)**
- .160: FAILED_TARGET_HARD — budget do host esgotado antes da fase LLM (o hunt já tinha budget próprio; o budget da camada de evasão vai endireitar isso entre ferramentas)
- O wrapper `start.sh` morreu no timeout de 4h do harness, mas o container segue (PASSO 9) — output montado no host, nada perdido. Quando a campanha acabar o container sai sozinho (`--rm`).

## Pendências (pós-run forense)

1. **Flip `enabled=1`** + rebuild + run real contra a defesa do lab
2. **Validar ffuf via SOCKS no container** (o chunked path do web_fuzz foi testado por partes no host — o host não tem ffuf; o container valida no run real)
3. **Threshold X da defesa real**: o primeiro bloqueio real ensina `block_threshold_learned` e o sistema passa a rotacionar proativamente antes de queimar
4. Integração opcional no lado Python (hunt_suite/zeroday lendo evasion_state para pular alvo bloqueado) — a camada bash já protege os fuzzers; o hunt tem budget próprio
5. sqlmap_login_probe e demais tools ainda não são budget-aware (os pesados eram os 6 fuzzers — cobertos)

## Backups (regra imutável)

Todos os arquivos alterados estão em `.backup/` com timestamp `20260928_*`:
param_fuzz.sh, api_fuzz.sh, recursive_fuzz.sh, api_route_extract.sh, web_fuzz.sh, spa_route_extract.sh, config.ini, Dockerfile, docker-run.sh, evasion_lib.sh (múltiplas revisões), evasion_selftest.sh, evasion/ (dir quebrado das tentativas anteriores).
