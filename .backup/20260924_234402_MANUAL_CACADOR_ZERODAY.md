# MANUAL DE EXECUÇÃO — CAÇADOR AUTÔNOMO DE 0-DAY (zeroday_hunt)

Público: o autor, executando por conta própria. Cobertura: **1 host alvo**
ou **redes inteiras** (infra virtualizada). Nada aqui exige mexer em código.

Data: 2026-09-13 (rev5b — com fase de VERIFICAÇÃO de suspeitas: mínimo de
falso positivo). Diário técnico: `20260913_cacador_autonomo_zeroday.md`.

---

## 1. Pré-requisitos (uma vez só)

1. **Docker + compose** no host.
2. **Ollama no host** com o modelo `gpt-oss:20b` baixado (o compose já
   aponta para `http://localhost:11434/v1`). Verificar antes de caçar:
   ```bash
   ollama ps          # deve listar gpt-oss:20b (se vazio, rode 1x p/ aquecer)
   systemctl status ollama
   ```
   (Ollama já configurado para GPU0+GPU1 via drop-in systemd.)
3. **Imagem do container** construída:
   ```bash
   cd /llm/projeto-tese/adversarial-cybersec/docker/pentest
   docker compose build
   ```
4. Alvo alcançável pela rede do host (ping/portas abertas).

Sem Ollama funcionando, a caça ainda roda com `--no-llm` (só a bateria
determinística — que é quem acha a maioria das falhas comuns).

---

## 2. O INVENTÁRIO — mecanismo completo

O inventário é um **YAML declarativo** que faz três coisas:

1. **Autoriza** (`authorization.allowed_cidrs`): TODO IP sondado precisa
   estar dentro de um destes CIDRs. É o gate de escopo — na run real de
   13/09 o LLM digitou um IP errado e o gate bloqueiu na hora.
2. **Define o alvo** (`target.seed_host_ip` + `target.subnet`): o sweep
   varre a `subnet` inteira e caça TODO host vivo que estiver dentro dos
   CIDRs autorizados. **Host único = subnet /32.**
3. **Declara credenciais e limites**: SSH (só as credenciais listadas
   podem ser usadas — o LLM não improvisa nada), crown jewel, listener C2,
   budgets de tempo.

### Onde criar o arquivo

Crie/arquivo no HOST em:

```
/llm/projeto-tese/adversarial-cybersec/configs/pentest/<nome>.yaml
```

O compose monta essa pasta como `/inventory` (read-only) dentro do
container. Referencie no comando como `--inventory /inventory/<nome>.yaml`.

### Todos os campos (com default)

```yaml
authorization:
  owner: "seu-nome"            # OBRIGATÓRIO — dono do ambiente (auditoria)
  allowed_cidrs:               # OBRIGATÓRIO — escopo autorizado (lista)
    - "192.168.10.0/24"

target:
  seed_host_ip: "192.168.10.14"   # OBRIGATÓRIO — alvo principal
  subnet: "192.168.10.0/24"       # o que o sweep varre (rede) ou /32 (host)
  ssh_creds:                      # OBRIGATÓRIO ≥1 (gate de validação).
    - username: "ubuntu"          # Mesmo que a caça não use SSH, informe
      password: "ubuntu"          # a credencial de laboratório. O caçador
      port: 22                    # SÓ usa o que estiver aqui listado.
    # - username: "root"
    #   key_path: "/checkpoints/id_rsa"   # alternativa por chave

crown_jewel:                     # NÃO usado no modo caça (é do modo
  path: "/etc/hostname"          # campanha/kill chain); pode deixar assim.
  min_bytes: 1

c2:
  listener_host: "0.0.0.0"       # listener de canário OOB (detecção de
  listener_port: 4444            # SSRF/RCE cego) — porta livre no host.

impact:
  allowed_services: []           # caçador não faz IMPACT; deixar vazio.

limits:
  max_wall_clock_seconds: 3600   # budget total (default 1h; use
                                 # --wall-clock p/ sobrescrever)
  ssh_connect_timeout: 10
  c2_callback_wait: 90           # espera máx. de callback OOB por sonda

bruteforce:                      # OPT-IN, default desligado. O caçador
  enabled: false                 # NÃO faz brute-force (não é caça a 0-day).
```

### Exemplo A — HOST ÚNICO (arquivo `configs/pentest/host_unica.yaml`)

```yaml
authorization:
  owner: "overcyber"
  allowed_cidrs: ["192.168.10.0/24"]
target:
  seed_host_ip: "192.168.10.14"
  subnet: "192.168.10.14/32"        # /32 = varre/caça SOMENTE este host
  ssh_creds:
    - username: "ubuntu"
      password: "ubuntu"
crown_jewel: {path: "/etc/hostname", min_bytes: 1}
c2: {listener_host: "0.0.0.0", listener_port: 4444}
impact: {allowed_services: []}
limits: {max_wall_clock_seconds: 5400}
```

### Exemplo B — REDE INTEIRA / infra virtualizada (`configs/pentest/rede_lab.yaml`)

```yaml
authorization:
  owner: "overcyber"
  allowed_cidrs:
    - "192.168.56.0/24"      # rede VirtualBox host-only
    - "192.168.10.0/24"      # rede física do lab
target:
  seed_host_ip: "192.168.56.101"     # por onde começar (sempre caçado,
  subnet: "192.168.56.0/24"          #   mesmo que não responda ping)
  ssh_creds:
    - username: "lab"
      password: "lab"
crown_jewel: {path: "/etc/hostname", min_bytes: 1}
c2: {listener_host: "0.0.0.0", listener_port: 4444}
impact: {allowed_services: []}
limits: {max_wall_clock_seconds: 10800}   # rede inteira: 3h
```

Regras de ouro:
- **`subnet` ⊆ `allowed_cidrs`** — host fora dos CIDRs é pulado.
- Hosts que **bloqueiam ping** não aparecem no sweep, MAS o
  `seed_host_ip` é sempre caçado. Para hosts que bloqueiam ICMP: rode uma
  caçada por host (`subnet: "<ip>/32"`).
- Válido também trocar alvo **sem editar YAML**: `--target-ip` +
  `--subnet` (o /24 do IP é autorizado junto).

---

## 3. O COMANDO — explicado em detalhe

```bash
cd /llm/projeto-tese/adversarial-cybersec/docker/pentest

docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.zeroday_hunt \
    --inventory /inventory/inventory.yaml \
    --i-am-authorized \
    --wall-clock 5400
```

| Trecho | O que faz |
|---|---|
| `cd docker/pentest` | pasta do compose da stack **isolada** `pentest-lab` (não toca em nenhum serviço do projeto principal). |
| `docker compose run --rm pentest-brain` | cria um container **efêmero** da imagem `pentest-brain` e o remove ao sair. O container usa `network_mode: host` (rede do próprio host: alcança os alvos E binda o listener C2 :4444 para canários OOB), monta o repo read-only em `/repo`, checkpoints em `/checkpoints`, o inventário em `/inventory` e **grava saídas** em `data/pentest_runs/` (rw). |
| `--entrypoint python` | a imagem tem como entrada padrão o CLI de campanha (`pentest-harness`); sobrescrevemos para executar como módulo Python. |
| `-m services.pentest.app.zeroday_hunt` | executa o módulo do **caçador** (função `main()`): F0 sweep → F1 nmap 1-65535 + `-sV` → F2 bateria genérica por porta → **F2.5 verificação de suspeitas** → F3 LLM caça por host → F4 veredito + auditoria dupla. |
| `--inventory /inventory/inventory.yaml` | o YAML criado na seção 2 (troque o nome do arquivo). Obrigatório. |
| `--i-am-authorized` | atestado de ambiente próprio — destrava a execução real (gate de segurança). Sem ele, apenas `--dry-run`. |
| `--wall-clock 5400` | budget total de 90 min (padrão do YAML pode ser maior/menor; a flag sobrescreve em memória). Ao estourar, a caça para com segurança e ainda gera relatório. |

### Flags opcionais

| Flag | Default | Efeito |
|---|---|---|
| `--target-ip IP` | — | sobrescreve o alvo do YAML (autoriza o /24 do IP junto) |
| `--subnet CIDR` | — | sobrescreve a subnet varrida (use `IP/32` p/ host único) |
| `--port-range R` | `1-65535` | ex. `1-10000` para caçadas mais rápidas |
| `--rounds N` | 14 | rodadas do LLM por host (mais = mais hipóteses testadas) |
| `--max-cmds-host N` | 24 | teto de `run_command` por host |
| `--no-llm` | — | só a bateria determinística (rápido, sem Ollama) |
| `--model NOME` | `gpt-oss:20b` | outro modelo do Ollama |
| `--dry-run` | — | não executa nada real (revisar o fluxo) |
| `--runs-root DIR` | `data/pentest_runs` | onde criar a pasta da run |

---

## 4. Saídas — `data/pentest_runs/<stamp>_zeroday/`

| Arquivo | Conteúdo |
|---|---|
| `hunt_report.md` | **relatório legível**: tabela de achados + descartados + metodologia |
| `findings.json` | achados estruturados (host/porta/classe/veredito/prova/evidência) + descartados por host |
| `events.ndjson` | cada fase, sonda, verificação (com motivo), finding, erro |
| `evidence/` + `evidence_manifest.json` | toda evidência com sha256 (auditoria re-verifica) |
| `llm_calls.ndjson`, `llm_transcripts/` | cada chamada ao LLM + conversa completa por host |
| `audit_report.json` | auditoria dupla (harness + caça) — `pass: true` obrigatório |
| `hunt.log`, `run_config.json` | console integral + configuração da run |

---

## 5. Vereditos — política anti-falso-positivo

- **confirmed** = prova executável na sua mão: token canário único
  refletido/ecoado, callback OOB que chegou ao listener, assinatura de
  conteúdo real (/etc/passwd, `[core]` do .git), resposta de protocolo que
  **concede** acesso (FTP 230, Redis +PONG/INFO, MQTT CONNACK rc=0,
  memcached STAT, SNMP public), PUT+GET roundtrip, TRACE refletindo.
- **discarded** = falso positivo **demonstrado** (removido dos achados,
  listado com motivo): SPA servindo a mesma página para toda rota, header
  sem efeito observável, "exception" genérica sem frame de stack,
  comportamento seguro (FTP negando anônimo, Redis com senha, MQTT
  exigindo auth), OPTIONS anunciando método que não funciona.
- **suspect** = anomalia real que a sonda genérica não consegue provar
  nem refutar (ex.: X-Original-URL alterando resposta de /admin de forma
  específica). Vai para o briefing do LLM como **prioridade máxima**.
- Confirmed do LLM sem arquivo de evidência é **rebaixado**
  automaticamente; a auditoria re-verifica arquivo+sha256 de TODO
  confirmed. Run só vale com `audit_report.json` → `pass: true`.

### Como conferir um achado na mão (exemplos)

```bash
# Redis sem auth (confirmed .14:6380)
redis-cli -h 192.168.10.14 -p 6380 PING        # +PONG = confirmado

# Traversal .14:8081
curl -s "http://192.168.10.14:8081/download?file=../../../../etc/passwd"

# Reflexão :8081/:3127/:3129
curl -s "http://192.168.10.14:8081/?q=PENTEST_TESTE_123" | grep PENTEST_TESTE_123

# .git exposto (.48:8083)
curl -s http://192.168.10.48:8083/.git/config | head
```

---

## 6. Segurança e limites

- Escopo travado por CIDR; denylist de comandos destrutivos; allowlist de
  binários; credenciais só do inventário; sem brute-force no caçador.
- O PUT de verificação cria UM arquivo-canário em caminho aleatório e o
  remove (DELETE) — se a limpeza falhar, o relatório avisa.
- Ausência de achado **não** prova ausência de vulnerabilidade: a
  superfície é o range de portas + a bateria + o que o LLM levantar.
- Protocolos binários desconhecidos dependem da fase LLM (banner bruto no
  briefing). Para aprofundar um host: rode de novo com `--rounds 20` e
  `--subnet <ip>/32`.

## 7. Atribuição de efetividade (rev6) — o quanto o .pt e o LLM ajudaram

Toda run real (campanha OU caçada) gera `attribution.md`/`attribution.json`
na própria pasta, com 4 blocos: efetividade da política .pt (taxa de
sucesso por ação tática com canário, mask-fit, progressão), contribuição
do LLM (ferramenta DECISIVA por sucesso = a que produziu a prova;
desperdício; latência; amplitude por host), cobertura da Cyber Kill Chain
(7 estágios Lockheed, com evidências) e TTPs além do MITRE (vetores
comportamentais inéditos no registro persistente `ttp_registry.json`,
com CWE/CAPEC).

Re-derive/audite qualquer run (o recálculo tem que ser idêntico):

```bash
cd docker/pentest
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.attribution --verify /repo/data/pentest_runs/<run>
```

Delta A/B da contribuição do LLM na campanha: rode a mesma campanha com
`--no-llm` e compare os `attribution.json` das duas.

## 8. Troubleshooting

| Sintoma | Causa/ação |
|---|---|
| `LLM indisponivel na fase de cacaca` | Ollama fora/sobrecarga → `systemctl status ollama`, `ollama ps`, aqueça o modelo e rode de novo (a parte determinística da run continua valendo) |
| `error: the following arguments are required: --inventory` | esqueceu `--entrypoint python` (caiu no CLI de campanha) |
| Nenhum host no sweep | firewall/ICMP bloqueado → use `subnet: "<ip>/32` por host |
| `pass: false` no audit_report | leia `checks` — todo confirmado precisa de evidência íntegra; reporte se acontecer |

## 9. Intel de CVE/exploit (rev7) — feed local, searchsploit e GitHub

**Espelho local do feed de CVEs** (reprodutível, offline):
```bash
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_feed sync --years 2022-2026   # full+incremental
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_feed index  --years 2022-2026  # índice sqlite
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_feed lookup CVE-2024-6387      # consulta offline
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_feed search redis
```
Armazenamento: `data/cve_feed/` (repo cvelistV5 + índice + proveniência).
NVD API 2.0 opcional com `--nvd` (env NVD_API_KEY).

**Exploits reais** (busca combinada com evidência):
```bash
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.exploit_search --cve 2024-6387 --online
#   --term "redis 6" | --nmap-xml <arquivo.xml> | --mirror <id> (copia p/ evidência)
```
O LLM tem as mesmas capacidades pelas tools `exploit_search` e
`cve_lookup` (esquemas + guia no prompt — passo 0 "INTEL PRIMEIRO").

**Validação de CVE por PoC inofensivo** (integrada à caçada, fase F2.7,
ou standalone):
```bash
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_validate \
    --inventory /inventory/inventory.yaml --i-am-authorized
```
Vereditos: `confirmed_precondicao` (PoC provou a pré-condição) /
`candidata_version` (na faixa; backport não muda string — não confirma) /
`refutada_versao` / `refutada_precondicao` / `nao_aplicavel`.

## 11. PILOT — teste do modelo .pt com UM comando (rev11)

Caçada (acha falhas + túnel + credenciais observadas) → inventário
estendido (creds com proveniência; gate ssh_login continua íntegro) →
campanha .pt+LLM (o .pt escolhe a vulnerabilidade — uma ou todas; LLM
compõe TTPs novas com as primitivas e prova com canário; kill chain via
túnel quando confirmado) → PILOT_REPORT.md consolidado (efetividade do
.pt, contribuição do LLM, CKC, auditorias).

```bash
cd docker/pentest
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.pilot \
    --inventory /inventory/inventory.yaml --target-ip 192.168.56.110 \
    --checkpoint /checkpoints/maestro_red_ep1246800.pt \
    --i-am-authorized [--rounds 16] [--max-steps 40] [--wall-clock 5400]
```
Saída: `data/pentest_runs/<stamp>_pilot/` (hunt/ + campaign/ +
inventory_estendido.yaml + extended_creds.json + hunt_context.json +
PILOT_REPORT.md).
