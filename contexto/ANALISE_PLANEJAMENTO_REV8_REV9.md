# Análise Universal — Ruadan + red-MPPO + Ollama para QUALQUER host, rede e N máquinas

**Data:** 2026-09-24 (rev2 — re-análise sem vínculo a laboratório específico)  
**Base:** rev8/rev9 + código-fonte (`agent.py`, `zeroday_hunt.py`, `state_adapter.py`, `tools.py`, `session.py`, `pilot.py`, `inventory.py`)  
**Lente:** o sistema deve funcionar contra **alvo arbitrário × rede arbitrária × escala arbitrária** — a política é vendida como "invariante a N hosts (13, 30, 40, 50 sem retraining)" (`agent.py:7`); a análise mede onde isso é **verdade por construção**, onde é **afirmado sem prova**, e onde o código **trava** a universalidade.

---

## 1. AS 6 DIMENSÕES DE UNIVERSALIDADE (veredito por dimensão)

| # | Dimensão | Veredito | Evidência central |
|---|---|---|---|
| 1 | **Alvo arbitrário** (qualquer produto/porta/protocolo) | 🟢 **FORTE** | `net_probe` RAW TCP/UDP p/ protocolo desconhecido + bateria por protocolo + LLM dirigindo hipóteses; `exploit_search` aceita XML de **qualquer** nmap/termo livre; fallback `candidata_searchsploit` p/ **qualquer** produto sem entrada curada (rev9) |
| 2 | **Rede arbitrária** (CIDRs múltiplos, /32→/16, multi-interface) | 🟢 **FORTE** | Inventário declarativo por CIDR (`inventory.py:76-106` gate `ip_allowed`); `--target-ip`/`--subnet` trocam alvo sem editar YAML; seed sempre caçado mesmo ping-bloqueado |
| 3 | **Escala arbitrária** (N hosts: 1→1000+) | 🟡 **PARCIAL** | **Bloqueios concretos**: teto hardcoded `extras[:8]` (`zeroday_hunt.py:515`), budget global sem alocação por host, caça sequencial sem priorização, nmap full-range por host, arestas O(N²) por passo (`state_adapter.py:324-329`) |
| 4 | **Política invariante a N** | 🟡 **DESIGN OK, PROVA FALTA** | `build_obs` = 8 frações normalizadas (`state_adapter.py:162-179`) ✓; pointer sobre N hosts ✓; GAT com node features **constantes** (`agent.py:217-223`) codifica só topologia; held-out topológico (#13) **nunca executado** — invariância é afirmação, não demonstração |
| 5 | **Conhecimento genérico** (não curado p/ 1 lab) | 🟡 **EM EXPANSÃO** | CVE feed local 200k+ offline ✓; curadoria por CLASSE ainda pequena (P0); vereditos de cve_validate são por classe de PoC, não por laboratório ✓ |
| 6 | **Execução distribuída** (rede grande = paralelo) | 🟢 **POSSÍVEL HOJE** | pentest-brain **não tem lock** (o lock é do ruadan:kali, `docker-run.sh:63-80`); `--runs-root` distinto = N caçadas paralelas já suportadas; falta playbook de shard + merge |

**Síntese:** o núcleo (gate de escopo, primitivas, prova executável, auditoria, política fatorada) é universal **por construção**. Os travadores estão na **camada de orquestração de escala** (budget, priorização, paralelismo, curadoria) e em **2 bugs de genericidade** (subnet /24-only, regex de evidência).

---

## 2. O QUE JÁ É UNIVERSAL (não mexer — proteger)

### 2.1 Escopo e autorização (qualquer rede)
- `authorization.allowed_cidrs` — lista arbitrária de CIDRs, IPv4/IPv6 aceitos pelo `ipaddress` (`inventory.py:76-94`)
- TODO IP sondado passa por `ip_allowed()` (`inventory.py:101-106`) — o LLM digitar IP fora do escopo é bloqueado (comprovado na run real)
- `subnet: "<ip>/32"` = host único; `/24`…`/16` = rede inteira; **multi-interface** = múltiplos CIDRs + `--expand-all`
- Secrets via `${ENV_VAR}` — credencial nunca hardcoded no inventário (`inventory.py:21-36`)

### 2.2 Primitivas universais (qualquer serviço)
- `http_probe` — HTTP arbitrário (método/path/headers/body) + canário OOB
- `net_probe` — RAW TCP/UDP com bytes arbitrários — **qualquer protocolo, incluindo binário sem nome**; OOB cego via payload
- `run_command` — arsenal completo (nmap/ffuf/sqlmap/searchsploit/…) com allowlist+denylist+evidência
- `exploit_search(cve|termo|nmap_xml)` — INTEL de **qualquer** fingerprint, não de um lab
- Veredito anti-FP por **assinatura de comportamento** (FTP 230, Redis +PONG, MQTT CONNACK rc=0, reflexão de token, callback OOB) — classes, não produtos

### 2.3 Política RL invariante a N (design)
- **obs global (8-dim)**: `discovered/n`, `counts[k]/nd`, `c2/n`, `step/max_steps` — **todas frações** → mesmo vetor em N=10 ou N=500 (`state_adapter.py:162-179`)
- **host_features (N,7)**: vuln, status/6, compromised, discovered, subnet/n_subnets, degree/max_degree — **normalizadas por host** (`state_adapter.py:132-151`)
- **PointerHead** sobre N host keys — target space aberto, sem retraining ao mudar N
- **action/target masks por pré-condição de kill chain** (`state_adapter.py:181-260`) — geradas para QUALQUER N
- **Fix rev8 completo** do contrato π(a|s,M): mesmo operador de máscara no act/update/bootstrap/GumbelSoftmax (`agent.py:396-417, 637-645, 709-714`)

### 2.4 Orquestração (qualquer alvo como parâmetro)
- `pilot.py --target-ip` é **parâmetro**, não constante; `--inventory` também
- Toda run é autocontida e auditável (`audit_report.json` `pass:true` obrigatório) — independe do alvo
- `attribution --verify <run>` re-deriva de **qualquer** pasta de run — determinístico

---

## 3. ONDE O SISTEMA TRAVA A UNIVERSALIDADE (arquivo:linha → fix)

### 3.A Escala de hosts (o "qualquer número de máquinas" na prática)

| # | Bloqueio | Local | Impacto em rede grande | Fix |
|---|---|---|---|---|
| A1 | **Teto hardcoded de expansão** `extras[:8]` | `zeroday_hunt.py:515` | com `--expand-all`, só 8 hosts das redes extras são caçados — uma /24 com 200 vivos ignora 192 | flag `--max-hosts N` (default: ilimitado dentro do budget); teto vira log, não silêncio |
| A2 | **Budget global único** sem alocação por host | `zeroday_hunt.py:run()` + `limits.max_wall_clock_seconds` | 100 hosts ÷ 1h ≈ 36s/host — o LLM precisa de minutos/host; hosts do fim da lista nem são visitados | `--per-host-budget` (auto: `max(floor, wall_clock/n_hosts)`); relatório lista hosts **não cobertos** por budget (honestidade de cobertura) |
| A3 | **Caça sequencial sem priorização** | `run()` — itera `ips` na ordem do sweep | hosts com superfície rica ficam no fim e são cortados pelo budget | score de superfície (n° portas abertas, riqueza de banner, CVE-candidatas) → ordenar descendente; reordenar após F1 |
| A4 | **nmap 1-65535 por host, sequencial** (600s/host) | `zeroday_hunt.py:scan_ports:234-236` | N=100 → horas só de F1, antes de qualquer bateria | two-phase: top-1000 em todos → full-range **só nos hosts com superfície** (flag `--fast-first`) |
| A5 | **`self.events` em RAM sem teto** | `zeroday_hunt.py:184-193` | duplicação do events.ndjson; 1000 hosts × ~50 eventos = dezenas de MB inúteis (e cresce) | manter só flag `terminated` + contadores; ndjson é a fonte |
| A6 | **SSH ControlMaster por (host,cred)** persistente | `session.py:36,54` (`ControlPersist=yes`) | centenas de mux sockets → `ulimit -n` e lixo de `/tmp` | LRU no ChannelPool: fechar canais inativos (`-O exit` já existe em `session.py:79`) |

### 3.B Topologia e política em N arbitrário

| # | Bloqueio | Local | Impacto | Fix |
|---|---|---|---|---|
| B1 | **Arestas O(N²) a cada sync** (loop duplo em todos os pares, chamado **todo passo** da campanha) | `state_adapter.py:324-329`; sync por passo em `ai_orchestrator.py:281` | N=5000 → 12,5M comparações/passo × 40 passos — minutos só remontando arestas idênticas | agrupar por subnet (dict) e arestar intra-grupo O(Σ n_g²); arestas incrementais (só hosts novos) |
| B2 | **subnet = 3º octeto IPv4** (semântica /24 embutida) | `state_adapter.py:288-291` | rede /16 ou /8: hosts de subredes diferentes caem no mesmo grupo → adjacency errada → masks de lateral move erradas; **IPv6 quebra** (não tem 4 octetos) | derivar grupo do **CIDR configurado** via `ipaddress.ip_network(...)` (mask-aware); suportar v6 |
| B3 | **GAT com node features constantes** (`nf[:,:,0]=1.0`) | `agent.py:217-223` | GAT codifica **só a topologia** — invariância ✓, mas a parte GAT da obs não discrimina hosts por estado (isso fica no obs global + pointer) | design aceitável — **documentar**; roadmap: hf agregado no GAT sem quebrar invariância (H4-adjacente) |
| B4 | **Adjacência densa (N,N) float32** | `state_adapter.py:153-160` + `agent.py:_encode_hosts` | N=10.000 → 400MB por tensor, ×batch | representação esparsa (COO/edge_index) no roadmap; para N≤1k aceitável |
| B5 | **Invariância a N nunca demonstrada** | plano rev8 item #13 (roadmap, não executado) | a promessa central ("qualquer número de máquinas") está **sem evidência empírica** | held-out topológico: N ∈ {10, 30, 50, 100, 250} × {1,2,4 subnets} × {regular, small-world, community} → curva success_rate×N plana = tese validada |
| B6 | **MAX_AGENTS=32** | `shared/constants.py:385` | limita MARL futuro (agents, não hosts) — hoje n_agents=1, sem impacto | só registrar; relevante ao exercitar multi-agente |

### 3.C Conhecimento genérico (qualquer produto)

| # | Bloqueio | Local | Impacto | Fix |
|---|---|---|---|---|
| C1 | **LOCAL_CVE_BASE curada pequena** | `cve_feed.py`/`cve_validate.py` | produto fora da curadoria → 0 candidatos (mitigado pelo fallback rev9, mas PoCs por classe só existem p/ poucos) | **P0 desta semana**: ampliar **por classe de vulnerabilidade** (traversal, reflexão, SSRF, auth-bypass, injection, info-disclosure) com detector paramétrico por produto+versão |
| C2 | **Regex de evidência exige extensão** `.json|.txt|.log|.xml` | `zeroday_hunt.py:731` | artefato válido sem extensão → confirmed do LLM rebaixado a suspect **em qualquer alvo** | aceitar qualquer path sob `evidence/` (+ verificação de existência) |
| C3 | **SPA routes fora do briefing** | `hunt_suite.py` ↔ `zeroday_hunt.py:325-331` | rotas `#/...` de **qualquer SPA** invisíveis ao LLM | **P0**: integrar `spa_route_extract.sh` ao fingerprint |
| C4 | **C2 beacon só bash `/dev/tcp`** | `tools.py:403-404` | alvo sem bash/Windows → callback OOB falha **silenciosamente** → confirmed vira suspect por falta de prova | cadeia de fallback: bash → nc → python → powershell |
| C5 | **`_local_source_ip` conecta na porta 22** p/ descobrir IP local | `tools.py:96-105` | alvo sem :22 aberta → retorna None → c2_callback falha (funciona, mas débito) | usar `IP ROUTE`/socket UDP para IP 8.8.8.8:53 (sem conexão real) |

### 3.D Orquestração distribuída

| # | Bloqueio | Local | Impacto | Fix |
|---|---|---|---|---|
| D1 | **Sem playbook de shard/merge** | `pilot.py`/`zeroday_hunt.py` | rede /16: 1 container não dá conta; sharding manual não documentado | playbook: fatiar CIDR em /24s → N containers com `--runs-root` distintos (paralelo já suportado) → tool `hunt_merge` consolidando findings+audits (sha256 preservado por shard) |
| D2 | **`pilot.py` subprocess sem timeout** | `pilot.py:61,156` | caçada/campanha travada = pilot travado | `subprocess.run(cmd, timeout=wall_clock+300)` |
| D3 | **`evidence/step%03d_`** compartilha contador entre hosts | `tools.py:69-72` com `state.step` global | com N hosts × portas, steps crescem além do previsto — sem colisão (padding, não truncamento), mas dirs ficam largos | namespace por host (`step%03d_h<idx>_`) — cosmético, baixa prioridade |

---

## 4. MÉTRICAS DE UNIVERSALIDADE (substituem qualquer métrica atrelada a um alvo)

| Métrica | Definição | Gate |
|---|---|---|
| `classes_distintas_confirmadas` | nº de classes de achado confirmed **distintas** na campanha (rede inteira) | ≥2 = critério do autor satisfeito **de verdade** (não 2 achados da mesma classe no mesmo porto) |
| `cobertura_superficie` | (hosts caçados × portas com bateria) / (hosts vivos × portas abertas) | reportar SEMPRE; ausência de achado ≠ ausência de vuln |
| `eficiencia_budget` | hosts completados / hosts iniciados | <1.0 deve listar hosts não cobertos |
| `invariancia_N` | success_rate da política vs N (held-out #13) | curva plana dentro do CI |
| `generalidade_cve` | fração de produtos fingerprintados com ≥1 candidato (curada ∪ fallback) | tendência ↑ com curadoria por classe |
| `auditoria` | `pass:true` + sha256 íntegro em TODO confirmed | binário, sem exceção |

> **Nota sobre o critério do autor (≥2 explorações):** em escala de rede, o critério correto é `classes_distintas_confirmadas ≥ 2` **na campanha** — nunca 2 confirmações da mesma classe/porto contando como 2. A run citada na rev8 (2× reflexão no mesmo Squid) atendeu "no limite"; a métrica acima fecha essa ambiguidade para **qualquer** alvo.

---

## 5. ROADMAP RE-ORDENADO (universalidade primeiro)

### P0 — ESTA SEMANA (mantido do plano, generalizado)
1. **Curadoria CVE por classe** + PoCs inofensivos paramétricos (C1)
2. **Regex de evidência** (C2)
3. **SPA routes no briefing** (C3)
4. **`cve_validate` em qualquer alvo autorizado** — critério genérico: ≥1 `confirmed_precondicao` em classe distinta, em qualquer superfície autorizada
5. **`--max-hosts` + fim do `extras[:8]` silencioso** (A1) — barato, destrava escala imediatamente

### P1 — 2 semanas (escala operacional)
6. `--per-host-budget` + relatório de cobertura/hosts não visitados (A2)
7. Priorização por superfície (A3) + two-phase scan `--fast-first` (A4)
8. Playbook shard/merge para redes grandes (D1) + timeout no pilot (D2)
9. **Retreino com máscaras** (contrato π(a|s,M) completo) → A/B do .pt
10. **Held-out 2x2 fatorial** (novidade estrutural vs shift sensorial)

### P2 — 1 mês (prova científica da universalidade)
11. **Held-out topológico N** {10→250} × subnets × grau (B5) — *isto é a validação empírica de "qualquer número de máquinas"*
12. Arestas O(N²)→subnet-group (B1) + subnet mask-aware/IPv6 (B2)
13. Drift W1/PSI lab↔sim por feature (#12) + ablação pointer condicionado (H4/#8)
14. Fallback chain do beacon C2 (C4) + LRU ChannelPool (A6) + eventos stream-only (A5)

### P3 — pesquisa
15. Intervenções causais com replay (#18, H7/MRCO) · adjacência esparsa (B4) · MARL n_agents>1 (B6) · GAT com hf agregado (B3)

---

## 6. RISCOS POR ESCALA

| N hosts (vivos) | Risco dominante | Mitigação disponível hoje | Mitigação P1 |
|---|---|---|---|
| 1–10 | nenhum estrutural | fluxo atual | — |
| 10–100 | budget estoura antes do fim da lista | `--rounds`/`--max-cmds-host` baixos por host | per-host budget + priorização |
| 100–500 | F1 (nmap full-range) domina o tempo | `--port-range` reduzido | two-phase scan |
| 500–5k | O(N²) do sync da campanha; RAM de eventos | sharding por /24 (paralelo) | B1 fix + shard/merge tool |
| >5k | adjacência densa; canal SSH fd limits | sharding obrigatório | B4 sparse + A6 LRU |

---

## 7. CONCLUSÃO DA RE-ANÁLISE

- O **núcleo é universal por construção** (gate CIDR, primitivas RAW, prova executável por assinatura, política fatorada normalizada, auditoria independente de alvo). Nenhuma parte essencial depende de um laboratório específico.
- Os **travadores reais** são operacionais e localizados: `extras[:8]` (A1), budget por host (A2), priorização (A3), two-phase scan (A4), O(N²)/subnet-/24 do adapter (B1/B2), curadoria por classe (C1), regex de evidência (C2).
- A promessa central da tese — **invariância a N** — está correta no design (frações em todo lugar, pointer aberto) mas **sem prova empírica**; o held-out topológico (#13/B5) é o item científico mais importante da fila, pois é a validação direta de "qualquer número de máquinas".
- **P0 desta semana mantido** (itens 1–4 do plano anterior, agora generalizados) + 1 item novo barato (A1) que destrava escala.

*Saídas relacionadas: `CODE_LEVEL_FINDINGS.md` (evidência por linha), `PLANO_ACAO_EXECUTAVEL.md` (cronograma), `RESUMO_EXECUTIVO.md` (1 página).*