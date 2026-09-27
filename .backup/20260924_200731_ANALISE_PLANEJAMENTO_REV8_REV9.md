# Análise Detalhada do Planejamento (rev8 + rev9) — Ruadan + red-MPPO + Ollama

**Data:** 2026-09-24  
**Base:** Documentos `20260915_rev8_auditoria_plano_completo.md`, `MANUAL_CACADOR_ZERODAY.md`, `20260922_rev11_pilot_um_comando.md` + código-fonte completo  
**Objetivo:** Análise profunda do estado atual, gaps, riscos e próximos passos acionáveis

---

## 1. RESUMO EXECUTIVO

O projeto atingiu **maturidade operacional significativa**:

| Componente | Estado | Evidência |
|---|---|---|
| **Harness de campanha** | ✅ Produção | `pentest-harness` CLI, auditoria SHA256, lock anti-paralelo |
| **Caçador 0-day (zeroday_hunt)** | ✅ Produção | F0-F4 pipeline, verificação anti-FP, LLM com tools, OOB canary |
| **Política RL (MADDPG fatorada)** | ✅ Treinada + validada | Checkpoint `maestro_red_ep1246800.pt`, 96/96 testes |
| **Bridge Ruadan↔RL↔LLM** | ✅ Funcional | `RuadanAIBrain` orquestra ciclo completo com fallback heurístico |
| **Feed CVE local + exploit_search** | ✅ Operacional | 200k+ CVEs offline, searchsploit+GitHub, validação PoC inofensiva |
| **PILOT (um comando)** | ✅ Implementado | `pilot.py` encadeia caçada→inventário estendido→campanha .pt+LLM |
| **Auditoria dupla** | ✅ Obrigatória | `audit_run` + `audit_hunt` → `pass: true` exigido |

**O sistema funciona ponta-a-ponta.** O que resta são **aprimoramentos de pesquisa** (held-out, drift, causalidade) e **expansão da base de conhecimento** (CVEs, PoCs).

---

## 2. ANÁLISE POR DIMENSÃO

### 2.1 Arquitetura de Sistemas (Score: 9/10)

**Pontos fortes:**
- **Separação limpa de responsabilidades**: Ruadan (arsenal Kali), red-MPPO (política RL), Bridge (orquestração), Pentest-app (caçador/campanha/PILOT)
- **Contratos explícitos**: `action_masks`/`target_masks` no `update()`, `training_mode=confirmatory` fail-fast
- **Evidência executável obrigatória**: Canário OOB (`PENTEST_CANARY_*`), reflexão de token, assinatura de conteúdo, resposta de protocolo que concede acesso
- **Imutabilidade de outputs**: `.dockerignore` + `ruadan/output/` único + `_archive/` para histórico

**Gaps/Riscos:**
- **GAT O(N²)**: `agent.py:217-223` aplica GAT em `update()` — com 50 hosts = 2500 arestas; documentado mas não benchmarkado em held-out topológico
- **HostEncoder target (E_ψ⁻)**: Opcional (`use_target_host_encoder`), mas checkpoints antigos não têm pesos → soft update só funciona se habilitado no treino
- **Single-agent RL**: `n_agents=1` hardcoded na config; arquitetura suporta MARL mas não exercitado

---

### 2.2 Pipeline de Caçada 0-day (Score: 9.5/10)

**Fluxo F0→F4 implementado corretamente:**

```
F0: sweep (ping + nmap -Pn)          → ips vivos
F1: service_scan (-sV)               → banners/produtos por porta
F2: hunt_suite (http/proto battery)  → findings determinísticos + F2.5 verify_suspect
F2.7: cve_validate (PoC inofensivo)  → confirmed_precondicao / refutada_versao / candidata_version
F3: LLM hunt (http_probe/net_probe/run_command + OOB) → hipóteses testadas com prova
F4: verdict + audit_hunt + attribution
```

**Inovações validadas:**
- **verify_suspect**: Promove `suspect`→`confirmed` (com prova) OU descarta com motivo (SPA, header sem efeito, erro genérico, comportamento seguro) — **elimina FP sistêmicos**
- **Canário OOB**: Token único injetado em header/body/URL → listener C2 `:4444` captura callback → prova de SSRF/RCE cego **sem depender da resposta visível**
- **INTEL PRIMEIRO**: `exploit_search` + `cve_lookup` **antes** de formular hipóteses — evita re-inventar exploits públicos
- **Anti-FP rigoroso**: `confirmed` do LLM sem arquivo de evidência → rebaixado para `suspect` automaticamente (`_parse_hunt_final:739`)

**O que pode melhorar:**
- **Protocolos binários desconhecidos**: Dependem 100% do LLM com `net_probe` raw — sem heurísticas automáticas de fuzzing de formato
- **SPA routes**: `spa_route_extract.sh` lê bundle JS, mas não integrado ao briefing do LLM automaticamente
- **Credential extraction**: `sqli_cred_dump` parseia emails/senhas do detalhe — frágil se formato mudar

---

### 2.3 Política RL (MADDPG Fatorada) (Score: 8.5/10)

**Arquitetura (`agent.py`):**
- **Actor fatorado**: `π(action_type|obs) × π(target|obs, host_embeddings)` — invariante a N hosts
- **PointerHead**: Atenção sobre host keys (GAT encoder) — seleciona alvo sem action space fixo
- **GAT opcional**: `use_gat=True` codifica topologia em `obs_dim + gat_out`
- **HostEncoder online**: Treinado junto com actor (gradiente flui); target encoder opcional com soft update

**Correções rev8 (auditoria itens 5,6,7,9,10,11):**
| Item | Problema | Fix |
|---|---|---|
| 5 | `update()` sem máscaras vs `act()` com | `update()` aceita `action_masks/target_masks/next_*`; mesmo operador `_mask_logits`/`_select_target_masks` no bootstrap e GumbelSoftmax |
| 6 | `mask_dependence=0` (shadow_violations=0) | `decide` grava `shadow_{action,target,joint}_valid`; CLI conta I_t real |
| 7 | `verified_transitions` contava hosts | VT = Σ incrementos de `chain_depth` entre `decide`s; nova métrica `verified_hosts` |
| 9 | GAT não aplicado no `update()` (obs crua) | `_encode_obs(GAT)` em cur/next/bc + teste 2 updates reais |
| 10 | `host_encoder_t` ausente | Opcional `use_target_host_encoder` + soft update (compat checkpoints) |
| 11 | Repeat/resize silencioso | `training_mode=confirmatory` fail-fast; dev mantém + warning |

**Roadmap pendente (itens 8,12,13,18):**
| Item | Descrição | Prioridade |
|---|---|---|
| 8 | Pointer condicionado à ação: `q=W_q[h_s;e_a]` | H4 (ablação) — **alto** para tese |
| 12 | State Representation Drift (W1/PSI por feature lab↔sim) | Quantitativo sim-to-real — **alto** |
| 13 | Held-out topológico (N, subnets, grau, community) + nota O(N²) | Validação GAT — **médio** |
| 18 | Intervenções causais do(a) com replay | H7/MRCO — **pesquisa** |

---

### 2.4 Atribuição de Efetividade (rev6) (Score: 9/10)

**Quatro blocos gerados em `attribution.md/json`:**
1. **Política .pt**: Taxa de sucesso por ação tática (com canário), mask-fit, progressão
2. **LLM**: Ferramenta DECISIVA por sucesso (a que produziu a prova), desperdício, latência, amplitude por host
3. **Cyber Kill Chain**: 7 estágios Lockheed com evidências
4. **TTPs além do MITRE**: Vetores comportamentais inéditos → `ttp_registry.json` persistente + CWE/CAPEC

**Validação A/B:** Rode campanha com `--no-llm` e compare `attribution.json` — **recomputável idêntico** dos brutos (`events.ndjson`, `findings.json`).

---

### 2.5 Feed CVE + Exploit Search (rev7 + rev9 fix) (Score: 9/10)

**Componentes:**
- **cve_feed**: Sync full/incremental (cvelistV5 2022-2026) → índice SQLite → lookup offline
- **exploit_search**: Feed local + `searchsploit` (Exploit-DB) + GitHub (online) → PoCs com evidência
- **cve_validate**: PoC inofensivo integrado à caçada (F2.7) → vereditos: `confirmed_precondicao` / `candidata_version` / `refutada_versao` / `refutada_precondicao` / `nao_aplicavel`

**Bug crítico corrigido (rev9):**
- `searchsploit -i` **ilegal** neste build (rc=2) → TODAS buscas falhavam silenciosamente
- **Fix**: `-i` removido; rc=1 (sem resultados) tratado como válido; regexes `.*?` para produto+versão; porta 3128 adicionada; +3 entradas curadas (vsftpd/Apache/Squid); fallback `candidata_searchsploit` para produtos sem entrada curada

**Validado na VM .110:** Squid 3.1.20 `refutada_versao` (faixa 4.0-5.1); Apache 2.2.22 `candidata_searchsploit` (php-cgi RCE listado).

---

### 2.6 PILOT — Teste do Modelo .pt em Um Comando (rev11) (Score: 9.5/10)

**Pipeline automatizado:**
```
P1: ZeroDayHunter (caçada multi-rede, SQLi, túnel CONNECT, CVEs, LLM)
       ↓ extrai credenciais OBSERVADAS em evidência (proveniência)
P2: Inventário ESTENDIDO (YAML base + creds descobertas comentadas + extended_creds.json)
       ↓ gate ssh_login continua íntegro (só inventário)
P3: Campanha .pt+LLM (política escolhe O QUÊ; LLM escolhe vuln + compõe TTPs; kill chain via túnel)
P4: PILOT_REPORT.md consolidado (efetividade .pt, contribuição LLM, CKC, auditorias)
```

**Comando único:**
```bash
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.pilot \
    --inventory /inventory/inventory.yaml --target-ip 192.168.56.110 \
    --checkpoint /checkpoints/maestro_red_ep1246800.pt \
    --i-am-authorized [--rounds 16] [--max-steps 40] [--wall-clock 5400]
```

**Saída:** `data/pentest_runs/<stamp>_pilot/` (hunt/ + campaign/ + inventory_estendido.yaml + extended_creds.json + hunt_context.json + PILOT_REPORT.md)

---

## 3. GAPS CRÍTICOS E PLANO DE AÇÃO PRIORIZADO

### P0 — Imediato (Próxima Semana)

| # | Ação | Arquivo/Comando | Critério de Pronto |
|---|---|---|---|
| 1 | **Ampliar LOCAL_CVE_BASE** com Squid/Apache/nginx/vsftpd/Dropbear + PoCs inofensivos por classe | `services/pentest/app/cve_feed.py`, `cve_validate.py` | `cve_validate` na VM .110 retorna ≥1 `confirmed_precondicao` em classe **distinta** de reflexão Squid |
| 2 | **Retreino com máscaras**: replay armazena masks → trainer passa no `update()` (contrato π(a\|s,M) completo) | `services/red_team/app/local_trainer.py`, `replay.py` | Novo `.pt` A/B comparado ao antigo (mesmo seed, métricas `critic_loss`/`actor_loss` estáveis) |
| 3 | **Corrigir integração SPA routes no briefing LLM**: `spa_route_extract.sh` output → `fingerprint` no `HostHunt` | `zeroday_hunt.py:325-331`, `hunt_suite.py` | Briefing inclui `spa_routes` quando houver; LLM usa em hipótese |

### P1 — Curto Prazo (2-4 Semanas)

| # | Ação | Descrição |
|---|---|---|
| 4 | **Held-out 2x2 executar**: `heldout_eval --factorial` com Blue .pt (separa novidade estrutural C-A de shift sensorial B-A) → dados para tese |
| 5 | **Ablação #8**: Pointer condicionado à ação (`q=W_q[h_s;e_a]`) — implementar em `pointer_head.py`, comparar com baseline |
| 6 | **Módulo Drift #12**: W1/PSI por feature (lab vs sim) correlacionado com degradação da política — `drift.py` existe, precisa popular com dados reais |
| 7 | **Avaliação topológica #13**: Held-out variando N (10/30/50), subnets, grau médio, community — documentar O(N²) do GAT |

### P2 — Médio Prazo (1-2 Meses)

| # | Ação | Descrição |
|---|---|---|
| 8 | **Intervenções causais #18**: Replay do(a) com infra de eventos/hash já existente → H7/MRCO |
| 9 | **VM .110 aprofundar**: `--rounds 20` só na :80/:3128 após ampliar base CVE; meta: classe distinta da 2ª exploração |
| 10 | **MARL real**: Exercitar `n_agents>1` no treino (cooperação/competição) — hoje `n_agents=1` hardcoded |

### P3 — Pesquisa/Longo Prazo

| # | Ação | Descrição |
|---|---|---|
| 11 | **Novidade em P(s'\|s,a)**: Atualmente "novel" = held-out sub-technique composition; transição real é Via B (roadmap) |
| 12 | **Coherence como heurística**: Já rotulada no report/veredito — validar se prediz sucesso em held-out |
| 13 | **Baselines não-CyberEnv**: Já corrigido (`leg_ativa=None`) — estender para baselines rule-based/heuristic |

---

## 4. ANÁLISE DE RISCOS TÉCNICOS

| Risco | Probabilidade | Impacto | Mitigação |
|---|---|---|---|
| **GAT O(N²) não escala** | Média | Alto (treino/inferência lentos) | Benchmark held-out N=50; considerar sparse attention ou top-k neighbors |
| **Checkpoint incompatível com host_encoder_t** | Baixa | Médio | `use_target_host_encoder=False` default; soft update só se pesos existirem |
| **LLM hallucina tool calls** | Média | Médio | `dispatch` valida schema; `verify_suspect` + auditoria re-verifica evidência |
| **searchsploit/GitHub rate limit** | Baixa | Baixo | Feed local é primário; online opcional com `--nvd` + cache |
| **Drift sim-to-real não detectado** | Alta | Alto | Módulo `drift.py` implementado — precisa popular com features reais do sensor |
| **Credential gate bypass** | Baixa | Crítico | `_cred_autorizada` valida contra inventário; SSH key path também validado |

---

## 5. OBSERVAÇÕES SOBRE O CÓDIGO EXISTENTE

### 5.1 Pontos de Atenção no `agent.py`

1. **Linha 165**: `self._masks_missing_warned = False` — warning **uma vez por instância**; em treino longo pode passar batido. Sugestão: log periodicidade ou contador.
2. **Linhas 463-482**: Reshape `obs_all` de `(B,D)` para `(B,N,D)` via `repeat` — em `confirmatory` falha (correto), mas em `development` sintetiza dados. **Risco**: gradiente sobre obs repetidas ≠ gradiente real.
3. **Linha 570**: `host_keys_det = self._encode_hosts(...).detach()` — critic path **sem gradiente** no encoder (correto para MADDPG), mas actor path (linha 683) usa `host_keys_live` **com gradiente**. Consistente.
4. **Linhas 709-714**: GumbelSoftmax `hard=True` sobre logits **mascarados** — mesmo operador do comportamento. **Correto** para contrato π(a\|s,M).

### 5.2 Pontos de Atenção no `zeroday_hunt.py`

1. **Linha 353**: `oob_wait=15-25` para hipóteses cegas — hardcoded no prompt. Sugerir parâmetro configurável por protocolo.
2. **Linha 454-458**: `exploit_search` automático por banner — **excelente** (INTEL PRIMEIRO), mas sem rate limiting / cache local.
3. **Linha 463-468**: `cve_validate` integrado mas erro não derruba caçada — correto (fail-soft), mas logar mais verboso.
4. **Linha 739**: `ev_path` regex exige extensão `.json|.txt|.log|.xml` — pode rejeitar evidências válidas sem extensão (ex: output bruto). Sugestão: aceitar qualquer arquivo sob `evidence/`.

### 5.3 Pontos de Atenção no `tools.py`

1. **Linha 276**: `tool_ssh_login` canário `echo {token}` — **simples e eficaz**, mas assume shell POSIX. Para Windows targets precisaria adaptação.
2. **Linhas 381-424**: `tool_c2_callback` usa `/dev/tcp` bash — só funciona se alvo tem bash + `/dev/tcp` habilitado. Fallback para `nc`/`python`/`powershell` seria robusto.
3. **Linha 494**: `tool_run_command` allowlist ~45 binários — **crítico** manter atualizada; auditoria deve verificar se binário novo foi adicionado sem revisão.

### 5.4 Pontos de Atenção no `bridge/ai_orchestrator.py`

1. **Linhas 319-400**: `_query_rl_policy` tenta HTTP → local PyTorch → heurístico. **Ordem correta**, mas fallback heurístico prioriza EXFILTRATE/C2/PERSIST — pode forçar ações inválidas se máscaras não passadas.
2. **Linhas 402-477**: `_query_llm_tactics` prompt pede JSON — parsing tolerante a cercas/texto, mas **sem schema validation** (pydantic/jsonschema). Risco de LLM retornar campos extras/errados.

---

## 6. RECOMENDAÇÕES DE MELHORIA DE ENGENHARIA

### 6.1 Testes de Contrato (Já 96/96 — expandir)

```python
# Adicionar em test_update_contract.py:
def test_update_masks_contract_confirmatory():
    """confirmatory mode: update() SEM máscaras = ValueError"""
    cfg = RCfg(..., training_mode="confirmatory")
    agent = MADDPGAgent(cfg)
    with pytest.raises(ValueError, match="modo confirmatory exige"):
        agent.update(..., action_masks=None)

def test_update_masks_contract_development_warning():
    """development mode: update() SEM máscaras = warning logado"""
    cfg = RCfg(..., training_mode="development")
    agent = MADDPGAgent(cfg)
    with caplog.at_level(logging.WARNING):
        agent.update(..., action_masks=None)
    assert "red_update_without_action_masks" in caplog.text
```

### 6.2 Observabilidade

- **Métricas Prometheus** no `rl_server` (`/metrics`) — expor `critic_loss`, `actor_loss`, `grad_norm`, `mask_dependence`
- **Tracing distribuído** (OpenTelemetry) entre Bridge → RL Server → ToolBox
- **Dashboard Grafana** padrão para runs: latency LLM, taxa confirmed/suspect, chain_depth, evidence_level

### 6.3 CI/CD

```yaml
# .github/workflows/test.yml
jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e red-MPPO-testing_model[test]
      - run: pytest services/red_team/tests/ services/pentest/tests/ -v
  integration:
    needs: unit
    runs-on: [self-hosted, gpu]
    steps:
      - run: docker compose -f red-MPPO-testing_model/docker/pentest/docker-compose.yml build
      - run: python -m services.pentest.app.zeroday_hunt --inventory configs/pentest/test.yaml --dry-run --no-llm
      - run: python -m services.pentest.app.attribution --verify data/pentest_runs/*_zeroday
```

---

## 7. PRÓXIMOS PASSOS CONCRETOS (ORDEN ADOS)

### Esta Semana
1. [ ] **Expandir LOCAL_CVE_BASE**: Adicionar entradas para Squid (CVE-2020-11950, CVE-2021-46784), Apache (CVE-2021-41773, CVE-2021-42013), nginx (CVE-2021-23017), vsftpd (CVE-2011-2523), Dropbear (CVE-2019-20679)
2. [ ] **Criar PoCs inofensivos** por classe: reflexão, traversal, SSRF, auth bypass — validar com `cve_validate` na .110
3. [ ] **Integrar SPA routes** no briefing: modificar `hunt_suite.py` para chamar `spa_route_extract.sh` e incluir no `HostHunt.products`
4. [ ] **Rodar PILOT completo** na VM .110 com `--rounds 20` — capturar `PILOT_REPORT.md` e `attribution.json`

### Próximas 2 Semanas
5. [ ] **Implementar retreino com máscaras**: modificar `local_trainer.py` para salvar `action_masks/target_masks/next_*` no replay; passar no `update()`
6. [ ] **Executar held-out 2x2**: `heldout_eval --factorial` com Blue .pt — coletar métricas para tese
7. [ ] **Ablação pointer condicionado**: branch `H4-action-conditioned-pointer` em `pointer_head.py`

### Próximo Mês
8. [ ] **Módulo Drift**: popular `drift.py` com features do sensor (portas, banners, latência) lab vs sim
9. [ ] **Avaliação topológica held-out**: variar N, subnets, community — gerar plots O(N²) vs latency
10. [ ] **Commit + push**: mudanças no repo local + `red-MPPO-testing_model` atualizado (via API autorizada)

---

## 8. CONCLUSÃO

O sistema **está pronto para uso em pesquisa real**. A arquitetura é sólida, a auditoria é rigorosa, e o pipeline ponta-a-ponta (caçada → campanha → atribuição) funciona com um único comando (`pilot.py`).

**O gargalo atual não é engenharia — é base de conhecimento.** A VM .110 só tem 2 portas abertas (80, 3128) e a base CVE curada não cobria Squid/Apache adequadamente (corrigido na rev9). **Ação de maior ROI: ampliar LOCAL_CVE_BASE + PoCs inofensivos + rodar cve_validate na .110.**

Os itens de roadmap (#8, #12, #13, #18) são **pesquisa de ponta** para a tese — não bloqueiam uso operacional, mas diferenciam a contribuição científica.

---

## 9. ARQUIVOS-CHAVE PARA REFERÊNCIA RÁPIDA

| Arquivo | Papel |
|---|---|
| `red-MPPO-testing_model/services/red_team/app/agent.py` | MADDPG fatorado + correções rev8 |
| `red-MPPO-testing_model/services/pentest/app/zeroday_hunt.py` | Caçador autônomo F0-F4 |
| `red-MPPO-testing_model/services/pentest/app/pilot.py` | Pipeline 1-comando P1-P4 |
| `red-MPPO-testing_model/services/pentest/app/tools.py` | ToolBox (primitivas + canário + evidência) |
| `red-MPPO-testing_model/services/pentest/app/inventory.py` | YAML declarativo + validação CIDR/credenciais |
| `red-MPPO-testing_model/services/pentest/app/attribution.py` | Efetividade .pt + LLM + CKC + TTPs |
| `red-MPPO-testing_model/services/pentest/app/cve_feed.py` | Feed local 200k+ CVEs offline |
| `red-MPPO-testing_model/services/pentest/app/exploit_search.py` | Busca exploits reais (local + searchsploit + GitHub) |
| `red-MPPO-testing_model/services/pentest/app/cve_validate.py` | Validação PoC inofensiva |
| `bridge/ai_orchestrator.py` | RuadanAIBrain (RL + LLM + fallback) |
| `bridge/action_dispatcher.py` | Kill Chain com evidence_level honesto |
| `ruadan/start.sh` + `ruadan/docker-run.sh` | Lançamento multi-container + locks + /etc/hosts dinâmico |
| `configs/pentest/inventory.yaml` | Exemplo de inventário real (multi-CIDR, SSH creds, C2) |

---

*Documento gerado automaticamente como parte da análise de planejamento. Salvo em `./contexto/ANALISE_PLANEJAMENTO_REV8_REV9.md` conforme padrão do projeto.*