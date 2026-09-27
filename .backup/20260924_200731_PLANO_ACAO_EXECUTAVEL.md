# Plano de Ação Executável — Próximos 30 Dias

**Objetivo:** Transformar análise em entregas concretas, priorizadas por ROI e dependências.

---

## SEMANA 1 (2026-09-24 a 2026-09-30) — BASE DE CONHECIMENTO + VALIDAÇÃO

### Dia 1-2: Ampliar LOCAL_CVE_BASE + PoCs Inofensivos
```bash
# 1. Editar base curada (arquivo interno do cve_feed)
# Local: red-MPPO-testing_model/services/pentest/app/cve_feed.py
# Buscar: LOCAL_CVE_BASE ou _CURATED_ENTRIES
# Adicionar entradas para:
#   - Squid: CVE-2020-11950 (4.0-5.1), CVE-2021-46784
#   - Apache: CVE-2021-41773 (2.4.49-50), CVE-2021-42013
#   - nginx: CVE-2021-23017
#   - vsftpd: CVE-2011-2523 (2.3.4)
#   - Dropbear: CVE-2019-20679
# Formato: {"cve": "...", "product": "...", "versions": ["..."], "poc_harmless": "..."}

# 2. Criar PoCs inofensivos por classe (reflexão, traversal, SSRF, auth bypass)
# Local: red-MPPO-testing_model/services/pentest/app/cve_validate.py
# Função: _HARMLESS_POCS por classe
```

### Dia 3: Integrar SPA Routes no Briefing
```bash
# Arquivo: red-MPPO-testing_model/services/pentest/app/hunt_suite.py
# Adicionar chamada a spa_route_extract.sh no hunt_suite_http
# Retornar no finding: "spa_routes": ["#/admin", "#/dashboard", ...]
# Atualizar zeroday_hunt.py:325-331 para incluir no fingerprint
```

### Dia 4: Corrigir Regex de Evidência (zeroday_hunt.py:731)
```python
# ANTES:
ev_path = re.compile(r"[\w.\-]+(/[\w.\-]+)+\.(json|txt|log|xml)$")

# DEPOIS:
ev_path = re.compile(r"evidence/[\w./\-]+")  # Qualquer arquivo sob evidence/
# OU melhor: verificar existência real do arquivo
```

### Dia 5: Rodar CVE Validate na VM .110
```bash
cd /system/ruadan-new/red-MPPO-testing_model/docker/pentest
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_validate \
    --inventory /inventory/inventory.yaml --i-am-authorized
# Esperado: ≥1 confirmed_precondicao em classe DISTINTA de reflexão Squid
```

---

## SEMANA 2 (2026-10-01 a 2026-10-07) — RETREINO COM MÁSCARAS + TESTES

### Dia 1-2: Modificar Replay para Armazenar Máscaras
```bash
# Arquivo: red-MPPO-testing_model/services/red_team/app/replay.py
# Em ReplayBuffer.add(): salvar action_masks, target_masks, next_action_masks, next_target_masks
# Estrutura: dict com keys "action_masks", "target_masks", "next_action_masks", "next_target_masks"
```

### Dia 3-4: Modificar Trainer para Passar Máscaras no Update
```bash
# Arquivo: red-MPPO-testing_model/services/red_team/app/local_trainer.py
# No loop de treino: sample batch -> passar masks no agent.update()
# Verificar: agent.update() assinatura já aceita (linha 396-417 agent.py)
```

### Dia 5: Treinar Novo .pt (A/B vs Antigo)
```bash
# Comando de treino (ajustar epochs/batch conforme infra)
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.red_team.app.local_trainer \
    --checkpoint /repo/data/checkpoints/maestro_red_ep1246800.pt \
    --output /repo/data/checkpoints/maestro_red_ep1246800_masked.pt \
    --training-mode confirmatory \
    --epochs 100

# Comparar: critic_loss, actor_loss, mask_dependence (I_t real)
```

---

## SEMANA 3 (2026-10-08 a 2026-10-14) — HELD-OUT 2x2 + ABLAÇÃO POINTER

### Dia 1-2: Executar Held-out 2x2 Fatorial
```bash
# Requer Blue .pt (baseline) já treinado
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.heldout_eval \
    --checkpoint /repo/data/checkpoints/maestro_red_ep1246800.pt \
    --blue-checkpoint /repo/data/checkpoints/blue_baseline.pt \
    --factorial \
    --runs-per-cell 5 \
    --output /repo/data/heldout_2x2_results.json

# Métricas: separa novidade estrutural (C-A) de shift sensorial (B-A)
# Output para tese: tabela + plots
```

### Dia 3-5: Ablação Pointer Condicionado à Ação (H4)
```bash
# Branch: git checkout -b H4-action-conditioned-pointer

# Arquivo: red-MPPO-testing_model/services/red_team/app/agent.py
# PointerHead: adicionar embedding da ação no query
# ANTES: q = W_q @ h_s
# DEPOIS: q = W_q @ [h_s; e_a]  (concatena action embedding)

# Treinar variante + comparar com baseline em held-out
```

---

## SEMANA 4 (2026-10-15 a 2026-10-21) — DRIFT + TOPOLOGIA + PILOT PRODUÇÃO

### Dia 1-2: Popular Módulo Drift com Dados Reais
```bash
# Arquivo: red-MPPO-testing_model/services/pentest/app/drift.py
# Coletar features do sensor (portas, banners, latência, n_hosts) em:
#   - Simulação (treino)
#   - Lab real (runs .110, .14, etc.)
# Calcular W1/PSI por feature -> correlacionar com degradação policy
```

### Dia 3: Avaliação Topológica Held-out
```bash
# Variar: N=10/30/50, subnets=1/2/3, grau médio, community structure
# Gerar grafos sintéticos + medir: latency, critic_loss, action_accuracy
# Documentar O(N²) do GAT em notebook/markdown
```

### Dia 4-5: PILOT Completo em Produção (VM .110)
```bash
cd /system/ruadan-new/red-MPPO-testing_model/docker/pentest
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.pilot \
    --inventory /inventory/inventory.yaml --target-ip 192.168.56.110 \
    --checkpoint /checkpoints/maestro_red_ep1246800.pt \
    --i-am-authorized --rounds 20 --max-steps 40 --wall-clock 7200

# Output: data/pentest_runs/<stamp>_pilot/PILOT_REPORT.md
# Verificar: 2ª exploração em classe DISTINTA de reflexão Squid
```

---

## CHECKLIST DE ENTREGAS (Definition of Done)

| Semana | Entregável | Critério de Aceite |
|---|---|---|
| 1 | LOCAL_CVE_BASE expandida | 5+ novas entradas curadas + PoCs inofensivos |
| 1 | SPA routes no briefing | `hunt_suite_http` retorna `spa_routes`; LLM usa em hipótese |
| 1 | Regex evidência corrigida | `confirmed` com arquivo sem extensão aceito |
| 1 | CVE validate na .110 | ≥1 `confirmed_precondicao` classe nova |
| 2 | Replay armazena masks | `ReplayBuffer.sample()` retorna masks |
| 2 | Trainer passa masks | `agent.update()` recebe masks; `training_mode=confirmatory` passa |
| 2 | Novo .pt treinado | A/B: loss estável, mask_dependence > 0 |
| 3 | Held-out 2x2 executado | JSON com métricas por célula (C-A, B-A) |
| 3 | Ablação H4 implementada | Pointer condicionado + comparação baseline |
| 4 | Drift populado | W1/PSI por feature + correlação com policy perf |
| 4 | Topologia held-out | Plots O(N²) vs N/subnets/grau/community |
| 4 | PILOT .110 produção | PILOT_REPORT.md + 2ª exploração classe distinta |

---

## COMANDOS DE VALIDAÇÃO CONTÍNUA (Rodar Diariamente)

```bash
# 1. Testes unitários (devem passar 100%)
cd /system/ruadan-new/red-MPPO-testing_model
python -m pytest services/red_team/tests/ services/pentest/tests/ -x -q

# 2. Dry-run caçador (valida pipeline F0-F4 sem rede)
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.zeroday_hunt \
    --inventory configs/pentest/inventory.yaml --dry-run --no-llm

# 3. Verificar auditoria de runs recentes
ls -la data/pentest_runs/*_zeroday/audit_report.json
cat data/pentest_runs/*_zeroday/audit_report.json | jq '.pass'

# 4. Verificar atribuição recomputável
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.attribution --verify /repo/data/pentest_runs/<latest_zeroday>
```

---

## RISCOS E CONTINGÊNCIAS

| Risco | Probabilidade | Contingência |
|---|---|---|
| VM .110 indisponível | Média | Usar `--dry-run` + alvo simulado; validar lógica sem execução real |
| Treino .pt falha (OOM/instabilidade) | Baixa | Reduzir batch_size; `gradient_accumulation_steps`; mixed precision |
| Held-out 2x2 demora demais | Média | Reduzir `--runs-per-cell` para 3; paralelizar células |
| Ablação H4 não melhora | Alta (pesquisa) | Documentar resultado negativo; voltar ao baseline para PILOT |
| CVE validate não acha nada | Baixa | Expandir base curada + fallbacks searchsploit/GitHub |

---

## COMUNICAÇÃO E TRACKING

- **Issues GitHub**: Criar 1 issue por item P0/P1 no repo `overcyber/red-MPPO-testing_model`
- **Commits**: `feat:`, `fix:`, `test:`, `docs:` seguindo Conventional Commits
- **Branch strategy**: `main` protegido; features em branches `feat/<ticket>`; PR + review obrigatório
- **Logs**: Todas runs em `data/pentest_runs/` com timestamp; `audit_report.json` = gate de qualidade

---

*Arquivo: `contexto/PLANO_ACAO_EXECUTAVEL.md` — Para execução direta.*