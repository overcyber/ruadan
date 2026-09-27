# Plano de Ação Executável — Universal (qualquer host / rede / N) — 4 semanas

**Regra:** nenhum IP, hostname ou laboratório hardcoded. Alvo entra por `$ALVO`, rede por `$SUBNET`, credenciais por inventário YAML, política por `$CHECKPOINT`. Toda validação é **contra critério genérico**, não contra uma VM específica.

---

## SEMANA 1 (P0 — MANTIDO) — CONHECIMENTO GENÉRICO + 2 FIXES BARATOS

### Dia 1-2 · Curadoria CVE por CLASSE de vulnerabilidade (não por laboratório)
- Ampliar `LOCAL_CVE_BASE` **por classe** — cada entrada = detector paramétrico (produto+faixa de versão) + PoC inofensivo:
  - traversal (Apache 2.4.49/50, nginx alias, Webmin), reflexão/template, SSRF, auth-bypass (vsftpd 2.3.4, php-cgi), injection, info-disclosure, proxy-abuse (Squid 4.x), Dropbear, Redis, etc.
- **Critério de pronto:** produto arbitrário fingerprintado → ou entrada curada OU `candidata_searchsploit` (fallback rev9) — **nunca zero silencioso**.

### Dia 2 · Regex de evidência (fix 1.5 — ~5 linhas)
```python
# zeroday_hunt.py:731 — aceitar qualquer artefato sob evidence/ (auditoria re-verifica existência+sha256)
```

### Dia 3 · SPA routes no briefing (fix C3)
- `hunt_suite_http` chama `spa_route_extract.sh`; rotas `#/...` entram no `fingerprint` do LLM (valem para **qualquer SPA**).

### Dia 3-4 · `--max-hosts` + fim do `extras[:8]` silencioso (fix 1.1 — ~15 linhas)
- Default: sem teto (o budget limita); truncagem = **relatório lista hosts não caçados**.

### Dia 5 · Validar em qualquer alvo autorizado (genérico)
```bash
cd red-MPPO-testing_model/docker/pentest
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_validate \
    --inventory "$INVENTARIO" --i-am-authorized
# GATE GENÉRICO: >=1 confirmed_precondicao em classe DISTINTA, em QUALQUER superfície autorizada
```
**Gates da semana (independem do alvo):**
- [ ] base curada cobre ≥6 classes com PoC inofensivo
- [ ] artefato de evidência sem extensão não rebaixa confirmed
- [ ] SPA com rotas #/: LLM as recebe no briefing
- [ ] `--max-hosts` funciona; truncagem aparece no relatório
- [ ] suíte de testes: 96/96 + novos contratos verdes

---

## SEMANA 2 — ESCALA OPERACIONAL (rede com N grande)

### Dia 1-2 · Budget por host + cobertura honesta (fix 1.2)
- `--per-host-budget` (auto = `max(360s, wall_clock/n_hosts)`); `_aggregate()` reporta `hosts_nao_cobertos` com motivo.

### Dia 3 · Priorização por superfície (fix 1.8) + two-phase scan (fix 1.7)
- Pós-F1: ordenar fila por score (portas abertas, banner com versão, CVEs candidatas); `--fast-first` p/ N>20 (top-1000 → full-range só nos ricos).

### Dia 4-5 · Playbook shard/merge p/ redes grandes (fix D1) + timeouts (fix 2.4)
```bash
# HOJE já dá paralelo: pentest-brain NÃO tem lock; runs-root distinto = container distinto
for shard in 192.168.0.0/24 192.168.1.0/24 192.168.2.0/24; do
  docker compose run --rm -d --entrypoint python pentest-brain \
      -m services.pentest.app.zeroday_hunt \
      --inventory "$INVENTARIO" --subnet "$shard" --i-am-authorized \
      --runs-root "data/pentest_runs/shard_${shard##*/}" &
done; wait
# NOVO (entregável): hunt_merge — consolida findings+audits dos shards (sha256 preservado por shard)
```

**Gates da semana:**
- [ ] 100 hosts vivos: relatório mostra cobertura real + quem ficou fora e por quê
- [ ] two-phase: F1 <25% do tempo total em rede média
- [ ] 3 shards paralelos → merge único com `pass:true` agregado

---

## SEMANA 3 — POLÍTICA: CONTRATO COMPLETO + PROVA FATORIAL

### Dia 1-2 · Retreino com máscaras (A/B do .pt — genérico)
- `replay.py` armazena `action_masks/target_masks/next_*`; `local_trainer.py` passa no `update()` (`training_mode=confirmatory`).
- **A/B:** mesmo seed, comparar `critic_loss/actor_loss/mask_dependence` (I_t real > 0).

### Dia 3-5 · Held-out 2x2 fatorial (novidade estrutural × shift sensorial)
```bash
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.heldout_eval \
    --checkpoint "$CHECKPOINT" --blue-checkpoint "$BLUE_PT" \
    --factorial --runs-per-cell 5 --output data/heldout_2x2.json
```
**Gates:** masks no replay (contrato π(a|s,M) fechado) · tabela C-A vs B-A com IC · 2x2 reproduzível.

---

## SEMANA 4 — PROVA CIENTÍFICA DE "QUALQUER N" + PILOT GENÉRICO

### Dia 1-3 · Held-out topológico — a validação empírica da invariância a N
- Grid: **N ∈ {10, 30, 50, 100, 250}** × {1, 2, 4 subnets} × {regular, small-world, community} × 5 seeds.
- Métrica: curva `success_rate × N` (plana dentro do CI = invariância demonstrada) + nota quantitativa do O(N²).
- **Este é o item que transforma "qualquer número de máquinas" de afirmação em evidência.**

### Dia 2 (paralelo) · Adapter mask-aware + arestas não-quadráticas (fixes 1.3/1.4)
- subnet = grupo derivado do CIDR (IPv4/IPv6); arestas por grupo com cache incremental.

### Dia 4-5 · PILOT em qualquer alvo autorizado (comando já genérico)
```bash
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.pilot \
    --inventory "$INVENTARIO" --target-ip "$ALVO" \
    --checkpoint "$CHECKPOINT" \
    --i-am-authorized --rounds 16 --max-steps 40 --wall-clock 5400
```
**Gates (genéricos):**
- [ ] `classes_distintas_confirmadas ≥ 2` na campanha (o critério do autor, sem trapaça de mesma-classe)
- [ ] `PILOT_REPORT.md` + auditorias das duas fases `pass:true`
- [ ] attribution recomputável bit-a-bit (`--verify`)

---

## FILA CONTÍNUA (após as 4 semanas)

| Item | Ref | Destrava |
|---|---|---|
| beacon fallback bash→nc→python→powershell | fix 1.6 | OOB cego em qualquer SO |
| LRU ChannelPool + eventos stream-only | 2.7/2.6 | campanhas largas sem fd/RAM leak |
| drift W1/PSI por feature lab↔sim | #12 | sim-to-real quantitativo |
| ablação pointer condicionado à ação | H4/#8 | discriminação de alvo na política |
| intervenções causais com replay | #18/H7 | MRCO |
| adjacência esparsa + GAT com hf agregado | B3/B4 | N > 5k |
| MARL n_agents>1 | B6 | cooperação |

---

## VALIDAÇÃO CONTÍNUA (diária, agnóstica de alvo)

```bash
# 1. Suíte completa
cd red-MPPO-testing_model && python -m pytest services/red_team/tests/ services/pentest/tests/ -x -q

# 2. Dry-run do caçador (pipeline F0-F4 sem rede)
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.zeroday_hunt --inventory "$INVENTARIO" --dry-run --no-llm

# 3. Auditoria de qualquer run
cat data/pentest_runs/*_zeroday/audit_report.json | jq '.pass, .n_checks, .n_failed'
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.attribution --verify "data/pentest_runs/<run>"

# 4. Invariância rápida (regressão da política em N)
python -m pytest services/pentest/tests/test_state_adapter.py -k "invariant" -q
```

---

## RISCOS E CONTINGÊNCIAS (sem alvo fixo)

| Risco | Contingência |
|---|---|
| nenhuma superfície autorizada disponível na semana | validar gates com `--dry-run` + `--no-llm` (pipeline) e held-out sintético (política) |
| treino OOM/instável | batch menor / grad accumulation; `confirmatory` acusa contrato, não sintetiza |
| held-out N=250 lento | reduzir seeds 5→3; paralelizar células por runs-root |
| 2x2 sem efeito | documentar negativo e seguir — o valor é o protocolo, não o resultado |
| merge de shards quebra sha256 | auditoria por shard permanece; merge consolida findings, não evidências |

---

## CRITÉRIO DE CONCLUSÃO DO CICLO (Definition of Done universal)

- [ ] Base CVE por classe + fallback: **nenhum** fingerprint → zero silencioso
- [ ] Rede de qualquer tamanho: budget por host + cobertura reportada + priorização
- [ ] Política: máscaras no treino (contrato completo) + **curva success×N plana publicada**
- [ ] Qualquer campanha: `classes_distintas_confirmadas ≥ 2` OU `FAILED_TARGET_HARD` honesto
- [ ] Toda run: `audit_report.pass=true` + attribution recomputável

*Arquivo: `contexto/PLANO_ACAO_EXECUTAVEL.md` — substitui a versão anterior (backup em `.backup/20260924_200731_*`).*