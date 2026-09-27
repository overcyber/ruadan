# Plano de Ação Executável — rev13 (pós-travadores resolvidos)

**Contexto:** os 16 travadores de universalidade foram RESOLVIDOS no código (ver `20260924_REV13_TRAVADORES_RESOLVIDOS.md`) com 125 testes verdes. Este plano é o **que falta depois disso**, priorizado. Zero IPs: alvo/rede/N entram por `$ALVO`, `$SUBNET`, `$INVENTARIO`, `$CHECKPOINT`.

**Estado de entrada:** caçador two-phase (`--fast-first`), budget por host, teto `--max-hosts`, cobertura honesta no relatório, subnet mask-aware + IPv6, arestas incrementais, beacon C2 com fallback multi-SO, SPA routes no briefing, base CVE por classe (+9) com probe blind-OOB, LRU de canais, pilot com timeout.

---

## SEMANA 1 — VALIDAÇÃO EM SUPERFÍCIE REAL (qualquer alvo autorizado)

### Dia 1 · Gate de sanidade pós-fix (sem rede)
```bash
cd red-MPPO-testing_model
python -m pytest services/pentest/tests/ -x -q      # 125 verdes obrigatórios
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.zeroday_hunt \
    --inventory "$INVENTARIO" --dry-run --no-llm    # pipeline F0-F4 sem rede
```
**Gate:** 125 passed + dry-run gera run com `audit_report.pass=true`.

### Dia 2-3 · Run real com as flags de escala
```bash
# rede >= 20 hosts vivos: two-phase + budget por host
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.zeroday_hunt \
    --inventory "$INVENTARIO" --i-am-authorized \
    --fast-first --rounds 14 --wall-clock 7200
```
**Gates (genéricos, independem do alvo):**
- [ ] relatório traz **ordem de caça por score** (evento `priorizacao`) — budget gasto onde há superfície
- [ ] se algo ficou fora: `hosts_nao_cobertos` + motivo aparece no relatório (nunca silêncio)
- [ ] `counts.confirmed_classes_distintas` reportado — ≥2 classes OU `FAILED_TARGET_HARD` honesto
- [ ] host rico ganhou portas além do top-1000 (merge full-range)

### Dia 3-4 · cve_validate com a base nova
```bash
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_validate \
    --inventory "$INVENTARIO" --i-am-authorized
```
**Gate:** ≥1 `confirmed_precondicao` em classe distinta em QUALQUER superfície autorizada (a base agora cobre traversal/ssh/info/ftp/rce-cgi/nginx + blind-OOB JNDI; fallback searchsploit para o resto).

### Dia 4-5 · `hunt_merge` (tool pequena, destrava o paralelo)
- Consolida N shards (`--runs-root` distintos já rodam paralelos — pentest-brain não tem lock):
  - `python -m services.pentest.app.hunt_merge data/pentest_runs/shard_*` 
  - une findings, reconta classes distintas, AGREGA cobertura, re-audita por shard (sha256 preservado)
- **Gate:** 3 shards de teste em loopback → merge único com `pass:true` agregado.

---

## SEMANAS 2-3 — POLÍTICA: CONTRATO COMPLETO + PROVA DA INVARIÂNCIA

### Retreino com máscaras (A/B do .pt)
- `replay.py` armazena `action_masks/target_masks/next_*`; `local_trainer.py` passa no `update()` com `training_mode=confirmatory`.
- **Gate:** A/B mesmo seed — `critic_loss/actor_loss` estáveis + `mask_dependence` (I_t real) > 0 no novo.

### Held-out 2x2 fatorial
```bash
... -m services.pentest.app.heldout_eval \
    --checkpoint "$CHECKPOINT" --blue-checkpoint "$BLUE_PT" \
    --factorial --runs-per-cell 5
```
**Gate:** tabela C-A (novidade estrutural) × B-A (shift sensorial) com IC, reproduzível.

### Held-out topológico — A PROVA de "qualquer número de máquinas"
- Grid: **N ∈ {10, 30, 50, 100, 250}** × {1,2,4 subnets} × {regular, small-world, community} × 5 seeds.
- **Gate (tese):** curva `success_rate × N` **plana dentro do IC** + nota quantitativa do custo O(N²).
- *É o item científico mais importante da fila:* a invariância a N está correta no design e os travadores de escala foram removidos — falta a evidência empírica.

---

## MÊS 1 — PESQUISA (ordem por ROI de tese)

| # | Item | Ref | Destrava |
|---|---|---|---|
| 1 | Drift W1/PSI por feature lab↔sim correlacionado com degradação da política | #12 | sim-to-real quantitativo |
| 2 | Ablação pointer condicionado à ação (`q=W_q[h_s;e_a]`) | H4/#8 | discriminação de alvo na política |
| 3 | Intervenções causais com replay do(a) | #18/H7 | MRCO |
| 4 | GAT com hf agregado (hoje: node features constantes) | B3 | GAT discrimina hosts sem quebrar invariância |
| 5 | Adjacência esparsa (COO) | B4 | N > 5k |
| 6 | MARL `n_agents>1` | B6 | cooperação |
| 7 | Base CVE: Dropbear + expansão contínua por classe | — | cobertura crescente |

---

## INFRA / DÉBITOS

- [ ] Commit + push do repo local (mudanças pentest + agent.py; autorizado: autor ou API)
- [ ] CI: os 125 testes como gate de PR no `red-MPPO-testing_model`
- [ ] `test_bridge.py`: mock obsoleto `sync_nmap_dict_hosts` (falha PRÉ-existente, fora da rev13)
- [ ] `RUADAN_ALLOWED_CIDRS` documentado no docker-run p/ redes não-/24

---

## BLOQUEIOS QUE DEPENDEM DO AUTOR

| Item | Por quê depende |
|---|---|
| Runs reais (dia 2-4) | exigem `--i-am-authorized` em superfície própria |
| Retreino + held-outs | precisam do container com torch (host não tem) + `blue_baseline.pt` |
| Push do repo | credencial/autorização do autor |

---

## VALIDAÇÃO CONTÍNUA (diária, agnóstica de alvo)

```bash
cd red-MPPO-testing_model && python -m pytest services/pentest/tests/ -x -q   # 125 verdes
python -m pytest bridge/test_bridge.py -q -k "not test_xml_service_preservation"  # 11 verdes
docker compose -f docker/pentest/docker-compose.yml run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.zeroday_hunt --inventory "$INVENTARIO" --dry-run --no-llm
```

## CRITÉRIO DE CONCLUSÃO DO CICLO (Definition of Done universal)

- [ ] Base CVE por classe + fallback: **nenhum** fingerprint → zero silencioso
- [ ] Rede de qualquer tamanho: budget por host + priorização + cobertura SEMPRE reportada
- [ ] Política: máscaras no treino + **curva success×N plana publicada**
- [ ] Qualquer campanha: `confirmed_classes_distintas ≥ 2` OU `FAILED_TARGET_HARD` honesto
- [ ] Toda run: `audit_report.pass=true` + attribution recomputável

*Substitui a versão anterior (backup em `.backup/20260924_234402_*`). Progresso da rev13: ver `20260924_REV13_TRAVADORES_RESOLVIDOS.md`.*