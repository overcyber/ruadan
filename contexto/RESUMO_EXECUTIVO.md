# Resumo Executivo — rev13 (travadores RESOLVIDOS)

**Data:** 2026-09-24 · **Sistema:** Ruadan + red-MPPO + Ollama  
**Lente:** QUALQUER host · QUALQUER rede · QUALQUER N de máquinas — zero IPs hardcoded

---

## ESTADO: TRAVADORES RESOLVIDOS NO CÓDIGO ✅

Os 16 travadores identificados na análise foram **consertados nesta sessão** (detalhe com arquivo:linha e testes: `contexto/20260924_REV13_TRAVADORES_RESOLVIDOS.md`):

| Travador (antes) | Agora |
|---|---|
| `extras[:8]` truncava redes grandes em silêncio | `--max-hosts` + `hosts_nao_cobertos` no relatório |
| budget global só; host do fim nem era visitado | `--per-host-budget` (auto) + cobertura parcial marcada por host |
| caça na ordem do sweep; full-range em todos | `--fast-first`: top-1000 em todos → score de superfície → full-range (com merge) nos ricos |
| arestas O(N²) remontadas a cada passo | incremental por grupo — re-sync 0,09 ms |
| subnet = 3º octeto (/16, /8 e IPv6 quebravam) | grupo pelo CIDR configurado (`RUADAN_ALLOWED_CIDRS`) + IPv6 por /64 |
| evidência sem extensão rebaixava confirmed real | aceita `evidence/...`; auditoria continua verificando existência+sha256 |
| beacon C2 só-bash (appliance/Windows perdiam OOB) | cadeia bash→nc→python3→powershell |
| SPA `#/rotas` invisíveis ao LLM | extraídas do bundle JS, no briefing e no relatório |
| base CVE pequena + bug `_cmp_faixa` (vsftpd/Apache refutados ERRADAMENTE) | +9 entradas por classe + probe blind-OOB (JNDI/Log4Shell) + bug morto |
| canais SSH eternos (fd leak) · pilot sem timeout · logs duplicados · warnings que sumiam | LRU 64 · timeout+rc 124 · diretório único · contadores periódicos |

**Validação:** **125 testes verdes** (111 originais + **14 novos** `test_universalidade_rev13.py`, um por travador) · 11 bridge verdes (1 falha pré-existente de mock obsoleto, comprovada com arquivo original) · smokes funcionais (adapter /16/IPv6/incremental, beacons sh-válidos + entrega real de token, CLI).

---

## PRÓXIMO (plano completo: `PLANO_ACAO_EXECUTAVEL.md`)

- **Semana 1 — validação real:** dry-run gate → run com `--fast-first` em rede ≥20 hosts (gates: priorização no relatório, cobertura reportada, `confirmed_classes_distintas`) → `cve_validate` (gate: ≥1 `confirmed_precondicao` classe distinta) → tool `hunt_merge` (paralelo por shard já suportado).
- **Semanas 2-3:** retreino com máscaras (A/B) · held-out 2x2 · **held-out topológico N∈{10..250}** — a prova empírica da invariância a N (item central da tese).
- **Mês 1:** drift W1/PSI · ablação H4 · intervenções causais #18 · GAT com hf · adjacência esparsa · MARL.
- **Bloqueios que dependem do AUTOR:** superfície autorizada p/ runs reais (`--i-am-authorized`), container com torch + `blue_baseline.pt` p/ treino/held-outs, autorização p/ push do repo.

---

## MÉTRICAS UNIVERSAIS (agora nativas no findings.json)

`confirmed_classes_distintas` (critério do autor sem trapaça de mesma-classe) · `hosts_nao_cobertos[]` + motivo · `budget{...}` · `spa_routes` · cobertura de superfície no relatório.

---

## DOCUMENTOS DA SESSÃO

```
contexto/
├── 20260924_REV13_TRAVADORES_RESOLVIDOS.md   # relatório da sessão: 16 fixes + testes (NOVO)
├── PLANO_ACAO_EXECUTAVEL.md                  # replan pós-fix (REESCRITO)
├── RESUMO_EXECUTIVO.md                       # este arquivo
├── ANALISE_PLANEJAMENTO_REV8_REV9.md         # análise universal (histórico; travadores → ver relatório rev13)
└── CODE_LEVEL_FINDINGS.md                     # findings por linha (histórico; status → ver relatório rev13)
.backup/20260924_212952_* (10 fontes originais) · 20260924_214011_* · 20260924_234402_* (docs)
```