# Resumo Executivo — Re-análise Universal (rev2)

**Data:** 2026-09-24 · **Sistema:** Ruadan + red-MPPO + Ollama  
**Lente:** QUALQUER host · QUALQUER rede · QUALQUER N de máquinas — zero IPs hardcoded  
**Correção da rev1:** a análise anterior amarrava validação a um laboratório específico; o sistema é projetado para ser alvo-agnóstico. Esta versão corrige isso.

---

## VEREDITO

**Núcleo universal por construção** ✅ — gate CIDR, primitivas RAW (`net_probe` p/ protocolo desconhecido), prova executável por assinatura de classe, política fatorada normalizada (frações em todo lugar, pointer aberto a N), auditoria independente de alvo.

**Travadores localizados e consertáveis** 🔴 — todos na camada de orquestração de escala e em 2 bugs de genericidade:

| Travador | arquivo:linha | fix |
|---|---|---|
| teto `extras[:8]` de hosts extras | `zeroday_hunt.py:515` | `--max-hosts` + relatório de não-cobertos |
| budget global sem alocação por host | `zeroday_hunt.py:run()` | `--per-host-budget` auto |
| caça sequencial sem priorização | `run()` (ordem do sweep) | score de superfície pós-F1 |
| nmap 1-65535 por host sequencial | `zeroday_hunt.py:234-236` | two-phase (top-1000 → full nos ricos) |
| arestas O(N²) todo passo da campanha | `state_adapter.py:324-329` | agrupar por subnet + incremental |
| subnet = 3º octeto (/24-only, IPv6 quebra) | `state_adapter.py:288-291` | grupo derivado do CIDR via `ipaddress` |
| regex de evidência exige extensão | `zeroday_hunt.py:731` | aceitar path sob `evidence/` |
| C2 beacon só-bash | `tools.py:403-404` | fallback bash→nc→python→powershell |
| invariância a N **nunca demonstrada** | plano #13 (roadmap) | held-out topológico N∈{10..250} |

---

## P0 DESTA SEMANA (mantido, generalizado)

1. **Curadoria CVE por CLASSE** + PoCs inofensivos paramétricos (produto arbitrário → curada OU fallback searchsploit; **nunca zero silencioso**)
2. **Regex de evidência** — confirmed válido em qualquer alvo
3. **SPA routes no briefing** — rotas `#/...` de qualquer SPA visíveis ao LLM
4. **`cve_validate` em qualquer alvo autorizado** — gate: ≥1 `confirmed_precondicao` em classe distinta, em qualquer superfície
5. **(novo, barato)** `--max-hosts` + fim do `extras[:8]` silencioso

---

## SEMANAS 2-4 (resumo)

- **S2 — Escala:** per-host budget + cobertura honesta (`hosts_nao_cobertos` no relatório) + priorização + two-phase scan + **playbook shard/merge** (paralelo já suportado: pentest-brain não tem lock; `--runs-root` distinto = N containers).
- **S3 — Política:** retreino com máscaras (contrato π(a|s,M) completo, A/B do .pt) + held-out 2x2 fatorial.
- **S4 — Prova científica:** held-out topológico **N∈{10,30,50,100,250}** (curva `success×N` plana = "qualquer número de máquinas" demonstrado) + adapter mask-aware/IPv6 + PILOT em qualquer alvo (`--target-ip` é parâmetro).

---

## MÉTRICAS UNIVERSAIS (substituem qualquer métrica atrelada a um alvo)

| Métrica | Gate |
|---|---|
| `classes_distintas_confirmadas` (campanha, rede inteira) | ≥2 — critério do autor **sem** contar 2 achados da mesma classe/porto como 2 |
| `cobertura_superficie` (caçados×portas / vivos×abertas) | reportada sempre |
| `eficiencia_budget` (completados/iniciados) | <1.0 lista quem ficou fora e por quê |
| `invariancia_N` (success_rate × N) | plana dentro do IC |
| `generalidade_cve` (produtos com ≥1 candidato) | tendência ↑ |
| auditoria (`pass:true` + sha256) | binário, sem exceção |

---

## PRÓXIMO COMANDO (parâmetros, não constantes)

```bash
# Dry-run: valida F0-F4 sem rede (qualquer inventário)
cd red-MPPO-testing_model/docker/pentest
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.zeroday_hunt --inventory "$INVENTARIO" --dry-run --no-llm

# Validação CVE em qualquer superfície autorizada
docker compose run --rm --entrypoint python pentest-brain \
    -m services.pentest.app.cve_validate --inventory "$INVENTARIO" --i-am-authorized
```

---

## DOCUMENTOS DESTA ANÁLISE

```
contexto/
├── ANALISE_PLANEJAMENTO_REV8_REV9.md   # análise universal (6 dimensões, bloqueios arquivo:linha, riscos por N)
├── CODE_LEVEL_FINDINGS.md              # findings com fixes e esforço por item + testes de contrato
├── PLANO_ACAO_EXECUTAVEL.md            # 4 semanas, gates genéricos, shard/merge, held-out N
└── RESUMO_EXECUTIVO.md                 # este arquivo
.backup/20260924_200731_*               # versões rev1 (backup pré-edição)
```

**Conclusão:** engenharia essencial já é alvo-agnóstica. O trabalho real é (a) conhecimento por **classe** — não por laboratório, (b) orquestração de **escala** — budget/priorização/paralelo, (c) **prova empírica da invariância a N** — o held-out topológico é o item científico mais importante porque valida literalmente a promessa "qualquer número de máquinas".