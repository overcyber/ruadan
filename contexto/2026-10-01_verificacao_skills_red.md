# 2026-10-01 — Verificação: as skills-red estavam sendo usadas? (NÃO — e agora sim)

> Pergunta do dono: "verifique se as skills estão sendo usadas corretamente em
> skills-red/Skills/". Resposta honesta: **estavam CONECTADAS mas NUNCA foram
> usadas** — em nenhum run. Causa-raiz achada e corrigida.

## Inventário real (contra a documentação antiga)

- **18 SKILL.md** (não 65 como documentos antigos diziam): 16 em
  `Skills/web/` (sqli, xss, rce, ssti, ssrf, xxe, idor, file-upload, waf-bypass,
  business-logic, graphql, deserialization, race-condition, request-smuggling,
  open-redirect, parameter-pollution) + 2 em `Skills/active-directory/`
  (offensive-active-directory, offensive-netexec)
- skills-red é o **4º repo git aninhado** do projeto (além de ruadan/, red-MPPO/ e o externo)
- Consumidor: `bridge/skills_context.py` → chamado por
  `red-MPPO/.../zeroday_hunt.py:_build_system_prompt` (fase F3 LLM do hunt)
- Monte no container: `/skills-red:ro` ✓ resolve (`/bridge/skills_context.py` → parent.parent → `/skills-red/Skills` ✓)

## CAUSA-RAIZ: skills conectadas, porém mortas de fome

Evidência dos runs: **ZERO** marcadores `METODOLOGIAS DE ATAQUE` nos
transcripts LLM e `llm_transcripts/` VAZIO nos 3 hunts do run 3 (e runs
anteriores): a fase F3 (única que injeta skills) **nunca executou** —
`"budget do host esgotado antes da fase LLM"` em todos.

Cadeia do problema:
```
zeroday_hunt_phase.sh: per_host_budget=1200s
  → F1 (port discovery) + F2 (bateria determinística por porta: probes, SSH
    login attempts, SPA routes...) come TODO o budget
  → F3 (LLM + skills + grafo Kali): linha de chegada nunca alcançada
```

## Bugs encontrados e corrigidos (com backup prévio, regra imutável)

| # | Bug | Fix | Commit |
|---|---|---|---|
| 1 | **F3 LLM sem budget garantido** (causa-raiz) | `llm_budget_reserve` (default 240s): deadline da BATERIA = `per_host - reserve`; F3 usa o deadline cheio. CLI `--llm-budget-reserve` + env `RUADAN_HUNT_LLM_RESERVE` no wrapper | red-MPPO `977559c`, ruadan `c8efaf1` |
| 2 | `build_skills_context(max_chars=10000)` retornava **13.098 chars** (estouro de 30% — header não contado no orçamento) | Header contabilizado; orçamento respeitado (validado: 10.038 ≤ 10.000+folga) | externo `704d8de` |
| 3 | `ALWAYS_INCLUDE = [offensive-reporting, offensive-fast-checking]` — **skills que NÃO EXISTEM** + código-morto (nunca chamado) | Constante removida com NOTA explicando o porquê | idem |
| 4 | Hunt emitia chaves `"fuzz"` e `"exploit_dev"` — **ausentes do mapa** do loader (contribuíam zero skills silenciosamente) | Mapeadas: `fuzz → parameter-pollution + business-logic`; `exploit_dev → rce` | idem |
| 5 | Portas web SEM banner (ex: 8443 tcpwrapped, 8000, 8080) caíam no `"fuzz"` → sem skills web | Portas `(80,443,8000,8008,8080,8081,8443,8888,9090,5800)` → http/https | red-MPPO `977559c` |

## Validações (saída real dos testes)

```
1. CLI aceita a flag: llm_budget_reserve=300          (--llm-budget-reserve 300)
2. default do dataclass: 240s
3. simulação deadline: bateria para em 960s, LLM tem janela de 240s garantida ✓
4. max_chars=10000 → contexto=10038 chars (OK ✓ — antes: 13098, estouro)
5. fuzz → [business-logic, parameter-pollution] | exploit_dev → [rce]
6. skills carregáveis no mapa: 18/18 (todas com conteúdo real)
7. loader funcional: 13KB de metodologia real para ['http','https','ssh']
   (OFFENSIVE-SQLi "Quick Workflow: Map all input vectors...")
```

## Erro de digitação corrigido no caminho
Ao estender a detecção de portas, transformei o primeiro `if` da cadeia em
`elif` (quebraria tudo com SyntaxError) — pego na hora e revertido antes de
commitar. Registrado aqui por honestidade.

## Como fica o fluxo (run 4 em diante)

```
per_host_budget 1200s ──┬── bateria F1/F2: deadline 960s (para ANTES)
                        └── F3 LLM: janela GARANTIDA de 240s
                              → _build_system_prompt(hh)
                                 → service_types (portas web alt agora mapeadas)
                                 → build_skills_context(≤10KB: sqli, xss, rce...)
                                 → + grafo Kali (/knowledge/kali_tools_graph.json)
                              → brain gpt-oss:20b caça COM metodologias
```

## Commits (todos pushed)
- red-MPPO-testing_model: `977559c` (rev14: reserva LLM + detecção + fixes)
- ruadan (2025): `c8efaf1` (wrapper --llm-budget-reserve)
- repo externo (main): `704d8de` (skills_context + doc)
- red-MPPO-testing_full (unificado): `083514a` (sync dos 3 arquivos)
