# 2026-10-01 — Atualização do git red-MPPO-testing_full (sync + incidente do rsync)

> Regra: toda saída salva em ./contexto/*.md — este doc espelha nos 2 repos.

## O que entrou no sync (commit b867500 + 3a50d82-force-add)

- `ruadan/config.ini`: TODO o trabalho da sessão — [EVASION] completa
  (port_touch_cap, jitter, budgets), 71 comandos nmap embrulhados no nmap_ev,
  findings JWT_ADMIN_CAPTURED/WafContentKill nas seções SQLMap/API Fuzz/Extract
  (78 padrões da sessão contados)
- rev14 (reserva LLM 240s p/ skills-red): zeroday_hunt.py, skills_context.py,
  zeroday_hunt_phase.sh
- contexto/ completo (42 docs — histórico de toda a evolução)

## Incidente do sync (transparência total)

O `rsync --delete` (pra espelhar o source) cometeu 2 erros, corrigidos na hora:
1. **Apagou arquivos exclusivos do repo** (README, .gitignore, setup.sh novo,
   targets/EXAMPLE, ORIGIN.md) — restaurados com `git restore` (todos estavam
   commitados)
2. **Vazou alvos reais** (juicer.txt, meu_lab.txt, test_url.txt) pra dentro da
   árvore do repo full — os excludes cobriam só `hosts.txt` no root e 2 arquivos
   em ruadan/targets, mas NÃO os demais nos 2 targets/. **Removidos do disco
   ANTES de qualquer commit — nunca chegaram ao git** (verificado:
   `git ls-files | grep -cE 'meu_lab|juicer|octopux'` = 0)
Lição: o próximo sync usa a lista completa de excludes (ou um script sync
dedicado) — registrado aqui pra não repetir.

## Furo de integridade pós-sync

`ruadan/targets/EXAMPLE.txt` não estava tracked: o `.gitignore` ANINHADO do
ruadan tem regra `targets/` (correta no repo dele — targets reais são runtime) e
o git não re-inclui arquivo dentro de diretório já excluído, mesmo com o
`!EXAMPLE.txt` do .gitignore filho. Fix: `git add -f` — EXAMPLE e .gitignore
tracked, clone-fresh confirma presença.

## Integridade final (commit 3a50d82, pushed)

```
336 arquivos | checkpoint .pt: 1 | evasão: 18 arquivos | skills: 18 SKILL.md
contexto: 42 docs | targets tracked: só EXAMPLE+.gitignore (2 níveis) ✓
alvos reais no git: 0 ✓ | clone-fresh: targets/EXAMPLE nos 2 níveis ✓
```

História do repo: 78950de → 5562d6f → 16c23af → 083514a → 7b54337 → b867500 →
3a50d82 (todos pushed em main, privado).
