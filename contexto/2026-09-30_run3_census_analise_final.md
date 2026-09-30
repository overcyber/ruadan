# 2026-09-30 — Run 3 com census adaptativo: análise final (10h52min, 13 PASSOs)

## Comparativo dos 3 runs contra a defesa

| Métrica | Run forense (sem evasão) | Run 2 (evasão v1) | **Run 3 (census adaptativo)** |
|---|---|---|---|
| JuiceShop | Martelado às cegas (fuzzers velhos, 2× requests) | **100% invisível** (nmap cego do .210, 0 fases HTTP) | **ATACADO POR COMPLETO**: 9 portas resgatadas via 4 IPs do pool, **5318 requests**, API real do SPA mapeada |
| .222 | 26min/porta pendurado | Rotacionado (58-72 aprendido) | Rotacionado, **threshold real 109** |
| Juice: threshold HTTP | — | — | **139 requests** (aprendido) |
| Ban de port-scan no pool | n/a | pool queimado por sondagem ingênua | **ZERO** (governor: cap 8 < threshold 10) |
| Traps identificadas | 0 | 0 | **juice: 11 traps + .222: 1** (census) |
| Findings juice | XSS (com request duplo) | nenhum (cego) | **API_ENDPOINT_FOUND reais**: /rest/user/whoami (200), authentication-details (auth 200/16993B!), continue-code, saveLoginIp... |
| Duração | 8h06 (morto no 9) | 8h06 (completo) | **10h52** (completo, tour de 13 PASSOs) |

## O que validou em campo

1. **Governor de portas-únicas**: ZERO bans de port-scan no Potemkin real durante a
   campanha inteira (cap 8 vs threshold 10; fuzzers + census sobreviveram 10h52 sem
   aposentar IP por port-scan).
2. **Oráculo com host-provado-vivo**: fix aplicado DURANTE o run salvou o pool —
   targets-lixo de `--script-args` (bug de parser, ver abaixo) geraram census contra
   "http-put.url=..." → HOST_UNREACHABLE ×3 → abort sem queimar IP (9 ocorrências, 0 IPs perdidos).
3. **Resgate em série**: NMAP_IDENTITY_RESCUED ×83 (cada fase nmap do juice cego do
   .210 → census cacheado + -sV das 9 portas).
4. **Thresholds reais aprendidos**: juice=139, .222=109 (camada HTTP de request) —
   nenhuma camada de porta-única precisou ser aprendida por ban (o governor previniu).
5. **Blocks gerenciados**: 89 TARGET_BLOCKED / 62 IP_ROTATED / 10 identidades — a
   campanha nunca travou, sempre rotacionou e seguiu.

## Gaps descobertos (fila de melhorias)

1. **Fases-junk contra traps**: o resgate entrega as portas TRAP ao Ruadan (são "open"
   no -sV) → phase groups inteiros rodaram contra tarpits (ftp/ssh/telnet/mysql/vnc/
   webmin no juice = todos traps que sempre rejeitam login). Fix: **nmap_ev FASE 2 deve
   excluir portas tp_*=trap do output reparado** (atacar só a superfície real) — corta
   horas de fase-junk e conexões inúteis.
2. **UDP cego = fantasmas**: o scan UDP (-sU pass-through do .210) viu tudo
   open|filtered (bloqueio de par derruba UDP também) → Ruadan criou ~100 labels de
   serviço fantasma (123/137/161...) → phase groups de nada. Fix: marcar outputs
   all-filtered como suspeitos (não gerar fases de portas que só vieram de scan cego).
3. **83 resgates re-escaneando**: cada fase nmap re-executou o -sV das 9 portas (83×).
   Fix: cache do -sV por alvo no estado (resgatar uma vez, reaproveitar output).
4. **--script-args fora da lista OPT_TAKES** do nmap_ev → TARGET capturou o valor do
   script-args em comandos NSE (davtest/webdav). Fix de 1 linha.

## Matriz Blue × Red final (dados deste run)

- Census: juice=11 traps / .222=1 trap / .221=0 (host morto)
- Competência Blue recalculada: **4/10 BÁSICA** (emulação confirmada + bloqueio
  adaptativo + silent drop + escalonamento de ofensas observado)
- Thresholds: juice 139 req / .222 109 req (camada HTTP); portas-únicas: nunca banidos
  (governor previniu — threshold real do Potemkin só conhecido da análise do código: 10)

## Estado

- Run 3 COMPLETOU (10h52, 13/13 PASSOs do tour planejado, teardown executado)
- Evidence level honesto: ENUM_ONLY (JuiceShop não tem RCE por design; .222 sem
  exploit público funcional para os CVEs encontrados)
- Output íntegro em `output/`; matrix em `output/defense_matrix.md`
- Commits: `ce50780` (agente adaptativo) → `03b718a` (oráculo vivo) → este (matriz+análise)
