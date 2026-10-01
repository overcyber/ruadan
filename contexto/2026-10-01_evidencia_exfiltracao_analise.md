# 2026-10-01 — Análise profunda: a "evidência de exfiltração" era auto-declarada (+ design do objetivo configurável)

> Pergunta do dono: "analise profundamente onde está a evidência real de
> exfiltração" no log "Objetivo de exfiltração alcançado com evidência validada!"
> — e o futuro objetivo configurável (exfiltrar flag.txt / entregar shell).

## 1. A resposta: a evidência REAL não existia — era circular

O log do último run (e de TODOS os anteriores) imprime:
```
[Evidence] Nível de evidência REAL: ENUM_ONLY — nenhum shell/sessão/exploit real
[AI Brain] Objetivo de exfiltração alcançado com evidência validada!
```

A contradição congelada no `ai_campaign_report.json` (step 12 do run 3):
```json
"success": true,
"evidence_level": "enum_only",
"detail": "Exfiltração: evidência SHA256=9ef68f1d... + 4 comandos."
```

A cadeia completa da mentira (código + artefatos verificados):
1. `action_dispatcher.py` branch `EXFILTRATE`: roda searchsploit + exploit_runner
   (enumeração pura — nenhum comando lê arquivo do alvo)
2. `self.canary.save_and_hash_evidence("exfil", "crown_jewel_<ip>.txt",
   "Flag comprovada em <ip>")` → **O SISTEMA ESCREVE O PRÓPRIO ARQUIVO**
   (32 bytes: `Flag comprovada em juice.octopux`) e calcula o SHA256 dele
3. `res.success = True` — **hardcoded, incondicional**
4. `ai_orchestrator.py:293`: `if action == EXFILTRATE and res.success:` →
   imprime "Objetivo alcançado com evidência validada!" e encerra a campanha

O SHA256 no manifest (`9ef68f1d...`) prova que um arquivo de 32 bytes escrito
pelo próprio Ruadan existe — prova criptográfica de auto-declaração. O sistema
de canários TEM o primitivo correto (`verify_token_in_output` — token que só
valida se VOLTAR da saída de comando contra o alvo), mas o EXFILTRATE nunca o
usou. A linha ENUM_ONLY vinha do avaliador honesto (`_assess_evidence`), que
rodava DEPOIS do success já cravado — dois narradores, o desonesto vencia.

## 2. Fix aplicado (rev14 — honestidade EXFILTRATE)

`action_dispatcher.py`: após `_assess_evidence`, o EXFILTRATE agora só mantém
`success=True` com `evidence_level == "credential"` (shell/sessão/bypass
confirmado). Sem isso: `success=False` + detail explicando o fracasso honesto
("a campanha não termina com auto-declaração"). O orquestrador só declara
vitória com sucesso REAL. Consequência imediata: **nenhum run volta a
"alcançar" exfiltração até existir acesso real** — e é assim que deve ser.

## 3. Design do objetivo configurável ([OBJECTIVE] no config.ini)

Documentado em `config.ini` (bloco `[OBJECTIVE]`, mode=legacy enquanto não
implementado):

### mode = exfiltrate_file — arquivos saem DO ALVO ou nada conta
- `files = flag.txt, /root/flag.txt, C:\flag.txt` (config do operador)
- `flag_regex = (flag|FLAG|CTF)\{[^}]{4,}\}` — conteúdo recuperado PRECISA casar
- Mecanismos de recuperação (em ordem de poder): sessão MSF aberta
  (`cat flag.txt` na sessão), SQLi confirmado (`LOAD_FILE`/`pg_read_file`/
  `UNION SELECT`), traversal funcional (endpoint que já leu /etc/passio),
  download HTTP autenticado (JWT admin capturado)
- Evidência: conteúdo recuperado + comando usado + origem (alvo) + SHA256 —
  hash de coisa que VEIO do alvo, não de frase escrita aqui
- Fracasso honesto: nada recuperado → "objetivo NÃO alcançado" no relatório

### mode = deliver_shell — a sessão viva vai pro operador
- Requer container C2 persistente (`ruadan-c2`: msfrpcd + handlers que
  SOBREVIVEM ao `--rm` da campanha — hoje a sessão morre com o container)
- Handoff em `ai_evidence/shell_handoff.txt`: session-id, tipo
  (meterpreter/shell), LHOST/LPORT, usuário, privilégio (getuid),
  instruções de attach (`msfconsole -x "sessions -i <id>"`)
- `shell_min_privilege = any | root` — aceita qualquer sessão ou só root
- Fluxo: RL/LLM continuam até sessão abrir → EXFILTRATE vira HANDOFF
  (mantém handler vivo, grava handoff, não encerra o listener)

### Implementação (fila)
1. `objective.py` (bridge): validador por modo — lê [OBJECTIVE], verifica
   recuperação real (regex no conteúdo) ou sessão viva; devolve evidência
2. Dispatcher EXFILTRATE: chama o validador em vez do success fixo
3. C2 persistente p/ deliver_shell (compose + handler que sobrevive)
4. Bateria: mock de alvo com flag.txt plantada + SQLi de leitura de arquivo —
   validar o ciclo inteiro no lab Potemkin antes do campo

## Commits
- externo main: dispatcher honesto + [OBJECTIVE] doc + este contexto
- full repo: sync dos mesmos
