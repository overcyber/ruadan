# Plano: Meterpreter + msconsole Automatizado para Ruadan

## Por Que Não Existe Hoje (Conforme Sua Análise)
- Ruadan usa Metasploit **apenas para consolidação de BD** (import Nmap XML → CSV reports)
- Meterpreter = payload interativo que precisa `LHOST/LPORT`, handlers dedicados, interação em tempo real
- SearchSploit apenas **copia PoC code** para output dir para revisão do operador

---

## Arquitetura Proposta

```
┌─────────────────────────────────────────────────────────────────┐
│                     Ruadan AI Brain                             │
│  (bridge/ai_orchestrator.py → action_dispatcher.py)             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌────────────┐  ┌────────────┐  ┌────────────┐
    │  EXPLOIT   │  │ PRIVESC    │  │  PERSIST   │
    │  _REMOTE   │  │  (meter-   │  │  (meter-   │
    │  (msf      │  │  preter)   │  │  preter)   │
    │  exploit)  │  │            │  │            │
    └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
          │               │               │
          ▼               ▼               ▼
    ┌────────────────────────────────────────────────┐
    │         Metasploit RPC (msgrpc) / msfconsole   │
    │  - Module execution (exploit/windows/smb/...)  │
    │  - Handler management (multi/handler)          │
    │  - Session tracking (meterpreter sessions)     │
    │  - Post-exploitation modules                   │
    └────────────────────────────────────────────────┘
```

---

## Fases de Implementação

### Fase 1: Cliente Metasploit RPC + Gerenciador de Handlers (Camada Bridge)
**Arquivos a criar/modificar:**
- `bridge/msf_rpc.py` — wrapper fino sobre `msfrpc`/`pymetasploit3` ou XML-RPC raw
- `bridge/handler_manager.py` — ciclo de vida: iniciar handler → aguardar sessão → rastrear session ID
- `bridge/state_adapter.py` — estender `HostRecord` com `msf_session_id`, `meterpreter_active`

**Decisões de design chave:**
- Usar **MSGRPC (msgrpc)** sobre `msfconsole -x` para I/O estruturado e eventos de sessão
- Rodar `msgrpc` dentro do container `kali-ruadan` (adicionar no Dockerfile: `gem install msgpack-rpc` + `msfdb init`)
- Handlers bind no IP do container (host network mode → acessível do target)

### Fase 2: Extensões do Action Dispatcher
**Modificar:** `bridge/action_dispatcher.py`

| RedAction | Atual | Novo (Meterpreter) |
|-----------|-------|-------------------|
| `EXPLOIT_REMOTE` | Fases Ruadan (SQLMap, Gobuster, etc.) | **+** Execução de módulo MSF via RPC |
| `PRIVILEGE_ESCALATE` | Brute Forcing + Exploitation phases | **+** `post/multi/recon/local_exploit_suggester`, `exploit/local/*` |
| `PERSIST_BACKDOOR` | Web exploitation + screenshots | **+** `exploit/windows/local/persistence`, `post/windows/manage/migrate` |
| `C2_ESTABLISH` | MSF DB import + reports | **+** Sessões de handler reais → verificação de canal C2 |

**Estratégia de seleção de módulo:**
- RL seleciona **tipo de ação** + **target**
- LLM fornece **nome do módulo** + **parâmetros** (LHOST, LPORT, payload)
- Dispatcher valida contra resultados de `exploit_search` + OS/serviço do target

### Fase 3: Integração Attack Plan + Config
**Modificar:** `ruadan/attackplan.ini`, `ruadan/config.ini`

Adicionar novas fases:
```ini
[Metasploit Exploit Execution]
run once: Metasploit Exploit Module

[Metasploit Handler Start]
run once: Metasploit Start Handler

[Metasploit Session Interaction]
run once: Metasploit Session Commands
```

**Entradas no Config.ini** (template-driven):
```ini
[Metasploit Exploit Module]
Command: msfrpc_exploit --module <module> --target <ip> --payload <payload> --lhost <lhost> --lport <lport> >> <output>.txt
Findings SessionCreated: (Session \d+ created)

[Metasploit Start Handler]
Command: msfrpc_handler --payload <payload> --lhost <lhost> --lport <lport> --exit-on-session >> <output>.txt
Findings HandlerStarted: (Handler started on \d+)

[Metasploit Session Commands]
Command: msfrpc_session --session <id> --command "<cmd>" >> <output>.txt
```

### Fase 4: Segurança & Auditoria (Crítico)
- **Verificação de canary** para cada execução de módulo MSF (já em `bridge/canary.py`)
- **Enforcement de escopo** — `strict_scope.py` deve validar CIDR do target ANTES de QUALQUER módulo MSF rodar
- **Limpeza de sessão** — auto-kill handlers no fim da campanha / Ctrl-C
- **Log de evidência** — todo comando MSF + output → `executed_commands.log` + manifesto SHA256

### Fase 5: Docker & Integração de Startup
- Adicionar serviço `msgrpc` no `docker-compose.yml` (ou rodar dentro do `kali-ruadan` via supervisor)
- Atualizar `start.sh` para aguardar health endpoint do `msgrpc`
- Montar `/tmp/msf_sessions` para persistência de sessão entre restarts

---

## Perguntas Antes de Prosseguir

1. **Biblioteca MSF RPC preferida:** `pymetasploit3` (mantido) vs XML-RPC raw vs gem `msfrpc`? Container atual tem Ruby?

2. **Bind de handlers:** `kali-ruadan` usa `network_mode: host`. Handlers devem bind em `0.0.0.0` (NIC do host) ou apenas container? Targets são máquinas de lab externas → precisam de NIC do host.

3. **Estratégia de payload:** Staged (`meterpreter/reverse_tcp`) vs stageless? Staged = menor, precisa handler; stageless = maior, autocontido.

4. **Persistência de sessão:** Manter sessões meterpreter vivas entre restarts do Ruadan? Requer daemon `msgrpc` + DB de sessão.

5. **Escopo do MVP Fase 1:** Apenas `EXPLOIT_REMOTE` → execução de módulo MSF + handler, ou incluir módulos post-exploit de `PRIVILEGE_ESCALATE`/`PERSIST_BACKDOOR` também?

6. **Estratégia de merge no GitHub:** Repo único com subdiretórios (`/ruadan`, `/red-mppo`, `/bridge`, `/docker`, `/configs`) — layout atual. Expectativas de CI/CD?

---

**Pronto para implementar Fase 1 quando confirmar o plano.** Quais perguntas priorizar?

---

# ✅ ETAPA 1 IMPLEMENTADA (2026-09-24 ~20:00 UTC): Pipeline de Exploração MSF

## O que foi implementado (funcionando)

### `ruadan/msf_exploit_phase.sh` — pipeline E2E num ÚNICO msfconsole
```
1. PostgreSQL + DB MSF (msf_start_db.sh, idempotente)
2. Handlers armados (exploit -j -z, processo vivo):
   • linux/x64/shell_reverse_tcp:4444
   • windows/meterpreter/reverse_tcp:4445
3. Scanners SAFE por serviço detectado (ssh_version, http_version, smb_version,
   mysql_version, ftp_version, telnet, smtp, rdp, snmp, redis, postgres, mongodb)
4. sessions -v (estado real)
5. Parse → MSF_SESSION_OPENED / MSF_CHECK_RESULT (evidência parseável)
6. [selftest] msfvenom linux/x64/meterpreter → execução local → session de VERDADE
```

### Integrações
| Ponto | O quê |
|---|---|
| `config.ini` | Seção `[Metasploit Exploit Phase]` + findings `MSFSession`/`MSFCheck` |
| `attackplan.ini` | Fase `[Metasploit Exploitation]` (run once) |
| Dispatcher EXPLOIT_REMOTE | Roda a fase após GoBuster |
| Dispatcher evidence | `_has_msf_session()` → `MSF_SESSION_OPENED` = **evidence_level=credential (C2 REAL)** |

### Por que um único msfconsole (sem RPC ainda)
Cada `msfconsole` é um processo isolado — jobs/sessions morrem com ele. O pipeline
usa UM resource script (.rc) dinâmico gerado por alvo: handlers + scanners +
sessions no MESMO processo. RPC (msgrpc) = Etapa 2 (interação com a session:
sysinfo, getuid, pivoting).

## Honestidade contra o Juice Shop
O Juice Shop é app web Node.js (SQLi/XSS/IDOR) — **sem RCE conhecido**. O pipeline
roda, reporta os checks e "nenhuma session" honestamente. **A session abre quando
o alvo tiver serviço explorável** (ex: VM com vsftpd backdoor, Samba CVE etc. no
lab). O SELFTEST prova o mecanismo E2E com um meterpreter local.

## Etapa 2 (próxima): interação com session via msgrpc
- msfrpcd + cliente Python (python3-msgpack)
- session: sysinfo, getuid, upload/download, screenshot
- Pós-exploit: local_exploit_suggester → privesc REAL → evidence

---

# 🏆 ETAPA 1 CONCLUÍDA COM PROVA REAL (2026-09-24 22:56 UTC)

## Selftest E2E: SESSION DE VERDADE ABERTA
```
MSF_SESSION_OPENED: Meterpreter session 1 opened (192.168.50.210:4444 -> 192.168.50.210:33450) at 2026-09-24 22:56:10 +0000
[msf-phase] *** SESSION(ÕES) ABERTA(S) — C2 REAL ESTABELECIDO ***
```

## O que a prova estabelece
1. Handler `exploit -j -z` permanece vivo (processo msfconsole único) ✓
2. Conexão reversa capturada: **Meterpreter session 1** ✓
3. Parse do log → `MSF_SESSION_OPENED` → findings → **evidence_level=credential** na kill chain ✓
4. Timing validado: boot ~50s → disparo T0+90s → session T0+91s → captura T0+125s ✓

## Bug de timing corrigido na validação (v1 preservada em .backup/)
`sleep 12` no rc fazia o console morrer ANTES do disparo (handler morto → connection
refused silencioso). Corrigido para `sleep 75` + timeout 240 — console vivo até
depois da captura.

## Como a fase funciona num run real (`./start.sh`)
- `EXPLOIT_REMOTE` (dispatcher) roda a fase `[Metasploit Exploitation]`
- Handlers: `linux/x64/shell_reverse_tcp:4444` + `windows/meterpreter/reverse_tcp:4445`
- Scanners SAFE por serviço detectado (ssh_version, http_version, smb, mysql, ftp, rdp, snmp, redis, postgres, mongodb)
- **Se o alvo tiver RCE explorável → session abre → `evidence_level=credential` (C2 REAL)**
- Se não (ex: Juice Shop, app web sem RCE) → pipeline roda + reporta honestamente
- Para validar o mecanismo em qualquer run: `bash /ruadan/msf_exploit_phase.sh <alvo> <portas> <output> selftest`

## ETAPA 2 (roadmap): interação com a session via msgrpc
- msfrpcd + python3-msgpack; session: sysinfo, getuid, upload/download
- local_exploit_suggester → privesc REAL (root de verdade → EXPLOITED_ROOT com evidência)
- Pós-exploit: hashdump, screenshot, pivoting para LATERAL_MOVE

---

# 🏆 ETAPA 2 CONCLUÍDA E PROVADA (2026-09-24 ~23:55 UTC): C2 persistente via msfrpcd

## Prova E2E (saída real do teste)
```
MSF_SESSION_OPENED: sid=1 tipo=meterpreter peer=192.168.50.210:51336 via=exploit/multi/handler
MSF_SYSINFO: sid=1 | Computer: Lazarus | OS: Debian (Linux 6.1.0-35-amd64) | Architecture: x64 | Meterpreter: x64/linux
MSF_GETUID: sid=1 | Server username: root
MSF_ROOT_CONFIRMED: sid=1 | Server username: root — ROOT REAL OBTIDO
MSF_PRIVESC_SUGGESTION: sid=1 | Collecting local exploits for x64/linux... (2.684 módulos verificados)
[msf-rpc] Evidência estruturada: msf_c2_evidence.json

=== C2-STATUS (processo separado, passos depois) ===
[c2-status] *** 1 SESSION(S) VIVA(S) — C2 REALMENTE ESTABELECIDO ***
MSF_SESSION_OPENED: sid=1 ... [ATIVA]
```

## O que a Etapa 2 entrega ao ciclo IA
- **Session persistente**: msfrpcd fica vivo durante o run; o C2_ESTABLISH (passo seguinte)
  lista e interage com a session aberta no EXPLOIT_REMOTE — C2 real entre passos
- **Pós-exploit real**: sysinfo (host/OS/arquitetura reais), getuid (usuário REAL —
  se root → MSF_ROOT_CONFIRMED → EXPLOITED_ROOT com evidência), local_exploit_suggester
  (2.684 módulos verificados contra o kernel/sistema REAL)
- **Findings → evidence**: MSFSession/MSFSysinfo/MSFGetuid/MSFRoot no config.ini
  promovem a kill chain com evidence_level=credential baseada em dados reais

## Saga de debug do protocolo (documentada para nunca mais sofrer)
1. Flags do msfrpcd: `-P` = SENHA, `-p` = PORTA (inverter = "starting on 127.0.0.1:msf")
2. **O msfrpcd 6.x é MsgPack sobre HTTP** (não msgpack-rpc binário puro!):
   `POST /api/` com `Content-Type: binary/message-pack`, body = msgpack **[método, *params]**
   (array simples — sem msgid!), response = map `{"result","token"}` / `{"error"}`
   — descoberto via MITM do cliente ruby oficial (proxy python logando os bytes)
3. Strings chegam como BIN type → decode recursivo bytes→str
4. `session.list` retorna map com chaves INTEIRAS (SIDs) → `strict_map_key=False`
5. `meterpreter_read` responde em chunks `{'data': str}` → extração limpa + drain do buffer

## Backups (regra imutável): msf_exploit_phase_py v1..v6 em .backup/

## Polimento final (v7)
- `mtr_read`: extrai texto limpo dos chunks `{'data': str}` + `mtr_drain` antes de cada comando
- Output da fase LIMPO (comprovado): `MSF_SYSINFO: Computer: Lazarus | OS: Debian (Linux 6.1.0-35-amd64) | x64`
- `--c2-status` enxuto: só confirma sessions ativas (sysinfo/getuid já emitidos limpos na fase;
  buffer do suggester em background não contamina mais a evidência do C2)

## ETAPA 3 (roadmap final): execução de exploits com session
- Disparar os exploits sugeridos pelo local_exploit_suggester VIA RPC (module.execute na session)
- getsystem / migration de processo / hashdump
- PERSIST_BACKDOOR com módulo real (ex: post/linux/manage/...)
- LATERAL_MOVE com route/arp da session (descoberta de vizinhos a partir do host comprometido)

---

# ETAPA 3 IMPLEMENTADA (2026-09-25 ~00:30 UTC): Pós-exploit ofensivo REAL

## `ruadan/msf_post_session.py` — ações sobre a session ativa (msfrpcd persistente)

| Ação | O que faz de verdade | Evidência parseável |
|---|---|---|
| `creds` | `getuid` + **`cat /etc/shadow` (Linux) / hashdump (Windows) pela session** | `MSF_CREDS_COLLECTED` (hash root real) |
| `privesc` | **local_exploit_suggester COMPLETO** contra o kernel REAL; extrai as sugestões verificadas e **DISPARA os top exploits via RPC** na session; se nova session root | `MSF_ROOT_OBTAINED` (→ evidence credential + EXPLOITED_ROOT real) |
| `pivot` | **`arp` pela session** — vizinhos REAIS da rede interna vistos do host comprometido | `MSF_PIVOT_NEIGHBOR` (insumo para LATERAL_MOVE) |
| `persist` | **GATE DUPLO** (`MSF_ALLOW_PERSIST=1` + ação explícita): default só detecta permissão (`/etc/cron.d` gravável); liberado, instala cron de reconexão marcado | `MSF_PERSIST_READY` |

## Integração no ciclo IA (dispatcher)
| Ação RL | Nova fase | Findings → evidence |
|---|---|---|
| `PRIVILEGE_ESCALATE` | `Metasploit Session Privesc` | MSFRoot → **credential** ("ROOT REAL OBTIDO") |
| `PERSIST_BACKDOOR` | `Metasploit Session Persist` | MSFPersist |
| `LATERAL_MOVE` | `Metasploit Session Pivot` | MSFPivot (vizinhos da rede interna) |

## Segurança
- Persistência REAL é OPT-IN (gate duplo): nunca instala backdoor por engano
- Privesc dispara apenas módulos VERIFICADOS pelo suggester contra o host real
- Tudo em lab próprio/autorizado (a mesma premissa do red-MPPO)

## Teste E2E (selftest): session real → creds (shadow REAL) → suggester → pivot (arp REAL) → persist (gate)
Resultado: [em anexo após a execução]
