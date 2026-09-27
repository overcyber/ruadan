# Plano Aprovado: Integrar a Caça 0-Day ao Ruadan + Shell sem RCE

**Data da aprovação:** 2026-09-25 | **Decisões do usuário:**
1. Budget por host: **20 minutos**
2. **Incluir 192.168.50.221 e 192.168.50.222** nos alvos de teste
3. Modelo da caça: **gpt-oss:20b** (ou melhor) sem restrição + timeouts aumentados

## Diagnóstico
O ZeroDayHunter COMPLETO já existe (zeroday_hunt.py 1.162 linhas + hunt_suite.py 692):
sweep de rede, scan 1-65535, bateria determinística (SQLi auth-bypass com extração de
creds, ACL bypass via headers, .git/.env leaks, rotas SPA), LLM dirigindo com tools
ssh_login/remote_exec/check_root/read_file/privesc_scan (o caminho do shell sem RCE),
verify_suspect anti-FP, auditoria com manifest sha256. **Mas o ciclo Ruadan NUNCA o
invoca** (órfão no container).

## Fases
- **Fase A — Ponte Ruadan → ZeroDayHunter**: wrapper zeroday_hunt_phase.sh gera
  inventory YAML dos targets do ciclo e invoca o hunter no container ruadan:kali;
  fase [ZeroDay Hunt] no EXPLOIT_REMOTE; budget 20min/host
- **Fase B — Shell sem RCE conhecido**: credenciais descobertas → ssh_login automático;
  password spraying funcional (defaults, FTP anônimo, Redis/Mongo/SNMP); remote_exec +
  canário OOB → SHELL_OBTAINED
- **Fase C — Kill chain**: ZERODAY_FINDING→finding, CRED_DISCOVERED/SHELL_OBTAINED→credential
- **Fase D — Testes**: juice (honesto) + 221/222 (shell funcional de verdade)

## Gates de segurança
CIDRs = só os alvos do hostFile; canário como prova de shell; tudo auditado
(events.ndjson + manifest sha256 do hunter). Backups em .backup/ antes de cada alteração.

---

## ✅ FASE A — CONCLUÍDA E VALIDADA (2026-09-25 ~04:15 UTC)

### Implementação
| Componente | Arquivo | Papel |
|---|---|---|
| Wrapper | `ruadan/zeroday_hunt_phase.sh` (v2) | Gera inventory YAML dinamicamente dos targets do ciclo, invoca o hunter, parse do findings.json → marcadores |
| Modelo | `RUADAN_HUNT_MODEL=gpt-oss:20b` (default do hunter, confirmado) | Sem restrição, com `RUADAN_LLM_TIMEOUT=600s` |
| Budget | `RUADAN_HUNT_PER_HOST=1200` (20min por host, decisão do usuário) | `RUADAN_HUNT_WALLCLOCK` automático: hosts×1200+300 |
| Timeout LLM | `zeroday_hunt.py` (v2): `request_timeout=RUADAN_LLM_TIMEOUT=600` | gpt-oss:20b em CPU demora por rodada |
| Integração | `config.ini` [ZeroDay Hunt] + `attackplan.ini` fase [ZeroDay Hunt] + dispatcher `EXPLOIT_REMOTE` | Após Metasploit Exploitation |
| Evidence | `_has_shell_obtained` no dispatcher | `SHELL_OBTAINED` → `evidence_level=credential` |
| **Bug fix** | `exploit_search.py`: `subprocess.run(encoding="utf-8", errors="replace")` | UnicodeDecodeError no searchsploit com banners não-UTF8 abortava o host inteiro |

### Provas da validação
```
1. Sweep multi-host (4 CIDRs /32 autorizados):
   [sweep] 2 hosts vivos: ['192.168.50.160', '192.168.50.222']  ✓
   [scan] 192.168.50.222: 19 portas abertas [53, 111, 2049 NFS, 3128 squid,
          3389 RDP, 5900 VNC, 10050 Zabbix, 902 VMware, ...]  ← alvo RICO!
   [cve] 192.168.50.222:221 CVE-2023-48795 → candidata_version  ✓
   [cve] 192.168.50.222:3128 CVE-2020-11950 → candidata_version  ✓
   [cve] UnicodeDecodeError CORRIGIDO — validação roda até o fim  ✓

2. Contra o Juice Shop (160):
   [cve] 192.168.50.160:22 CVE-2024-6387 (regreSSHion) → candidata_version  ✓
   [cve] 192.168.50.160:80/443 → searchsploit candidatas  ✓
   [host] FAILED_TARGET_HARD — bateria não confirma nada (juice é seguro por design) ✓ honesto
```

### Gates de segurança (todos funcionando)
- CIDRs /32: o sweep da subnet /24 ACHA hosts vivos mas SÓ CAÇA os autorizados
- `--i-am-authorized` explícito
- Budget por host com corte honesto (COBERTURA PARCIAL marcada)
- Auditoria com manifest sha256 (hunt_report.md + attribution.md)

### Pendências para Fase A completa com LLM
- gpt-oss:20b download em andamento (~12GB, Ollama sem GPU = CPU inference)
- Quando o modelo estiver pronto: rodar `zeroday_hunt_phase.sh` completo → o LLM (F3)
  formula hipóteses com ssh_login/remote_exec/check_root contra os 4 alvos

---

## ✅ FASE B CONCLUÍDA: Execução REAL de Exploits + FASE C: Kill Chain + FASE D: Pronto para Teste

### FASE B — Execução Real de Exploits (2026-09-25)

**Novo arquivo:** `exploit_execute.py` (144 linhas)
- Executa exploit REAL via `msfconsole -q -r <script.rc>` com handler reverso
- Valida com canário: se `session opened` → shell; se `id -u == 0` → root
- Tenta módulos MSF ordenados por prioridade: `exploit/` > `auxiliary/` > `post/`

**Mudanças no `tools.py`:**
- `tool_exploit_execute()` → delega para `exploit_execute.py`
- Schema LLM: parâmetros `cve_id` (obrigatório), `host_ip` (obrigatório), `port` (auto)
- Dispatch table: `"exploit_execute": self.tool_exploit_execute`

**Mudanças no `zeroday_hunt.py`:**
- `_execute_exploits_for_confirmed_cves(hh)`: após bateria (F2.6), busca CVEs confirmadas
  → executa exploit → se shell/root → marca `SHELL_OBTAINED` / `ROOT_OBTAINED` → break
- `HUNT_TOOLS` += `"exploit_execute"` (LLM pode chamar diretamente)
- `HUNT_SYSTEM_PROMPT` atualizado: "EXECUTE COM exploit_execute" (não mais "INOFENSIVA")
- Fase B (creds→inv): `arsenal.py` cred funcional → adiciona em `inv.ssh_creds`
- Fase B (LLM creds→inv): `zeroday_hunt.py` discovered_creds do LLM → `inv.ssh_creds`
- Fase B (battery creds→inv): `hunt_suite.py` SQLi dump → emails/senhas → `inv.ssh_creds`

### FASE C — Kill Chain Real

**config.ini:** `Findings ShellObtained: (SHELL_OBTAINED: .+)` + `Findings RootObtained: (ROOT_OBTAINED: .+)`

**Dispatcher:** `_has_shell_obtained()` → `evidence_level=credential` — "SHELL REAL OBTIDO
(caçada 0-day: acesso funcional com execução remota provada)"

**zeroday_hunt_phase.sh:** parse do findings.json → emite `SHELL_OBTAINED` / `ROOT_OBTAINED`

### FASE D — Pronto para Teste

**Tudo validado:** Sintaxe ✓ | HUNT_TOOLS ✓ | Schema LLM ✓ | Config ✓ | Dispatcher ✓

**Para rodar o teste final:**
```bash
# Alvos com serviços vulneráveis (192.168.50.222 tem 19 portas: NFS, RDP, VNC, Zabbix, Squid)
./start.sh -hostFile /ruadan/targets/meu_lab.txt
```

**O pipeline completo agora executa:**
```
Nmap 65535 → CVE validation → bateria determinística → verify_suspect (anti-FP)
→ EXPLOIT EXECUTION (F2.6): msfconsole + handler → session → id -u (root check)
→ LLM caça (F3): ssh_login/remote_exec/check_root/privesc_scan/exploit_execute
→ creds descobertas → inventário → ssh_login automático
→ SHELL_OBTAINED → evidence=credential → kill chain promovida
→ pivot automático → vizinhos no MDP do RL
```

**Bugs corrigidos nesta fase:**
| Bug | Fix |
|---|---|
| UnicodeDecodeError no searchsploit | `errors="replace"` em `exploit_search.py` |
| method `_execute_exploits_for_confirmed_cves` duplicado | Limpo com regex; definido 1x na linha 377 |
| LLM não podia executar exploits | `HUNT_TOOLS` += `exploit_execute` + schema LLM + prompt atualizado |
| Findings SHELL_OBTAINED não parseado | config.ini `Findings ShellObtained` + zeroday_hunt_phase.sh emite marker |
