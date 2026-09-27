# Relatório: Implementação e Teste dos Itens 1, 2 e 3 (SQLi, Duplicação, Paralelismo)

**Data:** 2026-09-24 ~17:00 (UTC-3)
**Run de validação:** `./start.sh -hostFile /ruadan/targets/meu_lab.txt` — 5 passos, LLM **10/10 SUCCESS**

---

## 1️⃣ SQLMap Login Probe — SQLi REAL detectada no run ✅

### O que foi implementado
| Arquivo | Mudança |
|---|---|
| `ruadan/sqlmap_login_probe.sh` | **NOVO**: probe de SQLi em 4 endpoints de login comuns; detecta redirect HTTP→HTTPS automaticamente; baseline (credencial inválida) vs bypass clássico (`' OR 1=1--`); confirma via sqlmap só no endpoint vivo; **pula sqlmap de verificação quando não há diff** (economia de ~10min/run) |
| `ruadan/config.ini` | Seções `[HTTP/HTTPS SQLMap Login]` com `Findings SQLiLoginBypass` (regex parseável) |
| `ruadan/attackplan.ini` | `[Exploitation]` http/https agora dispara o probe (primeiro comando da fase) |
| `bridge/action_dispatcher.py` | `_has_login_bypass()` → bypass confirmado = `evidence_level="credential"` |

### Resultado no run (prova real)
```
[probe] http://juice.octopux:80 redireciona para HTTPS — usando https://juice.octopux
[probe] /rest/user/login → baseline=401 bypass=200
SQLI_LOGIN_BYPASS_CONFIRMED: https://juice.octopux/rest/user/login
[probe] EVIDÊNCIA: {"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...email":"admin@juice-sh.op","role":"admin"
```
**Bypass de autenticação REAL com JWT de ADMIN capturado como evidência.**

### Bug fino encontrado e corrigido (pós-run)
O passo 2 ficou `evidence=finding` em vez de `credential`. Causa: **o configparser lowerifica os labels** (`SQLiLoginBypass` → `sqliloginbypass` — o arquivo gerado é `sqliloginbypass.txt`), e o dispatcher buscava case-sensitive. Corrigido para busca case-insensitive + **unit test aprovado**:
```
PASSOU: bypass detectado (lowercase) e idempotente
```
→ No próximo run, o passo que executa o probe será promovido a `evidence_level=credential`.

## 2️⃣ Duplicação hostname/IP — eliminada ✅

**Causa:** `sync_nmap_dict_hosts()` (design SNI/VHost) espelha as portas em AMBAS as keys (hostname↔IP) → cada fase executava 2x.

**Correção:** dedup por IP efetivo no `enumerate()` (a key canônica — hostname — processa; a contraparte é pulada).

**Prova no debuglog do run:**
```
enumerate() - Host: juice.octopux
enumerate() - contraparte espelhada pulada (mesmo IP que 192.168.50.160): 192.168.50.160
```
→ Comandos 1x por fase, pasta única no output, Metasploit DB start 1x só.

## 3️⃣ Proteção anti-runs-paralelos ✅

`check_parallel_run()` no `docker-run.sh` (modos scan): se já houver container da imagem ativo → **aborta com instrução clara**. Validado:
```
[!] ERRO: já existe um run do Ruadan ativo (imagem ruadan:kali):
      044b56cb2b89 7 seconds ago
```
Bypass consciente: `RUADAN_ALLOW_PARALLEL=1 ./start.sh ...`

## 🔧 Bugs extras descobertos nos logs e corrigidos nesta rodada

| Bug | Causa raiz | Correção |
|---|---|---|
| Gobuster EXIT_1 em HTTPS | gobuster 3.x valida certificado TLS por padrão; o cert do alvo é **CN=octopux ≠ juice.octopux** → `x509: certificate is valid for octopux` | `--no-tls-validation` (flag correta do 3.8.2 — a primeira tentativa `--no-tls-validate` não existe) em 12 comandos |
| `vulscan/vulscan.nse` EXIT_1 | Script é addon de terceiro (não vem no nmap) — `did not match a category, filename, or directory` | Trocado por **`--script=vulners`** (NSE padrão que consulta CVEs REAIS por versão de produto) |
| Gobuster "zero resultados" | **Comportamento CORRETO**: o proxy do alvo responde `403 (Length: 146)` para QUALQUER URL inexistente (soft-403/wildcard) — o gobuster detecta e aborta por design para não reportar 4600 falsos positivos | Nada a corrigir — a mensagem de wildcard agora é visível no `commanderrorlog.txt` |

## 📊 Resultado consolidado do run de validação

| Métrica | Valor |
|---|---|
| Passos | 5 (EXPLOIT_REMOTE → PRIVESC → PERSIST → C2 → EXFILTRATE) |
| LLM (container Docker) | **10/10 SUCCESS, 0 FAILED** |
| SQLi bypass confirmado | ✅ 2x (fases http+https do [Exploitation]) com JWT admin |
| Evidence passo 2 | `finding` (2 achados = os bypass) — será `credential` no próximo run (fix case) |
| Metasploit | ✅ **PONTA A PONTA**: PostgreSQL real → role/banco → schema → `Added workspace: meu_lab` → `Successfully imported` 2 XMLs → `msfhosts.csv` com host real + `msfservices.csv` com 22/ssh, 80/http... |
| Duplicação | ✅ Eliminada (debuglog comprova) |
| Pastas de output | 1 por alvo (`juice_octopux/`) |

## Próximos passos naturais
1. Rodar novamente para validar `evidence_level=credential` com o fix do case (SQLi bypass promovendo a kill chain com evidência real)
2. Plano Meterpreter/MSF (`PLANO_METERPRETER_MSCONSOLE.md`) — agora com a infra MSF 100% funcional (DB, workspace, import), faltam os módulos de exploit/handlers via MSGRPC
