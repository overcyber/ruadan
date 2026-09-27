# Análise Profunda: Por Que Nada Foi Explorado + Correções Implementadas

**Data:** 2026-09-26 | **Backups:** 85+ arquivos em `.backup/` (regra imutável)

## 5 Causas Raiz (diagnóstico do run completo de 4h+)

### CAUSA 1 — A ponte CVE→exploit estava QUEBRADA (CRÍTICA)
```
ANTES: _execute_exploits_for_confirmed_cves() procurava CVEs em suite_findings
       → suite_findings tinha 0 CVEs (elas iam para cve_validations!)
       → método nunca encontrava nada → NUNCA executava exploit

DEPOIS: método agora lê cve_validations (onde as CVEs realmente estão)
        + movido para DEPOIS da validação cve_validate()
        + aceita "candidata_version" e "candidata_searchsploit"
```

### CAUSA 2 — O LLM foi PASSIVO (só 6 tool calls em 3 runs)
```
Chamou:     service_scan(2), exploit_search(2), web_discover(1), http_probe(1)
NUNCA chamou: exploit_execute, ssh_login, remote_exec, check_root, cred_attack
Motivo: HUNT_SYSTEM_PROMPT dizia "INOFENSIVO" + cred_attack não estava em HUNT_TOOLS
```

### CAUSA 3 — SEM credenciais válidas + sem bruteforce
```
Inventory: "ruadan-lab-probe" (placeholder)
cred_attack: EXCLUÍDO de HUNT_TOOLS
→ LLM não podia fazer password spray em SSH/RDP/VNC/Squid
```

### CAUSA 4 — Juice Shop é seguro contra RCE por design
```
Tem: SQLi, XSS, IDOR, info disclosure — 14 vulns reais
NÃO tem: RCE, file upload com execução, prototype pollution detectável
→ shell no host 160 não vem da página web
```

### CAUSA 5 — Serviços do 222 estão patcheados
```
SSH: CVE-2024-6387 REFUTADA (OpenSSH 8.4 < 8.5)
Squid: CVE-2020-11950 candidata (mas requer validação real)
RDP/VNC/NFS: exigem autenticação (sem credenciais)
→ sem exploits públicos aplicáveis aos serviços atuais
```

## Correções Implementadas (6 fixes)

| # | Fix | Impacto |
|---|---|---|
| 1 | `_execute_exploits_for_confirmed_cves` lê `cve_validations` + movido para APÓS `cve_validate` | **CRÍTICO** — agora exploits serão executados |
| 2 | `cred_attack` ADICIONADO ao HUNT_TOOLS | LLM pode fazer password spray |
| 3 | `HUNT_SYSTEM_PROMPT` atualizado: "FIRE!" + protocolo cred_attack + exploit_execute para CADA CVE | LLM será mais agressivo |
| 4 | Dockerfile: `build-essential` + `libc6-dev` | `.c` exploits compilam (stdio.h disponível) |
| 5 | `Network Firewall Detection` (nmap firewalk) no config.ini + attackplan.ini | Detecta firewall/port filtering |
| 6 | `Port Filter Analysis` (nmap --script=firewalk --traceroute) | Análise de portas filtradas |

## Problemas Adicionais Encontrados nos Logs

### 192.168.50.221: praticamente vazio
- Apenas pasta `always/` com output mínimo
- RL detectou "servicos mínimos" — host com pouquíssima superfície
- **Esperado**: host pode não ter serviços exploráveis

### SSH vazio em ambos 160 e 222
- Diretórios `ssh/` criados mas 0 arquivos
- Comandos SSH não geraram output — possivelmente os comandos do config.ini
  para SSH não rodam ou falham silenciosamente
- **Investigar**: verificar se [Information Gathering] ssh: commands rodam

### Exploit test results: exploits IRRELEVANTES
- SNMP: exploits de 1999-2012 (Solaris snmpXdmid) — nada a ver com o alvo
- `.c` files: não compilavam por falta de build-essential (CORRIGIDO)
- `.rb` files: carregavam como MSF mas não EXECUTAVAM
- searchsploit busca por NOME do serviço (não por versão específica)

### ZeroDay findings eram "fakes" (informativos, não 0-days)
- `dns_version_disclosure`: BIND 9.16.50-Debian revelando versão — informativo, não explorável
- `reflection`: XSS refletido — vulnerabilidade conhecida, não 0-day
- Estes são findings corretos mas NÃO são 0-days. O hunter é honesto sobre isso.

## O que esperar no próximo run
```
1. CVE-2023-48795 (Teraprefix SSH) → exploit_execute será chamado
2. CVE-2020-11950 (Squid) → exploit_execute será chamado
3. cred_attack → password spray em SSH:221, RDP:3389, VNC:5900, Squid:3128
4. Firewall detection → nmap firewalk para detectar port filtering
5. build-essential → .c exploits compilam corretamente
6. LLM mais agressivo → mais tool calls, mais hipóteses testadas
```

## Git
- Commit: `aa619cd` pushed to `origin/2025`
- 85+ backups em `.backup/`
