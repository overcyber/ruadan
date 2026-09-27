# Análise Profunda: Run Completo de 4h27m (2026-09-27)

## MELHORIAS QUE FUNCIONARAM

### 1. Searchsploit AGORA usa product+version (não mais genérico):
```
ANTES (errado):  "snmp" → exploits de Solaris 1999
AGORA (correto): "ISC BIND 9.16.50"        ← product+version real
                 "OpenSSH 8.4p1 Debian 5"  ← product+version real
                 "Squid http proxy 4.13"  ← product+version real
                 "VMware Authentication Daemon 1.10"
                 "Debian Apt-Cacher NG httpd 3.6.4"
```

### 2. 3 CVEs candidatas identificadas por version_match:
- CVE-2024-6387 (regreSSHion) → OpenSSH 9.6p1 no juice.octopux
- CVE-2023-48795 (Terraprefix) → OpenSSH 8.4p1 no 192.168.50.222
- CVE-2020-11950 (Squid) → Squid 4.13 no 192.168.50.222

### 3. LLM mais ativo: 17 tool calls (vs 6 no run anterior)
Tools usadas: exploit_search(6), ssh_login(2), service_scan(2), run_command(2),
get_state(2), web_discover(1), http_probe(1), cve_lookup(1)

### 4. 3,681 exploits copiados (todos com product específico)
Total: 160=1604, 221=0, 222=2077

## PROBLEMAS QUE PERSISTEM

### 1. F2.6 (exploit_execute) NUNCA rodou
Zero entradas "[F2.6]" no hunt.log. O `_execute_exploits_for_confirmed_cves`
está posicionado CORRETAMENTE (após cve_validate) mas:

CAUSA PROVÁVEL: O código está correto no arquivo, mas o CONTAINER usa uma
 imagem Docker construída ANTES da correção. O mount -v monta o código,
 mas o zeroday_hunt.py é importado do PYTHONPATH=/app/red-mppo (não do mount).
 Verificar se o mount está correto no docker-run.sh.

### 2. Skills-red NÃO foram injetadas
Zero "METODOLOGIAS" nos transcripts do LLM. O `_build_system_prompt` foi
adicionado mas o `from skills_context import build_skills_context` falha
silenciosamente (try/except captura o ImportError).

CAUSA: `bridge/skills_context.py` está no HOST mas o container procura em
`/bridge/`. Verificar se o volume mount inclui este arquivo.

### 3. "Ruadan Added Always/Run Once Service" ainda é buscado
O searchsploit busca por "Ruadan Added Always Service" — um PLACEHOLDER interno.

CAUSA: O nmap_dict tem entradas com product="Ruadan Added Always Service"
(adicionado pelo próprio Ruadan para rodar comandos "always"). O exploit_search
usa `if product: target_query = product` — busca pelo placeholder.

FIX: Adicionar verificação `if "Ruadan Added" in product: continue`

### 4. 12/13 passos ainda são enum_only
Nenhum exploit real foi executado. As 3 CVEs candidatas não foram disparadas.

### 5. Modelo LLM: qwen3:8b (não gpt-oss:20b)
O campaign report mostra `llm: ollama/qwen3:8b`. O ZeroDay Hunt deveria usar
`gpt-oss:20b` (configurado no zeroday_hunt_phase.sh). O LLM do Ciclo IA usa
qwen3:8b (correto), mas o hunter deveria usar gpt-oss:20b.

## AÇÃO CORRETIVA NECESSÁRIA

1. Verificar se zeroday_hunt.py no container tem o código corrigido
2. Verificar se skills_context.py está montado no container
3. Filtrar "Ruadan Added" no exploit_search
4. Confirmar que o F2.6 realmente roda (adicionar print/log de debug)
5. Verificar se o modelo gpt-oss:20b está sendo usado no hunter
