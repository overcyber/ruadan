#!/bin/bash
# ==============================================================================
# Ruadan - Extrator de rotas de SPA (Single Page Application) via bundle JS
# ==============================================================================
# Uso: spa_route_extract.sh <target> <port> <scheme>
#
# POR QUE ESTE SCRIPT EXISTE: fuzzers de diretório (gobuster/ffuf) testam
# PATHS NO SERVIDOR — rotas de frontend tipo '/#/score-board' (hash Angular)
# NÃO existem no servidor: vivem dentro do main.js do bundle. Este script:
#   1. Baixa o index.html e todos os bundles .js referenciados
#   2. Extrai rotas de router minificado:  path:"rota"  e  path: 'rota'
#   3. Filtra assets/rotas parametrizadas e deduplica
#   4. Testa cada rota contra o servidor e compara com o BASELINE (rota
#      inexistente = resposta catch-all da SPA) — reporta tudo que DIFIERE,
#      mais as rotas de alto-valor sempre que presentes.
#   5. Saída parseável: SPA_ROUTE_FOUND: <rota> (HTTP <code>, <size> bytes)
#      → findings do Ruadan (Findings SPARoutes)
# ==============================================================================
set -u

TARGET="${1:?uso: spa_route_extract.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 20"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# ---- Detecta redirect HTTP -> HTTPS -----------------------------------------
BASE_URL="${SCHEME}://${TARGET}:${PORT}"
if [ "$SCHEME" = "http" ]; then
    _redir=$(curl $CURL_OPTS -o /dev/null -w "%{redirect_url}" "${BASE_URL}/" 2>/dev/null)
    if [ -n "$_redir" ] && [[ "$_redir" == https* ]]; then
        echo "[spa] ${BASE_URL} redireciona para HTTPS — usando ${_redir%/}" >&2
        BASE_URL="${_redir%/}"
    fi
fi
echo "[spa] Alvo: ${BASE_URL}"

# ---- Baixa index.html e descobre os bundles .js ------------------------------
curl $CURL_OPTS "${BASE_URL}/" -o "${TMPD}/index.html" 2>/dev/null
if [ ! -s "${TMPD}/index.html" ]; then
    echo "[spa][ERRO] Não foi possível obter o index da aplicação."
    exit 0
fi
JS_FILES=$(grep -oE '(src|href)="[^"]*\.js"' "${TMPD}/index.html" | sed 's/.*="//;s/"//' | sort -u)
echo "[spa] Bundles JS encontrados: $(echo "$JS_FILES" | wc -l)"

# ---- Baixa cada bundle e extrai rotas de router (minificado e legível) ------
ALL_ROUTES="${TMPD}/routes_raw.txt"
: > "$ALL_ROUTES"
for js in $JS_FILES; do
    case "$js" in
        http*) url="$js" ;;
        /*)     url="${BASE_URL}${js}" ;;
        *)      url="${BASE_URL}/${js}" ;;
    esac
    curl $CURL_OPTS "$url" -o "${TMPD}/bundle.js" 2>/dev/null
    [ -s "${TMPD}/bundle.js" ] || continue
    # Angular Router minificado:  path:"rota"      /      legível: path: 'rota'
    grep -oE 'path:"[^"]+"' "${TMPD}/bundle.js" | sed 's/path:"//;s/"$//' >> "$ALL_ROUTES" 2>/dev/null
    grep -oE "path:\s*'[^']+'" "${TMPD}/bundle.js" | sed "s/path:\s*'//;s/'$//" >> "$ALL_ROUTES" 2>/dev/null
done

# ---- Filtra e deduplica ------------------------------------------------------
ROUTES=$(sort -u "$ALL_ROUTES" | grep -vE '(^$|^:|/:|^js$|^/js$|\.js$|\.css$|\.png$|\.ico$|\.svg$)' | grep -vE '[${}()&; |]' | head -120)
N_TOTAL=$(echo "$ROUTES" | grep -c . || true)
echo "[spa] Rotas candidatas extraídas: ${N_TOTAL}"
[ "$N_TOTAL" -eq 0 ] && exit 0

# ---- Baseline: resposta catch-all da SPA (rota inexistente) ------------------
BASE_STATUS=$(curl $CURL_OPTS -H "Accept: text/html" -o /dev/null -w "%{http_code}" "${BASE_URL}/ruadan-nonexistent-${RANDOM}" 2>/dev/null)
BASE_SIZE=$(curl $CURL_OPTS -H "Accept: text/html" -o /dev/null -w "%{size_download}" "${BASE_URL}/ruadan-nonexistent-${RANDOM}" 2>/dev/null)
echo "[spa] Baseline (catch-all): HTTP ${BASE_STATUS} / ${BASE_SIZE} bytes"

# ---- Testa cada rota: reporta as que DIFEREM do catch-all ---------------------
HIGH_VALUE="score-board|admin|administration|swagger|api-doc|debug|config|backup|\.env|metrics|telemetry|graphql"
FOUND=0
while read -r route; do
    [ -z "$route" ] && continue
    code=$(curl $CURL_OPTS -H "Accept: text/html" -o /dev/null -w "%{http_code}" "${BASE_URL}/${route}" 2>/dev/null)
    size=$(curl $CURL_OPTS -H "Accept: text/html" -o /dev/null -w "%{size_download}" "${BASE_URL}/${route}" 2>/dev/null)
    differs=0
    [ "$code" != "$BASE_STATUS" ] && differs=1
    [ "$size" != "$BASE_SIZE" ] && differs=1
    high=0
    echo "/${route}" | grep -qiE "${HIGH_VALUE}" && high=1
    if [ "$differs" -eq 1 ] || [ "$high" -eq 1 ]; then
        tag=""
        [ "$high" -eq 1 ] && tag="[ALTO VALOR]"
        echo "SPA_ROUTE_FOUND: /${route} (HTTP ${code}, ${size} bytes${tag:+, ${tag}})"
        FOUND=$((FOUND + 1))
    fi
done <<< "$ROUTES"

echo "[spa] Rotas reportadas: ${FOUND} de ${N_TOTAL} candidatas (rotas '#/rota' acessíveis na SPA em ${BASE_URL}/#/)"
exit 0
