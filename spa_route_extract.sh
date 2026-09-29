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
#
# EVASÃO (evasion_lib.sh): budget global, jitter, detecção de bloqueio com
# rotação de IP, 1 request onde antes eram 2, pula portas emuladas, aborto
# gracioso. enabled=0 → padrão de requests idêntico ao original.
# ==============================================================================
set -u

TARGET="${1:?uso: spa_route_extract.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 20"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# ---- Camada de evasão -----------------------------------------------------------
_EV_LIB="$(dirname "${BASH_SOURCE[0]}")/evasion_lib.sh"
[ -f "$_EV_LIB" ] || _EV_LIB="/ruadan/evasion_lib.sh"
. "$_EV_LIB"
ev_init "$TARGET" "$PORT" "$SCHEME"
ev_skip_port && exit 0
ev_should_abort && exit 0

# ---- Detecta redirect HTTP -> HTTPS -----------------------------------------
BASE_URL="${SCHEME}://${TARGET}:${PORT}"
if [ "$SCHEME" = "http" ]; then
    _redir=$(curl $CURL_OPTS ${EV__IDA[@]+"${EV__IDA[@]}"} -o /dev/null -w "%{redirect_url}" "${BASE_URL}/" 2>/dev/null)
    if [ -n "$_redir" ] && [[ "$_redir" == https* ]]; then
        echo "[spa] ${BASE_URL} redireciona para HTTPS — usando ${_redir%/}" >&2
        BASE_URL="${_redir%/}"
    fi
fi
ev_set_probe_url "${BASE_URL}/"
echo "[spa] Alvo: ${BASE_URL}"

# ---- Baixa index.html e descobre os bundles .js ------------------------------
ev_code_bodyfile "${TMPD}/index.html" $CURL_OPTS "${BASE_URL}/"
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
    ev_should_abort && exit 0
    case "$js" in
        http*) url="$js" ;;
        /*)     url="${BASE_URL}${js}" ;;
        *)      url="${BASE_URL}/${js}" ;;
    esac
    ev_code_bodyfile "${TMPD}/bundle.js" $CURL_OPTS "$url"
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
ev_code_size $CURL_OPTS -H "Accept: text/html" "${BASE_URL}/ruadan-nonexistent-${RANDOM}"
BASE_STATUS="$EV_CODE"; BASE_SIZE="$EV_SIZE"
echo "[spa] Baseline (catch-all): HTTP ${BASE_STATUS} / ${BASE_SIZE} bytes"

# ---- Testa cada rota: reporta as que DIFEREM do catch-all ---------------------
HIGH_VALUE="score-board|admin|administration|swagger|api-doc|debug|config|backup|\.env|metrics|telemetry|graphql"
FOUND=0
while read -r route; do
    [ -z "$route" ] && continue
    ev_should_abort && exit 0
    ev_code_size $CURL_OPTS -H "Accept: text/html" "${BASE_URL}/${route}"
    code="$EV_CODE"; size="$EV_SIZE"
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
