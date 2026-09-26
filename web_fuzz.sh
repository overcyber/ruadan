#!/bin/bash
# ==============================================================================
# Ruadan - Fuzzing de conteúdo web SUPERIOR ao gobuster (wildcard-proof)
# ==============================================================================
# Uso: web_fuzz.sh <target> <port> <scheme>
#
# POR QUE ESTE SCRIPT EXISTE: o gobuster ABORTA quando o alvo responde igual
# para tudo (soft-403/catch-all da SPA — ex: proxy octopux responde 403/146
# para qualquer path, e a SPA responde 200/9903 para o resto). Nenhum fuzzer
# de status-code puro consegue trabalhar num alvo assim.
# A solução é AUTO-CALIBRAÇÃO: o ffuf (-ac) faz N requests com strings
# aleatórias, aprende a assinatura do wildcard (status+tamanho) e filtra
# automaticamente — só reporta respostas que DIFEREM do catch-all.
#
# Pipeline: ffuf (-ac) → feroxbuster (fallback) → gobuster (último recurso)
# Saída parseável: WEB_CONTENT_FOUND: <url> (HTTP <code>, <size> bytes)
# ==============================================================================
set -u

TARGET="${1:?uso: web_fuzz.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 15"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

WORDLIST="${WEBFUZZ_WORDLIST:-/usr/share/dirb/wordlists/common.txt}"
[ -f "$WORDLIST" ] || WORDLIST="/usr/share/dirb/wordlists/common.txt"

# ---- Detecta redirect HTTP -> HTTPS -------------------------------------------
BASE_URL="${SCHEME}://${TARGET}:${PORT}"
if [ "$SCHEME" = "http" ]; then
    _redir=$(curl $CURL_OPTS -o /dev/null -w "%{redirect_url}" "${BASE_URL}/" 2>/dev/null)
    if [ -n "$_redir" ] && [[ "$_redir" == https* ]]; then
        echo "[fuzz] ${BASE_URL} redireciona para HTTPS — usando ${_redir%/}" >&2
        BASE_URL="${_redir%/}"
    fi
fi
echo "[fuzz] Alvo: ${BASE_URL} | wordlist: ${WORDLIST}"

# ---- Preferência 1: ffuf com AUTO-CALIBRAÇÃO ----------------------------------
if command -v ffuf >/dev/null 2>&1; then
    echo "[fuzz] Executando ffuf com auto-calibração (-ac)..."
    FFUF_CSV="${TMPD}/ffuf.csv"
    if [ "$SCHEME" = "https" ]; then
        TLS_OPTS="-k"
    else
        TLS_OPTS=""
    fi
    ffuf -u "${BASE_URL}/FUZZ" -w "$WORDLIST" -ac -t 40 -se \
        $TLS_OPTS -o "$FFUF_CSV" -of csv >/dev/null 2>&1
    if [ -s "$FFUF_CSV" ]; then
        # CSV: FUZZ,url,location,input,status,length,words,lines
        tail -n +2 "$FFUF_CSV" | while IFS=, read -r _f _url _loc _inp _status _len _w _l; do
            echo "WEB_CONTENT_FOUND: ${_url} (HTTP ${_status}, ${_len} bytes)"
        done | sort -u
        _n=$(tail -n +2 "$FFUF_CSV" | wc -l)
        echo "[fuzz] ffuf: ${_n} conteúdo(s) encontrado(s) (wildcard filtrado por auto-calibração)."
        exit 0
    else
        echo "[fuzz] ffuf não retornou conteúdo além do wildcard."
        exit 0
    fi
fi

# ---- Preferência 2: feroxbuster ------------------------------------------------
if command -v feroxbuster >/dev/null 2>&1; then
    echo "[fuzz] ffuf ausente — executando feroxbuster (auto-filtro de tamanho)..."
    feroxbuster -u "$BASE_URL" -w "$WORDLIST" -t 40 -n -q \
        --insecure --auto-filter-size --auto-filter-words 2>&1 | \
        grep -oE "https?://[^ ]+" | sort -u | while read -r u; do
            echo "WEB_CONTENT_FOUND: ${u}"
        done
    exit 0
fi

# ---- Último recurso: gobuster --------------------------------------------------
if command -v gobuster >/dev/null 2>&1; then
    echo "[fuzz] ffuf/feroxbuster ausentes — caindo para gobuster (limitado em alvos com wildcard)."
    gobuster dir -e -t 30 --no-error --no-tls-validation \
        -s "200,204,500,403,301,302,308,307" --status-codes-blacklist "" \
        -u "$BASE_URL/" -w "$WORDLIST" 2>&1 | grep -E "^https?://" | \
        while read -r line; do echo "WEB_CONTENT_FOUND: $line"; done
    exit 0
fi

echo "[fuzz][ERRO] Nenhum fuzzer disponível (ffuf, feroxbuster, gobuster)."
exit 0
