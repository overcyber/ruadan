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
#
# EVASÃO (evasion_lib.sh, [EVASION] enabled=1):
#   - ffuf com -t 4 (eram 40 threads!), -p jitter 0.2-1.5s, -rate 8/s
#   - rotação de source-IP via SOCKS5 do pool (-x) quando identidade > 0
#   - wordlist em CHUNKS com probe de bloqueio entre lotes
#   - budget global + orçamento de tempo por porta + aborto gracioso
#   enabled=0 → ffuf original idêntico (-t 40, sem chunks).
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

# ---- Camada de evasão -----------------------------------------------------------
_EV_LIB="$(dirname "${BASH_SOURCE[0]}")/evasion_lib.sh"
[ -f "$_EV_LIB" ] || _EV_LIB="/ruadan/evasion_lib.sh"
. "$_EV_LIB"
ev_init "$TARGET" "$PORT" "$SCHEME"
ev_skip_port && exit 0
ev_should_abort && exit 0

# ---- Detecta redirect HTTP -> HTTPS -------------------------------------------
BASE_URL="${SCHEME}://${TARGET}:${PORT}"
if [ "$SCHEME" = "http" ]; then
    _redir=$(curl $CURL_OPTS ${EV__IDA[@]+"${EV__IDA[@]}"} -o /dev/null -w "%{redirect_url}" "${BASE_URL}/" 2>/dev/null)
    if [ -n "$_redir" ] && [[ "$_redir" == https* ]]; then
        echo "[fuzz] ${BASE_URL} redireciona para HTTPS — usando ${_redir%/}" >&2
        BASE_URL="${_redir%/}"
    fi
fi
ev_set_probe_url "${BASE_URL}/"
echo "[fuzz] Alvo: ${BASE_URL} | wordlist: ${WORDLIST}"

# ---- Preferência 1: ffuf com AUTO-CALIBRAÇÃO ----------------------------------
if command -v ffuf >/dev/null 2>&1; then
    if [ "$SCHEME" = "https" ]; then
        TLS_OPTS="-k"
    else
        TLS_OPTS=""
    fi

    if [ "$EV_ENABLED" = 1 ]; then
        # ---- MODO EVASÃO: chunks + jitter + rate + rotação de IP ----
        FFUF_CSV="${TMPD}/ffuf_all.csv"
        : > "$FFUF_CSV"
        _hdr_written=0
        _n_total=0
        split -l "$EV_CHUNK_SIZE" "$WORDLIST" "${TMPD}/chunk." 2>/dev/null
        for _chunk in "${TMPD}/chunk."*; do
            ev_should_abort && break
            # probe: ainda respondendo? se morreu, rotaciona identidade/IP
            if ! ev_probe "${BASE_URL}/"; then
                ev_rotate
                ev_should_abort && break
            fi
            _part="${TMPD}/ffuf_part.csv"
            ffuf -u "${BASE_URL}/FUZZ" -w "$_chunk" -ac $TLS_OPTS \
                $(ev_ffuf_args) -o "$_part" -of csv >/dev/null 2>&1
            if [ -s "$_part" ]; then
                if [ "$_hdr_written" = 0 ]; then
                    head -n 1 "$_part" >> "$FFUF_CSV"; _hdr_written=1
                fi
                tail -n +2 "$_part" >> "$FFUF_CSV"
                _n_total=$((_n_total + $(tail -n +2 "$_part" | wc -l)))
            fi
            rm -f "$_part"
        done
        rm -f "${TMPD}/chunk."*
        # budget: conta as palavras fuzzadas + calibração (~15/chunk) — flock-safe
        _chunks=$(( (_n_total + EV_CHUNK_SIZE) / EV_CHUNK_SIZE ))
        _bump=$(( _n_total + _chunks * 15 ))
        ev_state_bump_requests "$EV_STATE_DIR" "$_bump"
        EV_REQ_COUNT=$((EV_REQ_COUNT + _bump))
        if [ -s "$FFUF_CSV" ]; then
            tail -n +2 "$FFUF_CSV" | while IFS=, read -r _f _url _loc _inp _status _len _w _l; do
                echo "WEB_CONTENT_FOUND: ${_url} (HTTP ${_status}, ${_len} bytes)"
            done | sort -u
            echo "[fuzz] ffuf: ${_n_total} conteúdo(s) encontrado(s) (wildcard filtrado por auto-calibração)."
        else
            echo "[fuzz] ffuf não retornou conteúdo além do wildcard."
        fi
        exit 0
    fi

    # ---- MODO ORIGINAL (enabled=0): comportamento idêntico ao histórico ----
    echo "[fuzz] Executando ffuf com auto-calibração (-ac)..."
    FFUF_CSV="${TMPD}/ffuf.csv"
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
