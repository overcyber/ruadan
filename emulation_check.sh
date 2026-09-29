#!/bin/bash
# ==============================================================================
# Ruadan — Detecção de Porta Emulada ("fita") — honeypot/port-stealing detector
# ==============================================================================
# Uso: emulation_check.sh <target> <port> <scheme> [state_dir]
#
# POR QUÊ: a defesa do lab EMULA portas e serviços (responde como se fossem
# reais para Sugar o atacante e queimar o budget de tentativas). O Ruadan
# estava fuzzando 13 portas do mesmo alvo — a maioria fita. Este script
# classifica cada porta HTTP-candidata ANTES do fuzzing:
#
#   1. TTL: SYN-ACK da porta (via nping, vem com o nmap) vs TTL do ICMP.
#      Serviço real responde do MESMO host → mesmo TTL. Fita responde de
#      outro hop/appliance → TTL divergente. (+2 pontos, sinal forte)
#   2. Timing sintético: 4 requests a /; spread (max-min de time_total)
#      < 2ms = resposta de loop emulada (app real tem jitter de GC/disk/sched).
#      (+1 ponto)
#   3. Body clone: GET / e GET /ruadan-<rand> com MESMO código 200 E MESMO
#      md5 = responder igual para qualquer path = fita. (+2 pontos)
#      (403/404 para ambos = wildcard conhecido do proxy — não conta)
#   4. Cross-port clone: md5 de / desta porta igual ao md5 de / de outra
#      porta já verificada do mesmo alvo = mesma fita servindo portas.
#      (+1 ponto)
#
# Veredito: score >= 2 → EMULATED (high se tiver ttl/clone, senão medium)
#           score == 1 → suspeita (reporta, NÃO pula automaticamente)
#
# Saída (stdout vira finding do Ruadan via regex no config.ini):
#   EMULATED_SERVICE: <t>:<porta> confidence=<high|medium> reason=<sinais>
#   EMULATED_SUSPECT: <t>:<porta> reason=<sinais> (score 1 — não pula)
#
# Estado (se state_dir informado, com flock — compartilhado com evasion_lib):
#   emchk_<port>=1            já verificado
#   emulated_ports=53,902,... append da porta quando high/medium
#   md5_<port>=<hash>         para cross-port clone
#   req_count += <requests>   budget compartilhado
# ==============================================================================
set -u

TARGET="${1:?uso: emulation_check.sh <target> <port> <scheme> [state_dir]}"
PORT="${2:?porta}"
SCHEME="${3:-http}"
STATE_DIR="${4:-}"
[ -n "$STATE_DIR" ] && mkdir -p "$STATE_DIR" 2>/dev/null

BASE_URL="${SCHEME}://${TARGET}:${PORT}"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

EV_PROBE_TIMEOUT="${EV_PROBE_TIMEOUT:-4}"
_score=0
_reasons=""

# ---------- Helpers de estado (self-contained, mesmas chaves da evasion_lib) ----
_st_get() {
    [ -n "$STATE_DIR" ] && [ -f "${STATE_DIR}/evasion_state.env" ] || return 0
    grep -m1 "^$1=" "${STATE_DIR}/evasion_state.env" 2>/dev/null | cut -d= -f2-
}
_st_set() {
    [ -n "$STATE_DIR" ] || return 0
    local lf="${STATE_DIR}/.state.lock" f="${STATE_DIR}/evasion_state.env"
    (
        flock 9
        grep -v "^$1=" "$f" 2>/dev/null > "$f.tmp"
        echo "$1=$2" >> "$f.tmp"
        mv "$f.tmp" "$f"
    ) 9>"$lf" 2>/dev/null
}
_st_append_list() {  # $1=chave $2=valor → mantém lista CSV sem duplicar
    [ -n "$STATE_DIR" ] || return 0
    local cur; cur=$(_st_get "$1")
    case ",$cur," in
        *",$2,"*) return 0 ;;
    esac
    _st_set "$1" "${cur:+$cur,}$2"
}
_req_bump() {  # $1=n
    [ -n "$STATE_DIR" ] || return 0
    local lf="${STATE_DIR}/.state.lock" f="${STATE_DIR}/evasion_state.env" cur
    (
        flock 9
        cur=$(grep -m1 '^req_count=' "$f" 2>/dev/null | cut -d= -f2-); cur="${cur:-0}"
        grep -v '^req_count=' "$f" 2>/dev/null > "$f.tmp"
        echo "req_count=$((cur + ${1:-1}))" >> "$f.tmp"
        mv "$f.tmp" "$f"
    ) 9>"$lf" 2>/dev/null
}
_req_bump_noreq() { :; }

TOTAL_REQS=0

# ---------- Sinal 1: TTL (nping SYN-ACK vs ICMP) --------------------------------
ttl_score=0
ICMP_TTL=""
TCP_TTL=""
if command -v ping >/dev/null 2>&1; then
    ICMP_TTL=$(ping -c 2 -W 2 "$TARGET" 2>/dev/null | grep -oE 'ttl=[0-9]+' | head -1 | cut -d= -f2)
fi
if command -v nping >/dev/null 2>&1; then
    # -PA dá SYN-ACK; captura TTL das respostas RCVD
    TCP_TTL=$(nping --tcp -p "$PORT" -c 2 --delay 200ms "$TARGET" 2>/dev/null \
        | grep -oE 'TTL=[0-9]+' | head -1 | cut -d= -f2)
fi
if [ -n "$ICMP_TTL" ] && [ -n "$TCP_TTL" ]; then
    d=$(( ICMP_TTL > TCP_TTL ? ICMP_TTL - TCP_TTL : TCP_TTL - ICMP_TTL ))
    if [ "$d" -ge 2 ]; then
        ttl_score=2
        _reasons="${_reasons}ttl_mismatch(icmp=${ICMP_TTL},tcp=${TCP_TTL}),"
    fi
elif [ -n "$TCP_TTL" ]; then
    # sem ICMP para baseline: TTL ímpar/estranho não conclui — só registra
    :
fi
_score=$((_score + ttl_score))

# ---------- Sinal 2: timing sintético -------------------------------------------
tim_score=0
spread=""
times=()
for i in 1 2 3 4; do
    t=$(curl -sk --max-time "$EV_PROBE_TIMEOUT" -o /dev/null -w '%{time_total}' "${BASE_URL}/" 2>/dev/null)
    case "$t" in
        ''|0.000000*) continue ;;  # morreu — não é sinal de timing
    esac
    times+=("$t")
done
TOTAL_REQS=$((TOTAL_REQS + 4))
if [ "${#times[@]}" -ge 3 ]; then
    spread=$(printf '%s\n' "${times[@]}" | sort -g | awk 'NR==1{min=$1} {max=$1} END{printf "%.4f", max-min}')
    # spread < 0.002s (2ms) com 3+ amostras = resposta de loop sintético
    if awk -v s="$spread" 'BEGIN{exit !(s < 0.002)}'; then
        tim_score=1
        _reasons="${_reasons}uniform_timing(spread=${spread}s),"
    fi
fi
_score=$((_score + tim_score))

# ---------- Sinal 3: body clone (/ vs path aleatório) ---------------------------
clone_score=0
BODY_A="${TMPD}/a"; BODY_B="${TMPD}/b"
code_a=$(curl -sk --max-time "$EV_PROBE_TIMEOUT" -o "$BODY_A" -w '%{http_code}' "${BASE_URL}/" 2>/dev/null)
code_b=$(curl -sk --max-time "$EV_PROBE_TIMEOUT" -o "$BODY_B" -w '%{http_code}' "${BASE_URL}/ruadan-fitacheck-$RANDOM" 2>/dev/null)
TOTAL_REQS=$((TOTAL_REQS + 2))
if [ "$code_a" = "200" ] && [ "$code_b" = "200" ] && [ -s "$BODY_A" ] && [ -s "$BODY_B" ]; then
    h_a=$(md5sum "$BODY_A" 2>/dev/null | cut -d' ' -f1)
    h_b=$(md5sum "$BODY_B" 2>/dev/null | cut -d' ' -f1)
    if [ "$h_a" = "$h_b" ]; then
        clone_score=2
        _reasons="${_reasons}body_clone(/==random),"
    fi
fi
_score=$((_score + clone_score))

# ---------- Sinal 4: cross-port clone --------------------------------------------
cross_score=0
if [ -n "$STATE_DIR" ]; then
    if [ "$code_a" = "200" ] && [ -s "$BODY_A" ]; then
        h_a=$(md5sum "$BODY_A" 2>/dev/null | cut -d' ' -f1)
        if [ -n "$h_a" ]; then
            _st_set "md5_$PORT" "$h_a"
            # alguma outra porta já verificada tem o mesmo md5?
            other=$(
                grep -E "^md5_[0-9]+=$h_a$" "${STATE_DIR}/evasion_state.env" 2>/dev/null \
                | grep -v "^md5_$PORT=" | head -1 | cut -d= -f1 | sed 's/md5_//'
            )
            if [ -n "$other" ]; then
                cross_score=1
                _reasons="${_reasons}cross_port_clone(==porta ${other}),"
            fi
        fi
    fi
fi
_score=$((_score + cross_score))

# ---------- Registra consumo de budget ------------------------------------------
_req_bump "$TOTAL_REQS" 2>/dev/null || true

# ---------- Veredito -------------------------------------------------------------
_reasons="${_reasons%,}"
[ -z "$_reasons" ] && _reasons="sem sinais"

if [ "$_score" -ge 2 ]; then
    _conf="medium"
    if [ "$ttl_score" -gt 0 ] || [ "$clone_score" -gt 0 ]; then _conf="high"; fi
    echo "EMULATED_SERVICE: ${TARGET}:${PORT} confidence=${_conf} reason=${_reasons} score=${_score}"
    [ -n "$STATE_DIR" ] && _st_append_list emulated_ports "$PORT"
elif [ "$_score" -eq 1 ]; then
    echo "EMULATED_SUSPECT: ${TARGET}:${PORT} reason=${_reasons} score=1 (nao pula automaticamente)"
fi
exit 0
