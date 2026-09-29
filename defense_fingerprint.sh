#!/bin/bash
# ==============================================================================
# Ruadan — Defense Fingerprint (o que a defesa é e como ela bloqueia)
# ==============================================================================
# Uso: defense_fingerprint.sh <target> <port> <scheme> <state_dir> [source_ip]
#
# CHAMADO PELA evasion_lib no PRIMEIRO bloqueio de cada alvo (fp_done no
# estado). Roda ATRAVÉS da identidade recém-queimada — o momento ideal para
# observar COMO a defesa trata um IP bloqueado:
#
#   1. Camada do bloqueio (GET / com timeout curto + time_total):
#        403/429        → block_layer=http_403   (WAF/firewall responde HTTP)
#        000 rápido     → behavior=reset         (RST ou drop imediato)
#        000 até estourar o timeout → behavior=silent_drop (tarpit/blackhole)
#   2. IPS inline: GET benigno vs GET com path-traversal encodado.
#        benigno responde + suspeito morre → assinatura inline detectada
#   3. Emite FIREWALL_DETECTED (e IPS_SIGNATURE_DETECTED quando aplicável)
#      e persiste defense_profile no estado para o LLM/RL despriorizar.
#
# Consome ~4 requests do budget (registrados no estado compartilhado).
# ==============================================================================
set -u

TARGET="${1:?uso: defense_fingerprint.sh <target> <port> <scheme> <state_dir> [source_ip]}"
PORT="${2:?porta}"
SCHEME="${3:-http}"
STATE_DIR="${4:-}"
SRC_IP="${5:-}"
[ -n "$STATE_DIR" ] && mkdir -p "$STATE_DIR" 2>/dev/null

BASE_URL="${SCHEME}://${TARGET}:${PORT}"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

IDA=()
[ -n "$SRC_IP" ] && IDA=(--interface "$SRC_IP")

TOTAL_REQS=0

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
_req_bump() {
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

# ---------- 1. Camada do bloqueio ------------------------------------------------
behavior="unknown"; block_layer="unknown"
out=$(curl -sk --max-time 4 -o /dev/null -w '%{http_code} %{time_total}' ${IDA[@]+"${IDA[@]}"} "$BASE_URL/" 2>/dev/null)
TOTAL_REQS=$((TOTAL_REQS + 1))
code="${out%% *}"; tt="${out##* }"

if [ "$code" = "403" ] || [ "$code" = "429" ]; then
    block_layer="http_${code}"
    behavior="http_responds"
elif [ -z "$code" ] || [ "$code" = "000" ]; then
    block_layer="tcp"
    # reset/drop rápido (time_total < 1.0s) vs tarpit/silent drop (esperou até o timeout)
    if awk -v t="$tt" 'BEGIN{exit !(t < 1.0)}' 2>/dev/null; then
        behavior="reset"
    else
        behavior="silent_drop"
    fi
else
    block_layer="http_${code}"
    behavior="partial"
fi

echo "FIREWALL_DETECTED: ${TARGET}:${PORT} behavior=${behavior} block_layer=${block_layer} probe_code=${code:-000} time=${tt}s"

# ---------- 2. IPS inline (assinatura de payload) --------------------------------
ips_class=""
benign=$(curl -sk --max-time 4 -o /dev/null -w '%{http_code}' ${IDA[@]+"${IDA[@]}"} \
    "${BASE_URL}/ruadan-benigno-$RANDOM" 2>/dev/null)
TOTAL_REQS=$((TOTAL_REQS + 1))
sus=$(curl -sk --max-time 4 -o /dev/null -w '%{http_code}' ${IDA[@]+"${IDA[@]}"} \
    "${BASE_URL}/ruadan-%2e%2e%2fetc%2fpasswd-$RANDOM" 2>/dev/null)
TOTAL_REQS=$((TOTAL_REQS + 1))
# só concluímos se o benigno respondeu (TCP ok) e o suspeito morreu
if [ -n "$benign" ] && [ "$benign" != "000" ] && [ -z "$sus" -o "$sus" = "000" ]; then
    ips_class="path_traversal"
    echo "IPS_SIGNATURE_DETECTED: ${TARGET}:${PORT} class=${ips_class} (benigno=HTTP ${benign}, suspeito=sem resposta)"
    _st_set ips_inline "1"
fi

# ---------- 3. Persiste o perfil ---------------------------------------------------
_req_bump "$TOTAL_REQS" 2>/dev/null || true
_st_set defense_profile "${behavior}/${block_layer}${ips_class:+ ips_inline=${ips_class}}"
exit 0
