#!/bin/bash
# ==============================================================================
# Ruadan — Evasion Library (camada de evasão anti-bloqueio/anti-fita)
# ==============================================================================
# Uso (source-only, chamado pelos fuzzers):
#     . /ruadan/evasion_lib.sh
#     ev_init <target> <port> <scheme>
#     ... ev_body_and_code $CURL_OPTS "$URL" ... ; usa $EV_BODY / $EV_CODE
#
# MODO DESLIGADO ([EVASION] enabled=0 no config.ini):
#   Todas as funções viram pass-through com o MESMO padrão de requests dos
#   fuzzers originais (inclusive o request duplo histórico) — comportamento
#   idêntico ao antigo. Serve para não alterar um run forense em andamento.
#
# MODO LIGADO (enabled=1):
#   - Budget GLOBAL de requests por alvo — compartilhado entre TODAS as
#     ferramentas (a defesa conta por IP, não por ferramenta; agora nós também)
#   - Janela deslizante de códigos HTTP → detecção de bloqueio:
#       * K1 respostas consecutivas 403/429  (block_403_threshold)
#       * K2 timeouts consecutivos (000)    (block_timeout_threshold)
#       * K3 mistos 000/403/429 consecutivos(block_mixed_threshold)
#   - Rotação de identidade/IP: identidade 0 = IP direto do host;
#     identidades 1..N = pool [EVASION] ip_pool (aliases na interface)
#     curl usa --interface <ip>; ffuf/gobuster usam SOCKS5 do evasion_pool
#   - Cooldown com APRENDIZADO EMPÍRICO: quando um IP queimado volta a
#     responder, o tempo decorrido vira o cooldown conhecido (persistido)
#   - Rotação PROATIVA: após aprender o threshold de bloqueio da defesa,
#     rotaciona ANTES de queimar (fator proactive_rotate_factor)
#   - Jitter aleatório entre requests + rate limit nos fuzzers de wordlist
#   - Pula portas EMULADAS (emulation_check.sh, detecção de "fita")
#   - Fingerprint da defesa no primeiro bloqueio (defense_fingerprint.sh):
#     silent_drop vs reset vs tarpit; IPS inline (payload suspeito morre?)
#   - Orçamento de tempo por porta (fim dos 26min/porta pendurados)
#   - Aborto GRACIOSO: budget/pool esgotado → exit 0 com log; o pipeline segue
#
# Linhas de finding emitidas (regex no config.ini):
#   EMULATED_SERVICE: <t>:<porta> confidence=<c> reason=<r>
#   TARGET_BLOCKED: <t>:<porta> identity=<n> recent=<codes> requests_identity=<n>
#   IP_ROTATED: <t>:<porta> identity <old> -> <new> (<ip>) probe=HTTP <c>
#   FIREWALL_DETECTED: <t>:<porta> behavior=<b> block_layer=<l>
#   IPS_SIGNATURE_DETECTED: <t>:<porta> class=<c>
#   EVASION_BUDGET_EXHAUSTED: <t> <n>/<budget> requests
#   EVASION_POOL_EXHAUSTED: <t>:<porta> todas as identidades queimadas
#   EVASION_TIME_BUDGET: <t>:<porta> <s>s >= <budget>s
# ==============================================================================

# ---------- Source-time defaults (set -u safe) --------------------------------
# IMPORTANTE: usar ${VAR:-} — NUNCA atribuir valor direto aqui, senão a lib
# CLOBBERA as variáveis de ambiente (overrides de teste/config) do processo pai.
# Evitação de bloqueio só ativa depois de ev_init (env > config.ini > default).
EV_ENABLED="${EV_ENABLED:-}"
EV_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
EV_CONFIG="${EV_CONFIG:-/ruadan/config.ini}"
EV_OUTPUT_DIR="${EV_OUTPUT_DIR:-${RUADAN_OUTPUT_DIR:-/ruadan/output}}"
EV_TARGET=""; EV_PORT=""; EV_SCHEME="http"
EV_STATE_DIR=""; EV_WINDOW_FILE=""; EV_STATE_FILE=""
EV_POOL_IPS=()
EV__IDA=()               # args curl da identidade atual (--interface <ip>)
EV_IDENT=0; EV_IDENT_PREV=0
EV_REQ_COUNT=0; EV_REQ_IDENT=0
EV_BLOCKED_EVENTS=0
EV_COOLDOWN_LEARNED="${EV_COOLDOWN_LEARNED:-0}"
EV_ABORT=0; EV_ABORT_REASON=""
EV_BUDGET_LOGGED=0
EV_EMULATED=0
EV_PROBE_URL=""
EV_JITTER_MIN="${EV_JITTER_MIN:-}"
EV_JITTER_MAX="${EV_JITTER_MAX:-}"
EV_RATE_RPS="${EV_RATE_RPS:-}"
EV_FFUF_THREADS="${EV_FFUF_THREADS:-}"
EV_BLOCK_403_THRESHOLD="${EV_BLOCK_403_THRESHOLD:-}"
EV_BLOCK_TIMEOUT_THRESHOLD="${EV_BLOCK_TIMEOUT_THRESHOLD:-}"
EV_BLOCK_MIXED_THRESHOLD="${EV_BLOCK_MIXED_THRESHOLD:-}"
EV_COOLDOWN_BASE="${EV_COOLDOWN_BASE:-}"
EV_COOLDOWN_MAX="${EV_COOLDOWN_MAX:-}"
EV_COOLDOWN_LEARN_MIN="${EV_COOLDOWN_LEARN_MIN:-}"
EV_PROACTIVE_FACTOR="${EV_PROACTIVE_FACTOR:-}"
EV_BUDGET="${EV_BUDGET:-}"
EV_PORT_TIME_BUDGET="${EV_PORT_TIME_BUDGET:-}"
EV_PROBE_TIMEOUT="${EV_PROBE_TIMEOUT:-}"
EV_PROXY_BASE_PORT="${EV_PROXY_BASE_PORT:-}"
EV_CHUNK_SIZE="${EV_CHUNK_SIZE:-}"
EV_EMULATION_CHECK="${EV_EMULATION_CHECK:-}"
EV_DEFENSE_FINGERPRINT="${EV_DEFENSE_FINGERPRINT:-}"
EV_SOCKS_OK=0

# ---------- Parser de config ([EVASION] do config.ini) ------------------------
# configparser lowerifica labels; o awk compara tudo minúsculo.
_ev_cfg() {
    local key="$1" default="${2:-}" cfg="$EV_CONFIG"
    [ -f "$cfg" ] || { printf '%s' "$default"; return 0; }
    local val
    val=$(awk -v k="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" '
        BEGIN { in_sec = 0 }
        tolower($0) ~ /^[[:space:]]*\[evasion\][[:space:]]*$/ { in_sec = 1; next }
        in_sec && /^[[:space:]]*\[/ { in_sec = 0 }
        in_sec && index($0, "=") > 0 {
            key = tolower($1); sub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            sub(/^[^=]*=/, "", $0)
            sub(/^[[:space:]]+/, "", $0); sub(/[[:space:]]+$/, "", $0)
            if (key == k) { print $0; exit }
        }
    ' "$cfg" 2>/dev/null)
    printf '%s' "${val:-$default}"
}

# Expande "192.168.50.240-249", "192.168.50.240-192.168.50.249" ou "ip1,ip2"
# → lista de IPs (uma por linha). Range no último octeto (mesma subnet /24).
_ev_expand_pool() {
    local spec="${1:-}" part ip b1 b2 b3 s e i
    [ -z "$spec" ] && return 0
    local IFS=','
    for part in $spec; do
        part="${part//[[:space:]]/}"
        [ -z "$part" ] && continue
        if [[ "$part" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)-([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
            # forma IP-completo: A.B.C.X-A.B.C.Y (mesma subnet /24 exigida)
            b1="${BASH_REMATCH[1]}"; b2="${BASH_REMATCH[2]}"; b3="${BASH_REMATCH[3]}"
            s="${BASH_REMATCH[4]}"; e="${BASH_REMATCH[8]}"
            if [ "${BASH_REMATCH[5]}.${BASH_REMATCH[6]}.${BASH_REMATCH[7]}" != "${b1}.${b2}.${b3}" ]; then
                continue   # range entre subnets diferentes: ignora (não suportado)
            fi
            for ((i = s; i <= e; i++)); do
                printf '%s.%s.%s.%s\n' "$b1" "$b2" "$b3" "$i"
            done
        elif [[ "$part" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)$ ]]; then
            ip="${BASH_REMATCH[1]}"; e="${BASH_REMATCH[2]}"
            IFS='.' read -r b1 b2 b3 s <<< "$ip"
            for ((i = s; i <= e; i++)); do
                printf '%s.%s.%s.%s\n' "$b1" "$b2" "$b3" "$i"
            done
        else
            printf '%s\n' "$part"
        fi
    done
}

# ---------- Estado (arquivo KEY=VALUE com flock; compartilhado entre tools) ----
_ev_state_get() {
    [ -f "$EV_STATE_FILE" ] || return 0
    grep -m1 "^$1=" "$EV_STATE_FILE" 2>/dev/null | cut -d= -f2-
}
_ev_state_set() {
    [ "$EV_ENABLED" = 1 ] || return 0
    local k="$1" v="$2" lf="${EV_STATE_DIR}/.state.lock"
    (
        flock 9
        grep -v "^$k=" "$EV_STATE_FILE" 2>/dev/null > "${EV_STATE_FILE}.tmp"
        echo "$k=$v" >> "${EV_STATE_FILE}.tmp"
        mv "${EV_STATE_FILE}.tmp" "$EV_STATE_FILE"
    ) 9>"$lf" 2>/dev/null
}

_ev_ident_curl_args() {
    EV__IDA=()
    if [ "$EV_ENABLED" = 1 ] && [ "$EV_IDENT" -gt 0 ] && [ "$EV_IDENT" -le "${#EV_POOL_IPS[@]}" ]; then
        EV__DA_IF=""
        EV__DA_IF="${EV_POOL_IPS[$((EV_IDENT - 1))]}"
        [ -n "$EV__DA_IF" ] && EV__IDA=(--interface "$EV__DA_IF")
    fi
}

# ---------- Jitter -------------------------------------------------------------
ev_jitter() {
    [ "$EV_ENABLED" = 1 ] || return 0
    local d
    d=$(awk -v a="$EV_JITTER_MIN" -v b="$EV_JITTER_MAX" 'BEGIN{srand(); printf "%.2f", a + rand() * (b - a)}')
    sleep "$d"
}

# ---------- Registro de código HTTP (janela deslizante + budget + bloqueio) ----
_ev_trim_window() {
    local n
    n=$(wc -l < "$EV_WINDOW_FILE" 2>/dev/null || echo 0)
    [ "$n" -gt 300 ] && tail -n 150 "$EV_WINDOW_FILE" > "${EV_WINDOW_FILE}.t" 2>/dev/null && mv "${EV_WINDOW_FILE}.t" "$EV_WINDOW_FILE"
}

_ev_block_check() {
    local k lines bad
    k="$EV_BLOCK_403_THRESHOLD"
    lines=$(tail -n "$k" "$EV_WINDOW_FILE" 2>/dev/null | wc -l)
    bad=$(tail -n "$k" "$EV_WINDOW_FILE" 2>/dev/null | grep -vcE '^(403|429)$')
    [ "$lines" -eq "$k" ] && [ "$bad" -eq 0 ] && return 0
    k="$EV_BLOCK_TIMEOUT_THRESHOLD"
    lines=$(tail -n "$k" "$EV_WINDOW_FILE" 2>/dev/null | wc -l)
    bad=$(tail -n "$k" "$EV_WINDOW_FILE" 2>/dev/null | grep -vc '^000$')
    [ "$lines" -eq "$k" ] && [ "$bad" -eq 0 ] && return 0
    k="$EV_BLOCK_MIXED_THRESHOLD"
    lines=$(tail -n "$k" "$EV_WINDOW_FILE" 2>/dev/null | wc -l)
    bad=$(tail -n "$k" "$EV_WINDOW_FILE" 2>/dev/null | grep -vcE '^(000|403|429)$')
    [ "$lines" -eq "$k" ] && [ "$bad" -eq 0 ] && return 0
    return 1
}

ev_record() {
    [ "$EV_ENABLED" = 1 ] || return 0
    local code="${1:-000}"
    echo "$code" >> "$EV_WINDOW_FILE"
    _ev_trim_window
    EV_REQ_COUNT=$((EV_REQ_COUNT + 1))
    EV_REQ_IDENT=$((EV_REQ_IDENT + 1))
    _ev_state_set req_count "$EV_REQ_COUNT"
    _ev_state_set "req_ident_$EV_IDENT" "$EV_REQ_IDENT"
    # budget
    if [ "$EV_BUDGET_LOGGED" = 0 ] && [ "$EV_REQ_COUNT" -ge "$EV_BUDGET" ]; then
        EV_ABORT=1; EV_ABORT_REASON="budget"; EV_BUDGET_LOGGED=1
        echo "EVASION_BUDGET_EXHAUSTED: ${EV_TARGET} ${EV_REQ_COUNT}/${EV_BUDGET} requests (compartilhado entre todas as ferramentas)"
        return 0
    fi
    # bloqueio
    if _ev_block_check; then
        ev_on_block
        return 0
    fi
    # rotação proativa (após aprender o threshold da defesa)
    local learned
    learned=$(_ev_state_get block_threshold_learned)
    if [ -n "$learned" ] && [ "$learned" -ge 10 ]; then
        local cap=$(( learned * EV_PROACTIVE_FACTOR / 100 ))
        if [ "$EV_REQ_IDENT" -ge "$cap" ] && [ "${#EV_POOL_IPS[@]}" -gt 0 ]; then
            local now bt cd
            now=$(date +%s)
            bt=$(_ev_state_get "burned_$(( (EV_IDENT + 1) % (${#EV_POOL_IPS[@]} + 1) ))")
            [ -z "$bt" ] && { ev_rotate; : > "$EV_WINDOW_FILE"; }
        fi
    fi
}

# ---------- Rotação de identidade ----------------------------------------------
ev_rotate() {
    [ "$EV_ENABLED" = 1 ] || return 0
    local now start cand n bt cd delta probe_code
    now=$(date +%s); n=${#EV_POOL_IPS[@]}
    local i
    for ((i = 1; i <= n + 1; i++)); do
        cand=$(( (EV_IDENT + i) % (n + 1) ))
        # cooldown da identidade queimada
        bt=$(_ev_state_get "burned_$cand")
        if [ -n "$bt" ]; then
            cd=$EV_COOLDOWN_BASE
            if [ "$EV_COOLDOWN_LEARNED" -gt 0 ]; then
                # margem proporcional: learned/4 + 15s (nunca menos que isso)
                cd=$(( EV_COOLDOWN_LEARNED + EV_COOLDOWN_LEARNED / 4 + 15 ))
            fi
            [ "$cd" -gt "$EV_COOLDOWN_MAX" ] && cd=$EV_COOLDOWN_MAX
            [ $((now - bt)) -lt "$cd" ] && continue
        fi
        # adota a identidade e faz probe (curl --interface — proxy SOCKS só
        # é exigido pelo ffuf, checado em ev_ffuf_args via EV_SOCKS_OK)
        EV_IDENT_PREV=$EV_IDENT
        EV_IDENT=$cand
        _ev_ident_curl_args
        probe_code=$(curl -sk --max-time "$EV_PROBE_TIMEOUT" -o /dev/null -w '%{http_code}' ${EV__IDA[@]+"${EV__IDA[@]}"} "$EV_PROBE_URL" 2>/dev/null)
        EV_REQ_COUNT=$((EV_REQ_COUNT + 1)); _ev_state_set req_count "$EV_REQ_COUNT"
        if [ -n "$probe_code" ] && [ "$probe_code" != "000" ]; then
            if [ -n "$bt" ]; then
                delta=$((now - bt))
                # APRENDIZADO de cooldown: a defesa desbloqueou em algum ponto
                # entre burn e agora — delta é o limite superior observado.
                # Floor de 5s para filtrar ruído (config: cooldown_learn_min)
                local _lmin="${EV_COOLDOWN_LEARN_MIN:-5}"
                if [ "$delta" -ge "$_lmin" ] && [ "$delta" -le "$EV_COOLDOWN_MAX" ]; then
                    EV_COOLDOWN_LEARNED=$delta
                    _ev_state_set cooldown_learned "$delta"
                fi
            fi
            _ev_state_set ident "$EV_IDENT"
            local _lbl="direct"
            [ "$EV_IDENT" -gt 0 ] && _lbl="${EV_POOL_IPS[$((EV_IDENT - 1))]}"
            echo "IP_ROTATED: ${EV_TARGET}:${EV_PORT} identity ${EV_IDENT_PREV} -> ${EV_IDENT} (${_lbl}) probe=HTTP ${probe_code}"
            return 0
        fi
        # morreu na hora → queima e tenta a próxima
        _ev_state_set "burned_$cand" "$now"
    done
    EV_ABORT=1; EV_ABORT_REASON="pool_exhausted"
    echo "EVASION_POOL_EXHAUSTED: ${EV_TARGET}:${EV_PORT} todas as identidades queimadas (cooldown base ${EV_COOLDOWN_BASE}s, aprendido ${EV_COOLDOWN_LEARNED}s) - abortando graciosamente"
    return 1
}

ev_on_block() {
    local win_tail learned
    win_tail=$(tail -n 8 "$EV_WINDOW_FILE" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    _ev_state_set "burned_$EV_IDENT" "$(date +%s)"
    learned=$(_ev_state_get block_threshold_learned)
    [ -z "$learned" ] && learned=0
    if [ "$EV_REQ_IDENT" -gt "$learned" ]; then
        _ev_state_set block_threshold_learned "$EV_REQ_IDENT"
    fi
    EV_BLOCKED_EVENTS=$((EV_BLOCKED_EVENTS + 1))
    _ev_state_set blocked_events "$EV_BLOCKED_EVENTS"
    echo "TARGET_BLOCKED: ${EV_TARGET}:${EV_PORT} identity=$EV_IDENT recent=[${win_tail}] requests_this_identity=$EV_REQ_IDENT"
    # Fingerprint da defesa (uma vez por alvo): como ela bloqueia?
    if [ "$EV_DEFENSE_FINGERPRINT" = 1 ] && [ -z "$(_ev_state_get fp_done)" ] && [ -f "$EV_LIB_DIR/defense_fingerprint.sh" ]; then
        local _fp_ip=""
        [ "$EV_IDENT" -gt 0 ] && _fp_ip="${EV_POOL_IPS[$((EV_IDENT - 1))]}"
        bash "$EV_LIB_DIR/defense_fingerprint.sh" "$EV_TARGET" "$EV_PORT" "$EV_SCHEME" "$EV_STATE_DIR" "$_fp_ip" 2>/dev/null
        _ev_state_set fp_done 1
    fi
    ev_rotate
    : > "$EV_WINDOW_FILE"
    EV_REQ_IDENT=0
}

# ---------- Probe público (1 request leve num path conhecido) ------------------
ev_probe() {
    local url="${1:-$EV_PROBE_URL}" code
    code=$(curl -sk --max-time "$EV_PROBE_TIMEOUT" -o /dev/null -w '%{http_code}' ${EV__IDA[@]+"${EV__IDA[@]}"} "$url" 2>/dev/null)
    if [ "$EV_ENABLED" = 1 ]; then
        EV_REQ_COUNT=$((EV_REQ_COUNT + 1)); _ev_state_set req_count "$EV_REQ_COUNT"
    fi
    [ -n "$code" ] && [ "$code" != "000" ]
}

# ---------- Helpers de request (substituem os curls dos fuzzers) --------------
# Percent-encode mínimo para QUERY de URL (payload de fuzzing). O curl REJEITA
# (ou o servidor derruba) URLs com espaço/aspas cruas → falsos 000 → falso
# bloqueio. Não encoda '/' (path) — só os caracteres que quebram a URL.
ev_urlencode() {
    printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e "s/'/%27/g" \
        -e 's/"/%22/g' -e 's/</%3C/g' -e 's/>/%3E/g' -e 's/#/%23/g' \
        -e 's/&/%26/g' -e 's/\\/%5C/g' -e 's/?/%3F/g' -e 's/;/%3B/g'
}

# ev_body_and_code <curl-args...>  → $EV_BODY, $EV_CODE
#   disabled: 2 requests (padrão original: body primeiro, depois código)
#   enabled : 1 request (bug de request duplo corrigido) + identidade + jitter
ev_body_and_code() {
    if [ "$EV_ENABLED" != 1 ]; then
        EV_BODY=$(curl "$@" 2>/dev/null)
        EV_CODE=$(curl "$@" -o /dev/null -w "%{http_code}" 2>/dev/null)
        return 0
    fi
    ev_jitter
    local _bf; _bf="$(mktemp 2>/dev/null)"; : > "$_bf"
    EV_CODE=$(curl "$@" ${EV__IDA[@]+"${EV__IDA[@]}"} -o "$_bf" -w "%{http_code}" 2>/dev/null)
    EV_BODY=$(cat "$_bf" 2>/dev/null; rm -f "$_bf")
    ev_record "${EV_CODE:-000}"
}

# ev_code_size <curl-args...>  → $EV_CODE, $EV_SIZE
#   disabled: 2 requests (padrão original: código primeiro, depois tamanho)
#   enabled : 1 request com ambos
ev_code_size() {
    if [ "$EV_ENABLED" != 1 ]; then
        EV_CODE=$(curl "$@" -o /dev/null -w "%{http_code}" 2>/dev/null)
        EV_SIZE=$(curl "$@" -o /dev/null -w "%{size_download}" 2>/dev/null)
        return 0
    fi
    ev_jitter
    local _out
    _out=$(curl "$@" ${EV__IDA[@]+"${EV__IDA[@]}"} -o /dev/null -w "%{http_code} %{size_download}" 2>/dev/null)
    EV_CODE="${_out%% *}"; EV_SIZE="${_out##* }"
    ev_record "${EV_CODE:-000}"
}

# ev_code <curl-args...>  → $EV_CODE  (1 request nos dois modos)
ev_code() {
    if [ "$EV_ENABLED" != 1 ]; then
        EV_CODE=$(curl "$@" -o /dev/null -w "%{http_code}" 2>/dev/null)
        return 0
    fi
    ev_jitter
    EV_CODE=$(curl "$@" ${EV__IDA[@]+"${EV__IDA[@]}"} -o /dev/null -w "%{http_code}" 2>/dev/null)
    ev_record "${EV_CODE:-000}"
}

# ev_body <curl-args...>  → $EV_BODY  (1 request nos dois modos; enabled também
# captura $EV_CODE de graça no mesmo request e registra no budget/janela)
ev_body() {
    if [ "$EV_ENABLED" != 1 ]; then
        EV_BODY=$(curl "$@" 2>/dev/null)
        return 0
    fi
    ev_jitter
    local _bf; _bf="$(mktemp 2>/dev/null)"; : > "$_bf"
    EV_CODE=$(curl "$@" ${EV__IDA[@]+"${EV__IDA[@]}"} -o "$_bf" -w "%{http_code}" 2>/dev/null)
    EV_BODY=$(cat "$_bf" 2>/dev/null; rm -f "$_bf")
    ev_record "${EV_CODE:-000}"
}

# ev_code_bodyfile <bodyfile> <curl-args...>  → body gravado no arquivo, $EV_CODE
#   (1 request nos dois modos — padrão original `curl -o FILE -w code`)
ev_code_bodyfile() {
    local _bf="$1"; shift
    if [ "$EV_ENABLED" != 1 ]; then
        EV_CODE=$(curl "$@" -o "$_bf" -w "%{http_code}" 2>/dev/null)
        return 0
    fi
    ev_jitter
    EV_CODE=$(curl "$@" ${EV__IDA[@]+"${EV__IDA[@]}"} -o "$_bf" -w "%{http_code}" 2>/dev/null)
    ev_record "${EV_CODE:-000}"
}

# ---------- Flags extras para fuzzers de wordlist ------------------------------
# SOCKS só é usado se o pool de proxies (evasion_pool.sh + 3proxy) está de pé;
# curl roda com --interface direto (não precisa de proxy para nada)
EV_SOCKS_OK=0
ev_ffuf_args() {
    [ "$EV_ENABLED" = 1 ] || { echo ""; return 0; }
    local a="-t $EV_FFUF_THREADS -p $EV_JITTER_MIN-$EV_JITTER_MAX -rate $EV_RATE_RPS -timeout 8"
    if [ "$EV_SOCKS_OK" = 1 ] && [ "$EV_IDENT" -gt 0 ]; then
        a="$a -x socks5://127.0.0.1:$((EV_PROXY_BASE_PORT + EV_IDENT - 1))"
    fi
    echo "$a"
}
ev_gobuster_args() {
    [ "$EV_ENABLED" = 1 ] || { echo ""; return 0; }
    local a="--delay 1200ms -t $EV_FFUF_THREADS --timeout 10s"
    if [ "$EV_IDENT" -gt 0 ]; then
        a="$a --proxy socks5://127.0.0.1:$((EV_PROXY_BASE_PORT + EV_IDENT - 1))"
    fi
    echo "$a"
}

# ---------- Aborto gracioso (budget / tempo / pool) ----------------------------
ev_should_abort() {
    [ "$EV_ENABLED" = 1 ] || return 1
    if [ "$EV_ABORT" = 1 ]; then return 0; fi
    if [ -n "$EV_PORT_TIME_BUDGET" ] && [ "$EV_PORT_TIME_BUDGET" -gt 0 ] && [ "$SECONDS" -ge "$EV_PORT_TIME_BUDGET" ]; then
        EV_ABORT=1; EV_ABORT_REASON="time"
        echo "EVASION_TIME_BUDGET: ${EV_TARGET}:${EV_PORT} ${SECONDS}s >= ${EV_PORT_TIME_BUDGET}s orcamento por porta"
        return 0
    fi
    return 1
}

# ---------- Porta emulada (fita) -----------------------------------------------
ev_skip_port() {
    [ "$EV_ENABLED" = 1 ] || return 1
    [ "$EV_EMULATED" = 1 ]
}

ev_set_probe_url() {
    EV_PROBE_URL="$1"
}

# ---------- Init ---------------------------------------------------------------
ev_init() {
    EV_TARGET="${1:?ev_init: target obrigatorio}"
    EV_PORT="${2:-80}"
    EV_SCHEME="${3:-http}"

    # Config: env > config.ini > default
    EV_ENABLED="${EV_ENABLED:-$(_ev_cfg enabled 0)}"
    EV_ENABLED="${EV_ENABLED:-0}"
    [ "$EV_ENABLED" = "1" ] || { EV_ENABLED=0; return 0; }

    EV_IP_POOL="${EV_IP_POOL:-$(_ev_cfg ip_pool "")}"
    EV_PROXY_BASE_PORT="${EV_PROXY_BASE_PORT:-$(_ev_cfg proxy_base_port 10800)}"
    EV_BUDGET="${EV_BUDGET:-$(_ev_cfg request_budget 3000)}"
    EV_BLOCK_403_THRESHOLD="${EV_BLOCK_403_THRESHOLD:-$(_ev_cfg block_403_threshold 6)}"
    EV_BLOCK_TIMEOUT_THRESHOLD="${EV_BLOCK_TIMEOUT_THRESHOLD:-$(_ev_cfg block_timeout_threshold 4)}"
    EV_BLOCK_MIXED_THRESHOLD="${EV_BLOCK_MIXED_THRESHOLD:-$(_ev_cfg block_mixed_threshold 8)}"
    EV_COOLDOWN_BASE="${EV_COOLDOWN_BASE:-$(_ev_cfg cooldown_base 900)}"
    EV_COOLDOWN_MAX="${EV_COOLDOWN_MAX:-$(_ev_cfg cooldown_max 7200)}"
    EV_COOLDOWN_LEARN_MIN="${EV_COOLDOWN_LEARN_MIN:-$(_ev_cfg cooldown_learn_min 5)}"
    EV_JITTER_MIN="${EV_JITTER_MIN:-$(_ev_cfg jitter_min 0.2)}"
    EV_JITTER_MAX="${EV_JITTER_MAX:-$(_ev_cfg jitter_max 1.5)}"
    EV_RATE_RPS="${EV_RATE_RPS:-$(_ev_cfg rate_rps 8)}"
    EV_FFUF_THREADS="${EV_FFUF_THREADS:-$(_ev_cfg ffuf_threads 4)}"
    EV_CHUNK_SIZE="${EV_CHUNK_SIZE:-$(_ev_cfg chunk_size 300)}"
    EV_PORT_TIME_BUDGET="${EV_PORT_TIME_BUDGET:-$(_ev_cfg port_time_budget 240)}"
    EV_PROBE_TIMEOUT="${EV_PROBE_TIMEOUT:-$(_ev_cfg probe_timeout 4)}"
    EV_PROBE_PATH="${EV_PROBE_PATH:-$(_ev_cfg probe_path /)}"
    EV_PROBE_PATH="${EV_PROBE_PATH:-/}"
    EV_EMULATION_CHECK="${EV_EMULATION_CHECK:-$(_ev_cfg emulation_check 1)}"
    EV_DEFENSE_FINGERPRINT="${EV_DEFENSE_FINGERPRINT:-$(_ev_cfg defense_fingerprint 1)}"
    local _pf="$(_ev_cfg proactive_rotate_factor 70)"
    EV_PROACTIVE_FACTOR="${EV_PROACTIVE_FACTOR:-$_pf}"
    EV_OUTPUT_DIR="${EV_OUTPUT_DIR:-/ruadan/output}"

    # Pool de identidades
    mapfile -t EV_POOL_IPS < <(_ev_expand_pool "$EV_IP_POOL") 2>/dev/null || EV_POOL_IPS=()
    [ "${#EV_POOL_IPS[@]}" -eq 0 ] && mapfile -t EV_POOL_IPS < <(echo "") && EV_POOL_IPS=()

    # SOCKS do pool (ffuf/gobuster) — opcional: curl roda com --interface direto
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$EV_PROXY_BASE_PORT" 2>/dev/null; then
        EV_SOCKS_OK=1
    fi

    # Estado por alvo (persiste entre fases e entre containers — output é mount do host)
    local tdir
    tdir=$(printf '%s' "$EV_TARGET" | tr '.' '_')
    EV_STATE_DIR="${EV_OUTPUT_DIR}/${tdir}"
    mkdir -p "$EV_STATE_DIR" 2>/dev/null
    EV_STATE_FILE="${EV_STATE_DIR}/evasion_state.env"
    EV_WINDOW_FILE="${EV_STATE_DIR}/evasion_window.txt"
    touch "$EV_STATE_FILE" "$EV_WINDOW_FILE" 2>/dev/null

    # Carrega estado
    local v
    v=$(_ev_state_get ident);     [ -n "$v" ] && EV_IDENT="$v"
    v=$(_ev_state_get req_count); [ -n "$v" ] && EV_REQ_COUNT="$v"
    v=$(_ev_state_get cooldown_learned); [ -n "$v" ] && EV_COOLDOWN_LEARNED="$v"
    v=$(_ev_state_get blocked_events);   [ -n "$v" ] && EV_BLOCKED_EVENTS="$v"
    v=$(_ev_state_get "req_ident_$EV_IDENT"); [ -n "$v" ] && EV_REQ_IDENT="$v"
    _ev_ident_curl_args
    EV_PROBE_URL="${EV_SCHEME}://${EV_TARGET}:${EV_PORT}${EV_PROBE_PATH}"

    # Detecção de fita (emulação) — lazy, uma vez por porta
    if [ "$EV_EMULATION_CHECK" = 1 ] && [ -z "$(_ev_state_get "emchk_$EV_PORT")" ] && [ -f "$EV_LIB_DIR/emulation_check.sh" ]; then
        bash "$EV_LIB_DIR/emulation_check.sh" "$EV_TARGET" "$EV_PORT" "$EV_SCHEME" "$EV_STATE_DIR" 2>/dev/null
        _ev_state_set "emchk_$EV_PORT" 1
        v=$(_ev_state_get req_count); [ -n "$v" ] && EV_REQ_COUNT="$v"
    fi

    # Porta já marcada como emulada? → fuzzer pula (evita queimar budget em fita)
    local em
    em=$(_ev_state_get emulated_ports)
    if [ -n "$em" ]; then
        case ",$em," in
            *",$EV_PORT,"*)
                EV_EMULATED=1
                echo "EMULATED_SERVICE_SKIP: ${EV_TARGET}:${EV_PORT} porta emulada (fita) - fuzzing pulado para poupar budget"
                ;;
        esac
    fi

    echo "[EVASION] alvo=${EV_TARGET}:${EV_PORT} identidade=${EV_IDENT} pool=${#EV_POOL_IPS[@]}IPs req=${EV_REQ_COUNT}/${EV_BUDGET} cooldown_aprendido=${EV_COOLDOWN_LEARNED}s bloqueios=${EV_BLOCKED_EVENTS}"
}

# ---------- Helpers p/ scripts externos (emulation_check / defense_fingerprint)
# Bump atômico de request count no estado (flock) sem carregar a lib inteira.
ev_state_bump_requests() {
    # $1 = state_dir, $2 = n_requests
    local sd="${1:?}" n="${2:-1}" f="${1}/evasion_state.env" lf="${1}/.state.lock" cur
    (
        flock 9
        cur=$(grep -m1 '^req_count=' "$f" 2>/dev/null | cut -d= -f2-)
        cur="${cur:-0}"
        grep -v '^req_count=' "$f" 2>/dev/null > "$f.tmp"
        echo "req_count=$((cur + n))" >> "$f.tmp"
        mv "$f.tmp" "$f"
    ) 9>"$lf" 2>/dev/null
}
