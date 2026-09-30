#!/bin/bash
# ==============================================================================
# Ruadan — trap_census.sh: census adaptativo de portas-armadilha (anti-emulação)
# ==============================================================================
# Uso: trap_census.sh <target> [state_dir] [ports_csv]
#
# ZERO ASSINATURAS DE DEFESA. Nenhuma string/banner/mapa hardcoded — o sistema
# APRENDE por alvo, com 3 sinais genéricos que qualquer emulador de serviços
# falha (hoje, amanhã ou depois de qualquer patch):
#
#   1. CLUSTERING: ≥2 portas distintas devolvendo resposta BYTE-IDÊNTICA =
#      mesmo backend emulador servindo N portas (serviço real numa porta não
#      coincide byte-a-byte com outra porta). Sinal mais forte.
#   2. INSENSIBILIDADE A REQUEST: mesma porta, 2 paths diferentes → resposta
#      idêntica = canned. App real varia (layout, sessão, rota).
#   3. ORÁCULO DO BLOQUEIO: se o IP é banido no meio do census (connect→
#      timeout), o número de portas ACEITAS tocadas até ali = threshold real
#      da defesa (aprendido e persistido). Portas aceitas = contam; recusadas
#      e reais (não vistas pela defesa) = não contam.
#
# Governor embutido: cap de portas-aceitas-por-IP (config port_touch_cap,
# default conservador; substituído pelo threshold APRENDIDO-2). IP que toma
# ban vira offender (aposentado p/ sempre neste alvo — escalonamento de
# defesas anti-portscan tipicamente não expira ofensas).
#
# Estado por alvo (mesmo formato evasion_lib/nmap_ev, flock):
#   tp_<port>=trap|live|closed        census da porta
#   tp_hash_<port>=<md5>              resposta observada (p/ clustering)
#   trap_clusters=<n> live_ports=<csv> ptouch_<ip>=<csv> offender_<ip>=1
#   porttouch_threshold_learned=<n>  aprendido no oráculo do ban
#
# Findings: TRAP_CLUSTER: <t>:<ports> (n=<n> md5=<h>) | LIVE_PORT: <t>:<port>
#           DEFENSE_PORT_THRESHOLD_LEARNED: <t> <n>
# ==============================================================================
set -u

RUADAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TARGET="${1:?uso: trap_census.sh <target> [state_dir] [ports_csv]}"
STATE_DIR="${2:-}"
PORTS_CSV="${3:-}"

EV_CONFIG="${EV_CONFIG:-/ruadan/config.ini}"
EV_IP_POOL="${EV_IP_POOL:-}"

# ---------- config (genérico; nada de defesa aqui) ------------------------------
_pcfg() {
    awk -v k="$1" '
        BEGIN { in_sec = 0 }
        tolower($0) ~ /^[[:space:]]*\[evasion\][[:space:]]*$/ { in_sec = 1; next }
        in_sec && /^[[:space:]]*\[/ { in_sec = 0 }
        in_sec && index($0, "=") > 0 {
            key = tolower($1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            sub(/^[^=]*=/, "", $0); gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
            if (key == k) { print $0; exit }
        }
    ' "$EV_CONFIG" 2>/dev/null
}
EV_IP_POOL="${EV_IP_POOL:-$(_pcfg ip_pool)}"
EV_PORT_TOUCH_CAP="${EV_PORT_TOUCH_CAP:-$(_pcfg port_touch_cap)}"
EV_PORT_TOUCH_CAP="${EV_PORT_TOUCH_CAP:-8}"

[ -n "$STATE_DIR" ] || STATE_DIR="${RUADAN_OUTPUT_DIR:-/ruadan/output}/$(printf '%s' "$TARGET" | tr '.' '_')"
mkdir -p "$STATE_DIR" 2>/dev/null
STATE="$STATE_DIR/evasion_state.env"
LF="$STATE_DIR/.state.lock"
st_get() { grep -m1 "^$1=" "$STATE" 2>/dev/null | cut -d= -f2-; }
st_set() {
    ( flock 9
      grep -v "^$1=" "$STATE" 2>/dev/null > "$STATE.tmp"; echo "$1=$2" >> "$STATE.tmp"; mv "$STATE.tmp" "$STATE"
    ) 9>"$LF" 2>/dev/null
}
st_list_add() {
    local cur; cur=$(st_get "$1")
    case ",$cur," in *",$2,"*) return 0 ;; esac
    st_set "$1" "${cur:+$cur,}$2"
}

# cap efetivo: se já aprendemos o threshold real da defesa, cap = aprendido-2
_eff_cap() {
    local learned; learned=$(st_get porttouch_threshold_learned)
    if [ -n "$learned" ] && [ "$learned" -ge 4 ] 2>/dev/null; then
        echo $(( learned > 3 ? learned - 2 : learned - 1 ))
    else
        echo "$EV_PORT_TOUCH_CAP"
    fi
}

# ---------- pool -------------------------------------------------------------------
expand_pool() {
    local spec="$1" part ip b1 b2 b3 s e i
    local IFS=','
    for part in $spec; do
        part="${part//[[:space:]]/}"
        [ -z "$part" ] && continue
        if [[ "$part" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)-([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
            b1="${BASH_REMATCH[1]}"; b2="${BASH_REMATCH[2]}"; b3="${BASH_REMATCH[3]}"
            s="${BASH_REMATCH[4]}"; e="${BASH_REMATCH[8]}"
            [ "${BASH_REMATCH[5]}.${BASH_REMATCH[6]}.${BASH_REMATCH[7]}" != "${b1}.${b2}.${b3}" ] && continue
            for ((i = s; i <= e; i++)); do printf '%s.%s.%s.%s\n' "$b1" "$b2" "$b3" "$i"; done
        elif [[ "$part" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)$ ]]; then
            ip="${BASH_REMATCH[1]}"; e="${BASH_REMATCH[2]}"
            IFS='.' read -r b1 b2 b3 s <<< "$ip"
            for ((i = s; i <= e; i++)); do printf '%s.%s.%s.%s\n' "$b1" "$b2" "$b3" "$i"; done
        else
            printf '%s\n' "$part"
        fi
    done
}
[ -n "$EV_IP_POOL" ] || { echo "[census][ERRO] ip_pool vazio"; exit 1; }
mapfile -t POOL < <(expand_pool "$EV_IP_POOL")
[ "${#POOL[@]}" -gt 0 ] || { echo "[census][ERRO] pool vazio"; exit 1; }

# ---------- portas candidatas (escolha do ATACANTE, não da defesa) ------------------
if [ -n "$PORTS_CSV" ]; then
    IFS=',' read -ra CAND_PORTS <<< "$PORTS_CSV"
else
    CAND_PORTS=(443 80 8000 8080 8443 3000 8888 22 3389 5900 5800 10000)
fi

# ---------- governor -----------------------------------------------------------------
_ptouch_n() {  # quantas portas-aceitas o IP já tocou neste alvo
    local v; v=$(st_get "ptouch_$1"); v="${v:-}"
    [ -z "$v" ] && { echo 0; return; }
    awk -F, '{print NF}' <<< "$v"
}
CAND=()
for ip in "${POOL[@]}"; do
    [ -n "$(st_get "offender_$ip")" ] && continue
    CAND+=("$ip")
done
[ "${#CAND[@]}" -gt 0 ] || { echo "[census][ERRO] pool inteiro aposentado/ofensor"; exit 1; }

next_ip() {
    local cap ip
    cap=$(_eff_cap)
    for ip in "${CAND[@]}"; do
        if [ "$(_ptouch_n "$ip")" -lt "$cap" ]; then
            echo "$ip"; return 0
        fi
    done
    return 1
}

_probe() {  # porta modo → echo "result=... hash=..."
    python3 "$RUADAN_DIR/trap_probe.py" "$1" "$TARGET" "$2" "$3" 2>/dev/null
}

# ---------- FASE 1: coleta de observações brutas --------------------------------------
BAN_ORACLE=0
ALIVE_SEEN=0     # host provado vivo NESTE census (≥1 connect)
UNREACH=0        # timeouts consecutivos SEM vida (host down ≠ ban)
for p in "${CAND_PORTS[@]}"; do
    known=$(st_get "tp_$p")
    [ -n "$known" ] && continue
    ip=$(next_ip) || { echo "[census][WARN] sem IPs com folga — census parcial (aguardar cooldown/aprender)"; break; }

    out=$(_probe "$ip" "$p" banner)
    res="${out%% *}"
    case "$res" in
        result=refused)
            st_set "tp_$p" "closed"          # não conta: a defesa não a viu
            ALIVE_SEEN=1                     # RST prova que o host responde
            ;;
        result=timeout)
            if [ "$ALIVE_SEEN" = 1 ]; then
                # ORÁCULO: host provado vivo + drop = BAN. Portas-aceitas tocadas
                # por ESTE IP até aqui = threshold observado da defesa.
                BAN_ORACLE=$((BAN_ORACLE + 1))
                touched=$(_ptouch_n "$ip"); touched=${touched:-0}
                [ "$touched" -ge 2 ] && st_set porttouch_threshold_learned "$touched"
                st_set "offender_$ip" "1"
                st_set "burned_pair_$ip" "$(date +%s)"
                echo "DEFENSE_PORT_THRESHOLD_LEARNED: ${TARGET} ${touched} (ban do oráculo em ${ip} após ${touched} portas-aceitas)"
            else
                # host NÃO provado vivo: timeout = unreachable (host caído OU IP
                # pré-bloqueado) — NÃO queima o IP nem aprende threshold falso
                UNREACH=$((UNREACH + 1))
                if [ "$UNREACH" -ge 3 ]; then
                    echo "HOST_UNREACHABLE: ${TARGET} (sem resposta de ${UNREACH} IPs distintos — host caído ou bloqueio pré-existente de todo o pool)"
                    exit 0
                fi
            fi
            ;;
        result=connect)
            ALIVE_SEEN=1
            hash=$(grep -oE 'hash=[0-9a-f]*' <<< "$out" | cut -d= -f2)
            bytes=$(grep -oE 'bytes=[0-9]+' <<< "$out" | cut -d= -f2)
            # porta http-like (espera request) → resposta vazia no modo banner:
            # pega o hash do CORPO via probe http (mesma porta/IP = 1 unique)
            if [ "$bytes" = "0" ] || [ -z "$hash" ]; then
                out2=$(_probe "$ip" "$p" http)
                if [[ "$out2" == result=connect* ]]; then
                    hash=$(grep -oE 'hash=[0-9a-f]*' <<< "$out2" | head -1 | cut -d= -f2)
                    bytes=$(grep -oE 'bytes=[0-9]+' <<< "$out2" | cut -d= -f2)
                fi
            fi
            st_list_add "ptouch_$ip" "$p"     # porta ACEITA — conta pro threshold
            st_set "tp_hash_$p" "${hash:-none}${bytes:+:$bytes}"
            st_set "tp_$p" "alive"            # classificação vem na FASE 2
            ;;
    esac
done

# ---------- FASE 2: clustering + insensibilidade a request ----------------------------
# cluster: portas alive com hash IDÊNTICO (>=2 portas = mesmo backend emulador)
declare -A BY_HASH=()
alive_ports=""
for p in "${CAND_PORTS[@]}"; do
    [ "$(st_get "tp_$p")" = "alive" ] && alive_ports="${alive_ports}${p},"
done
alive_ports="${alive_ports%,}"
[ -n "$alive_ports" ] || { echo "[census] nenhuma porta viva nova"; exit 0; }

IFS=',' read -ra ALIVE <<< "$alive_ports"
for p in "${ALIVE[@]}"; do
    h=$(st_get "tp_hash_$p")
    BY_HASH["$h"]="${BY_HASH[$h]:-}${BY_HASH[$h]:+,}$p"
done

for h in "${!BY_HASH[@]}"; do
    IFS=',' read -ra members <<< "${BY_HASH[$h]}"
    if [ "${#members[@]}" -ge 2 ]; then
        # SINAL 1 (forte): mesma resposta byte-idêntica em portas distintas
        for p in "${members[@]}"; do st_set "tp_$p" "trap"; done
        echo "TRAP_CLUSTER: ${TARGET}:${BY_HASH[$h]} (n=${#members[@]} resposta_idêntica)"
    fi
done

# singleton: teste de insensibilidade a request (2º toque na MESMA porta = 1 unique)
for p in "${ALIVE[@]}"; do
    [ "$(st_get "tp_$p")" != "alive" ] && continue
    ip=$(next_ip) || break
    # swallow-candidata = porta http-like (banner vazio na FASE 1): serviço
    # HTTP de verdade SEMPRE responde a GET; aceitar e engolir = tarpit/null
    bh=$(st_get "tp_hash_$p")
    swallow=0
    case "$bh" in none*|"") swallow=1 ;; esac
    out=$(_probe "$ip" "$p" http)
    res="${out%% *}"
    if [ "$res" = "result=timeout" ]; then
        touched=$(_ptouch_n "$ip"); touched=${touched:-0}
        [ "$touched" -ge 2 ] && st_set porttouch_threshold_learned "$touched"
        st_set "offender_$ip" "1"
        st_set "burned_pair_$ip" "$(date +%s)"
        echo "DEFENSE_PORT_THRESHOLD_LEARNED: ${TARGET} ${touched} (oráculo em http-probe de ${ip})"
        continue
    fi
    [ "$res" != "result=connect" ] && continue
    h1=$(grep -oE 'hash=[0-9a-f]*' <<< "$out" | head -1 | cut -d= -f2)
    h2=$(grep -oE 'hash2=[0-9a-f]*' <<< "$out" | cut -d= -f2)
    st_list_add "ptouch_$ip" "$p"
    if [ "$swallow" = 1 ] && { [ -z "$h1" ] || [ "$h1" = "none" ]; }; then
        # http-like que aceita TCP e NUNCA responde HTTP: pode ser tarpit
        # OU serviço real não-HTTP sem banner (RDP e afins). Singleton fraco
        # → SUSPECT (não exclui, não pula; a camada HTTP decide depois)
        st_set "tp_$p" "suspect"
        echo "PORT_SUSPECT: ${TARGET}:${p} (aceita conexão e engole requests HTTP — tarpit ou serviço não-HTTP)"
    elif [ -n "$h1" ] && [ "$h1" = "$h2" ] && [ "$h1" != "none" ]; then
        # paths distintos → resposta idêntica: canned. MAS singleton fraco —
        # SPA catch-all e páginas de erro de proxy também são path-independentes
        # (FALSO-POSITIVO comprovado em campo contra o 443 REAL do alvo).
        # → SUSPECT (cluster entre portas é o único sinal forte de exclusão)
        st_set "tp_$p" "suspect"
        echo "PORT_SUSPECT: ${TARGET}:${p} (paths distintos, resposta idêntica — canned ou catch-all de app real)"
    else
        st_set "tp_$p" "live"
        st_list_add live_ports "$p"
        echo "LIVE_PORT: ${TARGET}:${p}"
    fi
done

n_trap=$(grep -cE '^tp_[0-9]+=trap$' "$STATE" 2>/dev/null); n_trap="${n_trap:-0}"
n_suspect=$(grep -cE '^tp_[0-9]+=suspect$' "$STATE" 2>/dev/null); n_suspect="${n_suspect:-0}"
n_live=$(grep -cE '^tp_[0-9]+=live$' "$STATE" 2>/dev/null); n_live="${n_live:-0}"
n_closed=$(grep -cE '^tp_[0-9]+=closed$' "$STATE" 2>/dev/null); n_closed="${n_closed:-0}"
learned=$(st_get porttouch_threshold_learned)
echo "[census] ${TARGET}: traps=${n_trap} suspeitas=${n_suspect} vivas=${n_live} fechadas=${n_closed} threshold_aprendido=${learned:-?} (cap atual: $(_eff_cap)) oraculos=${BAN_ORACLE}"
exit 0
