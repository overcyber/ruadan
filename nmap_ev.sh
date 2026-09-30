#!/bin/bash
# ==============================================================================
# Ruadan — nmap_ev.sh: recon resistente a bloqueio por (origem→destino)
# ==============================================================================
# Drop-in: substitui `nmap` nas fases de scan do config.ini.
#   bash /ruadan/nmap_ev.sh <args do nmap originais>
#
# POR QUÊ: a defesa do lab bloqueia por PAR (IP de origem → destino) com
# silent drop PERSISTENTE (≥12h observado). O run com evasão atacou o
# juice.octopux CEGO: os nmaps saíram do IP fixo (.210), viram 1000/1000
# portas filtered, e o Ruadan não disparou NENHUMA fase HTTP — o alvo
# "sumiu" da campanha apesar de o JuiceShop estar vivo (200/9903B de um
# IP limpo do pool).
#
# COMO: roda o nmap original; se o resultado tiver ZERO portas abertas:
#   FASE 1 — probe barato (/dev/tcp, 1.5s) nas portas comuns de lab,
#            DISTRIBUÍDO entre até 3 IPs limpos do pool (≤15 sondas/IP,
#            bem abaixo do threshold de bloqueio da defesa ~58-72)
#   FASE 2 — se achou portas: nmap -sV DIRIGIDO (só nas portas achadas)
#            com -S <ip limpo> -e <iface> → repara os MESMOS arquivos
#            -oN/-oX e o stdout (o Ruadan segue o fluxo normal)
#   Emite finding: NMAP_IDENTITY_RESCUED: <target> from <ip> (<n> portas)
# UDP scans (-sU) e modo evasão desligado: pass-through puro.
# ==============================================================================
set -u

EV_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
NMAP_BIN="${NMAP_BIN:-nmap}"

# ---------- Parse dos args: target, -oN, -oX, flags ---------------------------------
TARGET=""
ON_FILE=""; OX_FILE=""
has_su=0
args_rest=()
# opções que consomem o próximo argumento
declare -A OPT_TAKES=( [-oN]=1 [-oX]=1 [-oS]=1 [-oA]=1 [-oG]=1 [-p]=1 [--script]=1
    [--script-args]=1 [--host-timeout]=1 [--script-timeout]=1 [-D]=1 [-iL]=1 [--excludefile]=1
    [--exclude-ports]=1 [-S]=1 [-e]=1 [--max-rate]=1 [--min-rate]=1 [--max-retries]=1
    [--scan-delay]=1 [--max-scan-delay]=1 )
i=0
prev=""
ORIG_ARGS=()
for a in "$@"; do
    if [ -n "$prev" ]; then
        # valor da opção anterior
        case "$prev" in
            -oN) ON_FILE="$a" ;;
            -oX) OX_FILE="$a" ;;
        esac
        # outputs e portas não vão no resgate dirigido (a FASE 2 impõe os seus)
        case "$prev" in
            -oN|-oX|-oS|-oA|-oG|-p) prev=""; continue ;;
        esac
        ORIG_ARGS+=("$a")
        prev=""; continue
    fi
    case "$a" in
        -sU) has_su=1; ORIG_ARGS+=("$a") ;;
        -oN|-oX|-oS|-oA|-oG|-p) prev="$a" ;;
        -F)  : ;;   # fast-scan: irrelevante no resgate dirigido por -p
        -*)  ORIG_ARGS+=("$a")
             if [ -n "${OPT_TAKES[$a]:-}" ]; then prev="$a"; fi ;;
        *)   TARGET="$a" ;;   # posicional — o último vira o target (não vai em ORIG_ARGS)
    esac
done
# TARGET foi sobrescrito a cada posicional: guardamos o último ✓ (nmap aceita
# múltiplos, mas os comandos do Ruadan passam 1; dnssrv/proxy placeholders são
# removidos pelo Ruadan2 antes da execução)

# ---------- Pass-through: UDP ou evasão desligada -----------------------------------
_ev_enabled() {
    local v
    v=$(awk '
        BEGIN { in_sec = 0 }
        tolower($0) ~ /^[[:space:]]*\[evasion\][[:space:]]*$/ { in_sec = 1; next }
        in_sec && /^[[:space:]]*\[/ { in_sec = 0 }
        in_sec && index($0, "=") > 0 {
            key = tolower($1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            sub(/^[^=]*=/, "", $0); gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
            if (key == "enabled") { print $0; exit }
        }
    ' "${EV_CONFIG:-/ruadan/config.ini}" 2>/dev/null)
    [ "${v:-0}" = "1" ]
}

count_open() {
    if [ -n "$ON_FILE" ] && [ -f "$ON_FILE" ]; then
        # 'open' LIMPO (open|filtered de fonte banida é lixo — defesa derruba tudo)
        grep -cE '[0-9]+/(tcp|udp)[[:space:]]+open([^|]|$)' "$ON_FILE" 2>/dev/null
        return
    fi
    echo 0
}

if [ "$has_su" = 1 ] && ! _ev_enabled; then
    exec "$NMAP_BIN" "$@"
fi

# ---------- 1. nmap original --------------------------------------------------------
"$NMAP_BIN" "$@"
rc=$?

# achou portas? nada a resgatar
_open=$(count_open)
if [ "$_open" -gt 0 ]; then
    exit $rc
fi

# host morto de verdade? (down) — nmap imprime "host unresponsive"/parecido
if [ -n "$ON_FILE" ] && [ -f "$ON_FILE" ] && grep -qiE "host (seems|is) (down|unresponsive)" "$ON_FILE" 2>/dev/null; then
    exit $rc
fi

# ---------- 2. Resgate com identidade limpa do pool --------------------------------
[ -n "$TARGET" ] || exit $rc

_pool_cfg() {
    awk -v k="$1" '
        BEGIN { in_sec = 0 }
        tolower($0) ~ /^[[:space:]]*\[evasion\][[:space:]]*$/ { in_sec = 1; next }
        in_sec && /^[[:space:]]*\[/ { in_sec = 0 }
        in_sec && index($0, "=") > 0 {
            key = tolower($1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            sub(/^[^=]*=/, "", $0); gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
            if (key == k) { print $0; exit }
        }
    ' "${EV_CONFIG:-/ruadan/config.ini}" 2>/dev/null
}

IP_POOL="${EV_IP_POOL:-$(_pool_cfg ip_pool)}"
[ -n "$IP_POOL" ] || exit $rc
IFACE="${EV_IFACE:-}"
if [ -z "$IFACE" ]; then
    # sem iproute2 no container: parse /proc/net/route (default via coluna 1)
    IFACE=$(awk '$2=="00000000" {getline; } END{}' /dev/null 2>/dev/null; \
        awk 'BEGIN{r["00000000"]} $2 in r {print $1; exit}' /proc/net/route 2>/dev/null)
fi
[ -n "$IFACE" ] || exit $rc

# estado por alvo (mesmo formato da evasion_lib)
OUT_BASE="${RUADAN_OUTPUT_DIR:-/ruadan/output}"
TDIR="${OUT_BASE}/$(printf '%s' "$TARGET" | tr '.' '_')"
mkdir -p "$TDIR" 2>/dev/null
STATE="$TDIR/evasion_state.env"
LF="$TDIR/.state.lock"
st_get() { grep -m1 "^$1=" "$STATE" 2>/dev/null | cut -d= -f2-; }
st_set() {
    ( flock 9
      grep -v "^$1=" "$STATE" 2>/dev/null > "$STATE.tmp"; echo "$1=$2" >> "$STATE.tmp"; mv "$STATE.tmp" "$STATE"
    ) 9>"$LF" 2>/dev/null
}
req_bump() {
    ( flock 9
      cur=$(grep -m1 '^req_count=' "$STATE" 2>/dev/null | cut -d= -f2-); cur="${cur:-0}"
      grep -v '^req_count=' "$STATE" 2>/dev/null > "$STATE.tmp"; echo "req_count=$((cur + ${1:-1}))" >> "$STATE.tmp"; mv "$STATE.tmp" "$STATE"
    ) 9>"$LF" 2>/dev/null
}

# expande pool (último octeto ou IP-completo)
expand_pool() {
    local spec="$1" part ip b1 b2 b3 s e i
    local IFS=','
    for part in $spec; do
        part="${part//[[:space:]]/}"
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
mapfile -t POOL < <(expand_pool "$IP_POOL")
[ "${#POOL[@]}" -gt 0 ] || exit $rc

# ── CACHE de resgate (F5): cada fase nmap do Ruadan repete o MESMO comando
#    contra o MESMO alvo (83× no run 3) — cache por comando; hit = 0 requests
CACHE_KEY=$(printf '%s|%s' "$TARGET" "$*" | md5sum | cut -d' ' -f1)
CACHE_DIR="$TDIR/nmap_ev_cache"
if [ -f "$CACHE_DIR/$CACHE_KEY.nmap" ]; then
    [ -n "$ON_FILE" ] && cp "$CACHE_DIR/$CACHE_KEY.nmap" "$ON_FILE"
    if [ -n "$OX_FILE" ] && [ -f "$CACHE_DIR/$CACHE_KEY.xml" ]; then cp "$CACHE_DIR/$CACHE_KEY.xml" "$OX_FILE"; fi
    cat "$CACHE_DIR/$CACHE_KEY.nmap"
    echo ""
    echo "NMAP_IDENTITY_RESCUED: ${TARGET} (resgate em CACHE — comando repetido, 0 requests gastos)"
    exit 0
fi

# ── RESGATE UDP (F2): -sU cego do IP fixo → re-executa o comando ORIGINAL com
#    -S do pool (defesas anti-portscan contam TCP; UDP do pool é seguro)
if [ "$has_su" = 1 ]; then
    URESCUE_IP=""
    for ip in "${POOL[@]}"; do
        [ -n "$(st_get "offender_$ip")" ] && continue
        URESCUE_IP="$ip"; break
    done
    [ -n "$URESCUE_IP" ] || exit $rc
    UTMP="$(mktemp -d)"
    "$NMAP_BIN" "$@" -S "$URESCUE_IP" -e "$IFACE" \
        -oN "$UTMP/r.nmap" -oX "$UTMP/r.xml" >/dev/null 2>&1
    u_open=0
    [ -s "$UTMP/r.nmap" ] && u_open=$(grep -cE '[0-9]+/(tcp|udp)[[:space:]]+open([^|]|$)' "$UTMP/r.nmap")
    if [ "$u_open" -gt 0 ]; then
        [ -n "$ON_FILE" ] && cp "$UTMP/r.nmap" "$ON_FILE"
        [ -n "$OX_FILE" ] && cp "$UTMP/r.xml" "$OX_FILE"
        cat "$UTMP/r.nmap"
        echo ""
        echo "NMAP_IDENTITY_RESCUED: ${TARGET} (${u_open} portas UDP resgatadas de ${URESCUE_IP}; original saiu cego)"
        mkdir -p "$CACHE_DIR"
        cp "$UTMP/r.nmap" "$CACHE_DIR/$CACHE_KEY.nmap" 2>/dev/null
        cp "$UTMP/r.xml" "$CACHE_DIR/$CACHE_KEY.xml" 2>/dev/null
    fi
    rm -rf "$UTMP"
    exit 0
fi

# portas comuns de lab/web (probe barato, sem nmap)
COMMON_PORTS=(21 22 23 25 53 80 110 111 123 135 137 139 143 389 443 445 465 587 636 993 995 1433 1900 2049 3000 3128 3142 3306 3389 4443 5432 5555 5800 5900 5985 6379 7070 8000 8008 8080 8081 8443 8888 9000 902 9090 9091 9200 10000 11211 27017 51413)

# probe com SOURCE-BIND (bash /dev/tcp NÃO amarra origem)
# uso: probe_conn <src_ip> <porta>  (destino = $TARGET global)
# saída: 0 = conectou (porta aberta) | 1 = RECUSADO (porta fechada, IP vivo)
#        2 = TIMEOUT (IP bloqueado/tarifado pela defesa)
probe_conn() {
    python3 - "$1" "$TARGET" "$2" <<'PYEOF' 2>/dev/null
import socket, sys
src, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    s = socket.create_connection((dst, port), timeout=1.5, source_address=(src, 0))
    s.close()
    sys.exit(0)
except ConnectionRefusedError:
    sys.exit(1)
except Exception:
    sys.exit(2)
PYEOF
}

# ── SONDAGEM FRUGAL: rumo a hosts endurecidos (observado no .160) a
#    defesa aceita apenas ~12-15 conexões TCP por IP de origem antes de
#    dropar. Uma varredura de 52 portas queimou 3 IPs limpos mid-sweep.
#    Estratégia: lista ENXUTA de portas-chave (12), sondadas de IPs NOVOS
#    (um por vez; burn mid-sweep → cai pro próximo).
CAND=()
for ip in "${POOL[@]}"; do
    [ -n "$(st_get "offender_$ip")" ] && continue
    [ -n "$(st_get "burned_pair_$ip")" ] && continue
    CAND+=("$ip")
done
[ "${#CAND[@]}" -gt 0 ] || exit $rc   # pool inteiro queimado rumo a este alvo

# ---------- Census adaptativo (FASE 1) -------------------------------------------
# trap_census.sh: clustering de respostas idênticas + insensibilidade a request
# + ORÁCULO DO BLOQUEIO (threshold real aprendido). ZERO assinaturas de defesa:
# qualquer mudança na defesa muda o que o sistema APRENDE, não o que ele espera.
# portas vivas/trap = portas ACEITAS (o -sV identifica; fuzzers pulam traps).
_eff_cap() {
    local learned; learned=$(st_get porttouch_threshold_learned)
    if [ -n "$learned" ] && [ "$learned" -ge 4 ] 2>/dev/null; then
        echo $(( learned > 3 ? learned - 2 : learned - 1 ))
    else
        echo "${EV_PORT_TOUCH_CAP:-8}"
    fi
}
_ptouch_n() {
    local v; v=$(st_get "ptouch_$1"); v="${v:-}"
    [ -z "$v" ] && { echo 0; return; }
    awk -F, '{print NF}' <<< "$v"
}
_ptouch_add() {
    local cur; cur=$(st_get "ptouch_$1"); cur="${cur:-}"
    case ",$cur," in *",$2,"*) return 0 ;; esac
    st_set "ptouch_$1" "${cur:+$cur,}$2"
}

EV_LIB_DIR_NMAP="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
EV_IP_POOL="$IP_POOL" EV_CONFIG="${EV_CONFIG:-/ruadan/config.ini}" \
EV_PORT_TOUCH_CAP="${EV_PORT_TOUCH_CAP:-}" \
    bash "${EV_LIB_DIR_NMAP}/trap_census.sh" "$TARGET" "$TDIR" 2>&1 | sed 's/^/[nmap_ev|census] /'

FOUND_PORTS=""
while IFS='=' read -r k v; do
    case "$k" in
        tp_*) case "$v" in live|suspect) FOUND_PORTS="${FOUND_PORTS}${k#tp_}," ;; esac ;;
            # F1: trap (cluster confirmado) NÃO entra no resgate — o Ruadan
            # não cria fases-junk contra tarpits; live+suspect = superfície real
    esac
done < "$STATE" 2>/dev/null
FOUND_PORTS=$(printf '%s\n' ${FOUND_PORTS} 2>/dev/null | tr ',' '\n' | sort -un | paste -sd, -)
FOUND_PORTS="${FOUND_PORTS%,}"
[ -n "$FOUND_PORTS" ] || exit $rc   # census não achou portas aceitas
st_set "rescue_ports" "$FOUND_PORTS"

# IPs com folga de ptouch para o -sV (chunks de ~3 toques/IP)
LIVE_IPS=()
CAP=$(_eff_cap)
for ip in "${POOL[@]}"; do
    [ -n "$(st_get "offender_$ip")" ] && continue
    LIVE_IPS+=("$ip")
done
[ "${#LIVE_IPS[@]}" -eq 0 ] && LIVE_IPS=("${POOL[$(( ${#POOL[@]} - 1 ))]}")
# ── FASE 2: nmap -sV em LOTES de 3 portas por IP vivo (o limite de conexões
#    por IP rumo a hosts endurecidos ~12-15 torna impossível um -sV de
#    10+ portas de um IP só — queimaria mid-scan)
TMPD="$(mktemp -d)"
MERGED_N="$TMPD/rescue.nmap"; : > "$MERGED_N"
BEST_N=""; BEST_X=""; n_ok=0; li=0
IFS=',' read -ra FP <<< "$FOUND_PORTS"
CHUNK=3
pick_ip() {  # IP com folga de ptouch para o chunk (governor)
    local ip
    for ip in "${LIVE_IPS[@]}"; do
        if [ $(( $(_ptouch_n "$ip") + ${#chunk[@]} )) -le "$CAP" ]; then
            echo "$ip"; return 0
        fi
    done
    echo "${LIVE_IPS[0]}"
}
for ((s = 0; s < ${#FP[@]}; s += CHUNK)); do
    chunk=("${FP[@]:s:CHUNK}")
    [ "${#chunk[@]}" -eq 0 ] && continue
    ip=$(pick_ip)
    li=$((li + 1))
    cports="$(IFS=','; echo "${chunk[*]}")"
    # F3: preserva os args ORIGINAIS (scripts NSE como --script=vulners, -T, -O)
    # com -p do lote + source-bind do pool — o vulscan roda o vulners DE VERDADE
    "$NMAP_BIN" "${ORIG_ARGS[@]}" -p "$cports" -S "$ip" -e "$IFACE" \
        --host-timeout 90s -oN "$TMPD/c.nmap" -oX "$TMPD/c.xml" "$TARGET" >/dev/null 2>&1
    c_open=0
    [ -s "$TMPD/c.nmap" ] && c_open=$(grep -cE '[0-9]+/(tcp|udp)[[:space:]]+open([^|]|$)' "$TMPD/c.nmap")
    if [ "$c_open" -gt 0 ]; then
        cat "$TMPD/c.nmap" >> "$MERGED_N"
        n_ok=$((n_ok + c_open))
        # guarda o melhor XML válido (não concatenamos XML — inválido p/ parser)
        _best_cnt=$(grep -cE '[0-9]+/(tcp|udp)[[:space:]]+open([^|]|$)' "$BEST_N" 2>/dev/null); _best_cnt="${_best_cnt:-0}"
        if [ -z "$BEST_N" ] || [ "$c_open" -gt "$_best_cnt" ]; then
            BEST_N="$TMPD/c.nmap"; BEST_X="$TMPD/c.xml"
        fi
    fi
    # governor: as portas do lote contam pro threshold do IP que as escaneou
    for cp in "${chunk[@]}"; do _ptouch_add "$ip" "$cp"; done
    rm -f "$TMPD/c.nmap" "$TMPD/c.xml"
done

if [ "$n_ok" -gt 0 ] && [ -s "$MERGED_N" ]; then
    # repara os outputs originais (o Ruadan parseia esses)
    if [ -n "$ON_FILE" ]; then cp "$MERGED_N" "$ON_FILE"; fi
    if [ -n "$OX_FILE" ] && [ -n "$BEST_X" ]; then cp "$BEST_X" "$OX_FILE"; fi
    cat "$MERGED_N"
    echo ""
    echo "NMAP_IDENTITY_RESCUED: ${TARGET} (${n_ok} portas resgatadas via ${li} identidade(s) do pool; scan original saiu cego por bloqueio de par origem->destino)"
    st_set "rescued_at" "$(date +%s)"
    req_bump "$((n_ok * 4))"
    # F5: guarda no cache — repetições deste mesmo comando custam 0 requests
    mkdir -p "$CACHE_DIR" 2>/dev/null
    cp "$MERGED_N" "$CACHE_DIR/$CACHE_KEY.nmap" 2>/dev/null
    [ -n "$BEST_X" ] && cp "$BEST_X" "$CACHE_DIR/$CACHE_KEY.xml" 2>/dev/null
fi
rm -rf "$TMPD"
exit 0
