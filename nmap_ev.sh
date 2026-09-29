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
declare -A OPT_TAKES=( [-oN]=1 [-oX]=1 [-oS]=1 [-oA]=1 [-p]=1 [--script]=1
    [--host-timeout]=1 [--script-timeout]=1 [-D]=1 [-iL]=1 [--excludefile]=1
    [-S]=1 [-e]=1 [--max-rate]=1 [--min-rate]=1 [--max-retries]=1 [--scan-delay]=1 )
i=0
prev=""
for a in "$@"; do
    if [ -n "$prev" ]; then
        # valor da opção anterior
        case "$prev" in
            -oN) ON_FILE="$a" ;;
            -oX) OX_FILE="$a" ;;
        esac
        prev=""; continue
    fi
    case "$a" in
        -sU) has_su=1; args_rest+=("$a") ;;
        -*)  args_rest+=("$a")
             if [ -n "${OPT_TAKES[$a]:-}" ]; then prev="$a"; fi ;;
        *)   TARGET="$a" ;;   # posicional — o último vira o target
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
        grep -cE '[0-9]+/(tcp|udp)[[:space:]]+open' "$ON_FILE" 2>/dev/null
        return
    fi
    echo 0
}

if [ "$has_su" = 1 ] || ! _ev_enabled; then
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
    b=$(st_get "burned_pair_$ip")
    [ -n "$b" ] && continue
    CAND+=("$ip")
done
[ "${#CAND[@]}" -gt 0 ] || exit $rc   # pool inteiro queimado rumo a este alvo

# portas-chave (web + acesso remoto + serviços de valor) — MANTER ENXUTA
KEY_PORTS=(443 80 8000 8080 8443 3000 8888 22 3389 5900 5800 10000)

FOUND_PORTS=""
PROBE_IP=""
total_probes=0
pi=0
CACHED=$(st_get "rescue_ports")
if [ -n "$CACHED" ]; then
    FOUND_PORTS="$CACHED"
else
    for p in "${KEY_PORTS[@]}"; do
        while [ "$pi" -lt "${#CAND[@]}" ]; do
            ip="${CAND[$pi]}"
            rc_p=0
            probe_conn "$ip" "$p" || rc_p=$?
            if [ "$rc_p" = 0 ]; then
                FOUND_PORTS="${FOUND_PORTS}${p},"
                PROBE_IP="${PROBE_IP:-$ip}"
                break
            elif [ "$rc_p" = 2 ]; then
                # IP bloqueado rumo ao alvo → descarta e REPETE a mesma porta
                st_set "burned_pair_$ip" "$(date +%s)"
                pi=$((pi + 1))
            else
                # recusado: porta fechada, IP vivo — próxima porta
                break
            fi
        done
        total_probes=$((total_probes + 1))
        [ "$pi" -ge "${#CAND[@]}" ] && break
    done
    req_bump "$total_probes"
    FOUND_PORTS="${FOUND_PORTS%,}"
    # conserva: o IP que sondou fica gasto rumo a este alvo
    [ -n "$PROBE_IP" ] && st_set "burned_pair_$PROBE_IP" "$(date +%s)"
    [ -n "$PROBE_IP" ] && st_set "rescue_probes_${TARGET}" "$total_probes"
    [ -n "$FOUND_PORTS" ] && st_set "rescue_ports" "$FOUND_PORTS"
fi
[ -n "$FOUND_PORTS" ] || exit $rc   # nem a lista-chave conectou de nenhum IP

# IPs vivos restantes para o -sV (o que sondou já está gasto)
LIVE_IPS=()
for ((k = pi + 1; k < ${#CAND[@]}; k++)); do LIVE_IPS+=("${CAND[$k]}"); done
[ "${#LIVE_IPS[@]}" -eq 0 ] && [ "$pi" -lt "${#CAND[@]}" ] && LIVE_IPS=("${CAND[$pi]}")
[ "${#LIVE_IPS[@]}" -eq 0 ] && LIVE_IPS=("${POOL[$(( ${#POOL[@]} - 1 ))]}")
# ── FASE 2: nmap -sV em LOTES de 3 portas por IP vivo (o limite de conexões
#    por IP rumo a hosts endurecidos ~12-15 torna impossível um -sV de
#    10+ portas de um IP só — queimaria mid-scan)
TMPD="$(mktemp -d)"
MERGED_N="$TMPD/rescue.nmap"; : > "$MERGED_N"
BEST_N=""; BEST_X=""; n_ok=0; li=0
IFS=',' read -ra FP <<< "$FOUND_PORTS"
CHUNK=3
for ((s = 0; s < ${#FP[@]}; s += CHUNK)); do
    chunk=("${FP[@]:s:CHUNK}")
    [ "${#chunk[@]}" -eq 0 ] && continue
    ip="${LIVE_IPS[$((li % ${#LIVE_IPS[@]}))]}"
    li=$((li + 1))
    cports="$(IFS=','; echo "${chunk[*]}")"
    "$NMAP_BIN" -Pn -sV --version-light -p "$cports" -S "$ip" -e "$IFACE" \
        --host-timeout 90s -oN "$TMPD/c.nmap" -oX "$TMPD/c.xml" "$TARGET" >/dev/null 2>&1
    c_open=0
    [ -s "$TMPD/c.nmap" ] && c_open=$(grep -cE '[0-9]+/(tcp|udp)[[:space:]]+open' "$TMPD/c.nmap")
    if [ "$c_open" -gt 0 ]; then
        cat "$TMPD/c.nmap" >> "$MERGED_N"
        n_ok=$((n_ok + c_open))
        # guarda o melhor XML válido (não concatenamos XML — inválido p/ parser)
        if [ -z "$BEST_N" ] || [ "$c_open" -gt "$(grep -cE '[0-9]+/(tcp|udp)[[:space:]]+open' "$BEST_N" 2>/dev/null || echo 0)" ]; then
            BEST_N="$TMPD/c.nmap"; BEST_X="$TMPD/c.xml"
        fi
    fi
    # conserva: assume que o IP do lote ficou gasto rumo a este alvo
    st_set "burned_pair_$ip" "$(date +%s)"
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
fi
rm -rf "$TMPD"
exit 0
