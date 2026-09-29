#!/bin/bash
# ==============================================================================
# Ruadan — Evasion Pool (pool de IPs de origem + SOCKS5 com source-binding)
# ==============================================================================
# Uso:
#   evasion_pool.sh up       # adiciona aliases de IP na interface + sobe 3proxy
#   evasion_pool.sh down     # mata os proxies e remove os aliases
#   evasion_pool.sh status   # mostra estado de cada identidade
#
# ARQUITETURA:
#   A defesa do lab bloqueia por IP após X tentativas. O atacante (container
#   kali, --network host) sai com um único IP (ex: 192.168.50.210). Este script
#   cria N identidades extras:
#     - aliases de IP na interface (ex: 192.168.50.240-249 — faixa do config
#       [EVASION] ip_pool, NUNCA hardcoded, NUNCA são alvos)
#     - 1 instância 3proxy SOCKS5 por IP, escutando em 127.0.0.1:108xx com
#       -e <ip> (source-binding: toda conexão sai com aquele IP de origem)
#   O curl usa --interface <ip> direto (sem proxy, menor latência);
#   ffuf/gobuster (sem suporte a source-bind) usam -x socks5://127.0.0.1:108xx.
#
# ONDE RODA: dentro de um container com --network host --cap-add NET_ADMIN
#   (os aliases caem no netns do HOST e ficam visíveis para o container de
#   ataque, que também é host-networked). O container do pool precisa ficar
#   de pé enquanto a campanha roda (processos 3proxy morrem com o container).
#   Para TESTES: roda direto no host com ip_pool=127.0.0.2-11 iface=lo
#   (aliases de loopback são invisíveis para a rede).
#
# O 3proxy é opcional: se ausente, avisa e segue só com aliases (curl
# --interface funciona; ffuf fica sem rotação de source-IP).
# ==============================================================================
set -u

EV_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# ---------- Config ([EVASION] do config.ini; env override) --------------------
EV_CONFIG="${EV_CONFIG:-/ruadan/config.ini}"
EV_IP_POOL="${EV_IP_POOL:-}"
EV_IFACE="${EV_IFACE:-}"
EV_PROXY_BASE_PORT="${EV_PROXY_BASE_PORT:-}"

_pool_cfg() {
    local key="$1" default="${2:-}"
    [ -f "$EV_CONFIG" ] || { printf '%s' "$default"; return 0; }
    local val
    val=$(awk -v k="$key" '
        BEGIN { in_sec = 0 }
        tolower($0) ~ /^[[:space:]]*\[evasion\][[:space:]]*$/ { in_sec = 1; next }
        in_sec && /^[[:space:]]*\[/ { in_sec = 0 }
        in_sec && index($0, "=") > 0 {
            key = tolower($1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            sub(/^[^=]*=/, "", $0)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
            if (key == k) { print $0; exit }
        }
    ' "$EV_CONFIG" 2>/dev/null)
    printf '%s' "${val:-$default}"
}

EV_IP_POOL="${EV_IP_POOL:-$(_pool_cfg ip_pool "")}"
EV_IFACE="${EV_IFACE:-$(_pool_cfg iface auto)}"
EV_PROXY_BASE_PORT="${EV_PROXY_BASE_PORT:-$(_pool_cfg proxy_base_port 10800)}"

if [ -z "$EV_IP_POOL" ]; then
    echo "[evasion-pool][ERRO] ip_pool vazio — configure [EVASION] ip_pool no config.ini ou export EV_IP_POOL"
    exit 1
fi

# Detecta interface default (para alias de LAN). Sem iproute2 → ERRO alto e
# claro (não chuta eth0: alias em interface errada é silenciosamente inútil).
if [ -z "$EV_IFACE" ] || [ "$EV_IFACE" = "auto" ]; then
    if command -v ip >/dev/null 2>&1; then
        EV_IFACE=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
    fi
    if [ -z "$EV_IFACE" ]; then
        echo "[evasion-pool][ERRO] não consegui detectar a interface default (iproute2 ausente?)"
        echo "[evasion-pool][ERRO] exporte EV_IFACE=<iface> explicitamente"
        exit 1
    fi
fi

# Máscara: loopback /8; LAN /24 (configurável via EV_CIDR)
if [ "${EV_CIDR:-}" = "" ]; then
    if [ "$EV_IFACE" = "lo" ]; then EV_CIDR="8"; else EV_CIDR="24"; fi
fi

# ---------- Expande o range (mesma lógica da evasion_lib) ----------------------
expand_pool() {
    local spec="$1" part ip b1 b2 b3 s e i
    local IFS=','
    for part in $spec; do
        part="${part//[[:space:]]/}"
        [ -z "$part" ] && continue
        if [[ "$part" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)-([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
            b1="${BASH_REMATCH[1]}"; b2="${BASH_REMATCH[2]}"; b3="${BASH_REMATCH[3]}"
            s="${BASH_REMATCH[4]}"; e="${BASH_REMATCH[8]}"
            if [ "${BASH_REMATCH[5]}.${BASH_REMATCH[6]}.${BASH_REMATCH[7]}" != "${b1}.${b2}.${b3}" ]; then
                continue
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

alias_present() {
    ip addr show dev "$EV_IFACE" 2>/dev/null | grep -qw "$1"
}

proxy_up() {
    (timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$1" 2>/dev/null) && return 0
    return 1
}

start_proxy_for() {
    local ip="$1" port="$2"
    if proxy_up "$port"; then
        echo "[evasion-pool]     socks5 127.0.0.1:${port} (src ${ip}) já no ar"
        return 0
    fi
    local pidfile="/run/evasion-socks-${port}.pid"
    # 3proxy se existir; senão evasion_socks.py (pure-Python, SEM dependências —
    # o pacote 3proxy não existe nos repos do Kali)
    if command -v 3proxy >/dev/null 2>&1; then
        local cfg="/tmp/3proxy-ev-${port}.cfg"
        cat > "$cfg" <<EOF
daemon
pidfile ${pidfile}
log /dev/null
allow *
maxconn 256
socks -p${port} -i127.0.0.1 -e${ip}
EOF
        3proxy "$cfg" 2>/dev/null
    elif command -v python3 >/dev/null 2>&1 && [ -f "$EV_LIB_DIR/evasion_socks.py" ]; then
        nohup python3 "$EV_LIB_DIR/evasion_socks.py" -l 127.0.0.1 -p "$port" -s "$ip" >/dev/null 2>&1 &
        echo $! > "$pidfile"
    else
        echo "[evasion-pool][WARN] nem 3proxy nem evasion_socks.py disponíveis — ffuf ficará sem rotação de source-IP"
        return 3
    fi
    sleep 0.4
    if proxy_up "$port"; then
        echo "[evasion-pool]     socks5 127.0.0.1:${port} (src ${ip}) no ar"
        return 0
    fi
    echo "[evasion-pool][WARN] proxy falhou ao subir 127.0.0.1:${port} (src ${ip})"
    return 1
}

stop_proxy_for() {
    local port="$1" pidfile="/run/evasion-socks-${port}.pid"
    if [ -f "$pidfile" ]; then
        kill "$(cat "$pidfile")" 2>/dev/null
        rm -f "$pidfile"
    fi
    # fallback: mata por pattern de linha de comando
    pkill -f "evasion_socks.py .* -p ${port} " 2>/dev/null
    pkill -f "3proxy.*${port}" 2>/dev/null
    rm -f "/tmp/3proxy-ev-${port}.cfg"
}

# ---------- Operações parciais (docker-run.sh divide: aliases no HOST com
# iproute2, SOCKS no container — a imagem Kali NÃO tem iproute2) ------------------
aliases_up() {
    echo "[evasion-pool] Aliases: iface=${EV_IFACE} cidr=/${EV_CIDR} range=${EV_IP_POOL}"
    while read -r ip; do
        [ -z "$ip" ] && continue
        if alias_present "$ip"; then
            echo "[evasion-pool]   alias ${ip}/${EV_CIDR} já presente em ${EV_IFACE}"
        elif ip addr add "${ip}/${EV_CIDR}" dev "$EV_IFACE" 2>/dev/null; then
            echo "[evasion-pool]   alias ${ip}/${EV_CIDR} adicionado em ${EV_IFACE}"
        else
            echo "[evasion-pool][ERRO] falha ao adicionar ${ip}/${EV_CIDR} em ${EV_IFACE} (precisa root?)"
        fi
    done < <(expand_pool "$EV_IP_POOL")
}
aliases_down() {
    echo "[evasion-pool] Removendo aliases de ${EV_IFACE}"
    while read -r ip; do
        [ -z "$ip" ] && continue
        if alias_present "$ip"; then
            ip addr del "${ip}/${EV_CIDR}" dev "$EV_IFACE" 2>/dev/null \
                && echo "[evasion-pool]   alias ${ip} removido" \
                || echo "[evasion-pool][WARN] não removeu alias ${ip}"
        fi
    done < <(expand_pool "$EV_IP_POOL")
}
socks_up() {
    echo "[evasion-pool] SOCKS: range=${EV_IP_POOL} base=${EV_PROXY_BASE_PORT}"
    idx=0
    while read -r ip; do
        [ -z "$ip" ] && continue
        port=$((EV_PROXY_BASE_PORT + idx))
        start_proxy_for "$ip" "$port" >/dev/null 2>&1 || true
        if proxy_up "$port"; then
            echo "[evasion-pool]   socks5 127.0.0.1:${port} (src ${ip}) no ar"
        else
            echo "[evasion-pool][ERRO] socks5 127.0.0.1:${port} (src ${ip}) NÃO subiu"
        fi
        idx=$((idx + 1))
    done < <(expand_pool "$EV_IP_POOL")
    echo "[evasion-pool] ${idx} listeners SOCKS processados."
}
socks_down() {
    idx=0
    while read -r ip; do
        [ -z "$ip" ] && continue
        stop_proxy_for "$((EV_PROXY_BASE_PORT + idx))"
        idx=$((idx + 1))
    done < <(expand_pool "$EV_IP_POOL")
    echo "[evasion-pool] listeners SOCKS derrubados."
}

case "${1:-status}" in
up)
    aliases_up
    socks_up
    echo "[evasion-pool] Pool pronto."
    ;;
aliases-up)   aliases_up ;;
aliases-down) aliases_down ;;
socks-up)     socks_up ;;
socks-down)   socks_down ;;
down)
    socks_down
    aliases_down
    echo "[evasion-pool] Pool derrubado."
    ;;
status)
    echo "[evasion-pool] iface=${EV_IFACE} range=${EV_IP_POOL} proxy_base=${EV_PROXY_BASE_PORT}"
    idx=0; alive=0
    while read -r ip; do
        [ -z "$ip" ] && continue
        port=$((EV_PROXY_BASE_PORT + idx))
        a="ausente"; alias_present "$ip" && a="presente"
        p="down"; proxy_up "$port" && { p="up"; alive=$((alive + 1)); }
        printf '[evasion-pool]   %-16s alias:%-9s socks5://127.0.0.1:%-6s %s\n' "$ip" "$a" "$port" "$p"
        idx=$((idx + 1))
    done < <(expand_pool "$EV_IP_POOL")
    echo "[evasion-pool] ${alive}/${idx} proxies no ar"
    ;;
*)
    echo "uso: evasion_pool.sh up|down|aliases-up|aliases-down|socks-up|socks-down|status"
    echo "env: EV_IP_POOL=192.168.50.240-249 EV_IFACE=enp5s0 EV_PROXY_BASE_PORT=10800 EV_CONFIG=/ruadan/config.ini"
    exit 1
    ;;
esac
exit 0
