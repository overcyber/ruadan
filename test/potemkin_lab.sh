#!/bin/bash
# ==============================================================================
# Ruadan — Bateria de eficácia contra o Potemkin REAL (lab isolado em 127.0.0.2)
# ==============================================================================
# Valida o agente vermelho ADAPTATIVO (trap_census/governor/oráculo) contra a
# defesa real deployada num container — sem tocar na rede do lab.
#
# C1  EFICÁCIA DA DEFESA (controle): 1 IP sonda traps sequencialmente → a
#     defesa BANE (prova que o Potemkin funciona contra scan ingênuo)
# C2  CENSUS ADAPTATIVO: governor respeitado (cap < threshold) → mapa completo
#     de traps + porta REAL identificada, ZERO bans
# C3  PORTA REAL ILIMITADA: hammering na porta real → defesa cega
# C4  IPv6 CEGO: conexões v6 → zero eventos (gap documentado)
# C5  ESCALONAMENTO: 3 triggers do mesmo IP → bans 10→30→60s (aprendizado)
# C6  ORÁCULO DO THRESHOLD: census de 1 IP só → ban no meio → sistema APRENDE
#     o threshold real (3) e aposenta o IP
#
# Resultados: ruadan/test/results_potemkin_<ts>/  (tudo salvo localmente)
# ==============================================================================
set -u
RUADAN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$RUADAN/test/potemkin_lab"
TS=$(date +%Y%m%d_%H%M%S)
RES="$RUADAN/test/results_potemkin_$TS"
mkdir -p "$RES"
PASS=0; FAIL=0
_ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
_bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
PROBE="$RUADAN/trap_probe.py"
BLOCKS="$LAB/potemkin_blocks.log"
FWLOG="$LAB/potemkin_fw.log"
CTR="potemkin-test"

cleanup() {
    docker rm -f "$CTR" >/dev/null 2>&1
    pkill -f "mock_real.py" 2>/dev/null
    # segurança: chain POTEMKIN fora, jump fora
    iptables -D INPUT -j POTEMKIN 2>/dev/null
    iptables -F POTEMKIN 2>/dev/null
    iptables -X POTEMKIN 2>/dev/null
}
trap cleanup EXIT

# ---------- preflight -----------------------------------------------------------
echo "═══ PREFLIGHT ═══"
command -v iptables >/dev/null || { echo "[ERRO] iptables ausente no host"; exit 1; }
docker images ruadan:kali --format "{{.Repository}}" | grep -q ruadan || { echo "[ERRO] imagem ruadan:kali ausente"; exit 1; }
[ -f "$LAB/potemkin.py" ] || { echo "[ERRO] potemkin.py ausente no lab"; exit 1; }
# portas ocupadas no host (serviços reais) — EXCLUÍDAS das listas de cenário
ss -tln 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un > "$RES/host_ports.txt"
# candidatos a trap (perto do mapa de respondentes) — dinâmico, nada fixo
CANDS="21 25 79 110 135 137 139 143 587 993 995 2222 2323 3690 5432 9900"
TRAPS=""
for p in $CANDS; do
    grep -qx "$p" "$RES/host_ports.txt" || TRAPS="$TRAPS $p"
done
read -ra TP <<< "$TRAPS"

if [ "${#TP[@]}" -lt 12 ]; then echo "[ERRO] portas de trap insuficientes (${#TP[@]})"; exit 1; fi
echo "  portas de trap disponíveis: ${TP[*]:0:16}"

# ---------- sobe a defesa + o serviço real --------------------------------------
echo "═══ SETUP: Potemkin (container) + serviço real 127.0.0.2:7777 ═══"
rm -f "$BLOCKS" "$FWLOG" "$LAB/potemkin_run.log"
python3 "$LAB/mock_real.py" > "$RES/mock.log" 2>&1 &
sleep 0.5
docker rm -f "$CTR" >/dev/null 2>&1
docker run -d --name "$CTR" --network host --cap-add NET_ADMIN -v "$LAB:/lab" \
    --entrypoint bash ruadan:kali -c '
        command -v iptables >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1 || true; apt-get install -y -qq iptables >/dev/null 2>&1 || echo "[warn] install iptables falhou" >> /lab/potemkin_fw.log; }
        command -v iptables >/dev/null 2>&1 || echo "[erro] iptables ausente — drops nao funcionarao" >> /lab/potemkin_fw.log
        printf "#!/bin/bash\n[ \"\$1\" = \"-n\" ] && shift\nexec \"\$@\"\n" > /usr/local/bin/sudo
        chmod +x /usr/local/bin/sudo
        cp /lab/firewall_helper.sh /usr/local/bin/potemkin-firewall
        chmod +x /usr/local/bin/potemkin-firewall
        exec python3 /lab/potemkin.py -c /lab/test.conf
    ' >/dev/null
# aguarda prontidão: alguma trap aceita conexão
READY=0
for i in $(seq 1 90); do
    r=$(python3 "$PROBE" 127.0.0.1 127.0.0.2 "${TP[0]}" banner 2>/dev/null)
    [ "${r%% *}" = "result=connect" ] && { READY=1; break; }
    sleep 2
done
[ "$READY" = 1 ] || { echo "[ERRO] Potemkin não ficou pronto"; docker logs "$CTR" 2>&1 | tail -5; exit 1; }
sleep 1
# o serviço REAL precisa estar vivo antes de prosseguir (Potemkin captura a porta se o mock morrer)
curl -s --max-time 2 -o /dev/null -w "" "http://127.0.0.2:7777/" 2>/dev/null || { echo "[ERRO] mock real 7777 morto — abortando"; exit 1; }
echo "  defesa no ar + serviço real 7777 no ar"

# ---------- helpers de asserção --------------------------------------------------
cnt() { local n; n=$(grep -cE "$1" "$2" 2>/dev/null); echo "${n:-0}"; }
scan_count() { cnt "SCAN ip=$1 " "$BLOCKS"; }
rate_count() { cnt "RATE ip=$1 " "$BLOCKS"; }
wait_unblock() {  # $1=ip, timeout 100s
    local before now
    before=$(cnt "UNBLOCK $1" "$FWLOG")
    for i in $(seq 1 50); do
        now=$(cnt "UNBLOCK $1" "$FWLOG")
        [ "$now" -gt "$before" ] && return 0
        sleep 2
    done
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
echo ""; echo "═══ C1 — EFICÁCIA DA DEFESA (controle: scan ingênuo leva ban) ═══"
for p in "${TP[0]}" "${TP[1]}" "${TP[2]}" "${TP[3]}" "${TP[4]}"; do
    python3 "$PROBE" 127.0.0.3 127.0.0.2 "$p" banner >> "$RES/c1.log" 2>&1
done
sleep 1
n=$(scan_count 127.0.0.3)
if [ "$n" -ge 1 ]; then
    _ok "C1 defesa detectou e baniu o scanner (SCAN ip=127.0.0.3: $n evento(s))"
    grep "SCAN ip=127.0.0.3" "$BLOCKS" | head -1 | sed 's/^/      /' | tee -a "$RES/c1.log"
else
    _bad "C1 defesa NÃO baniu (esperado ≥1 SCAN para 127.0.0.3)"
fi

# ══════════════════════════════════════════════════════════════════════════════
echo ""; echo "═══ C2 — CENSUS ADAPTATIVO (governor: zero bans + mapa completo) ═══"
C2ST="$RES/c2_state"; mkdir -p "$C2ST"
EV_CONFIG=/nonexistent EV_IP_POOL="127.0.0.4-127.0.0.12" EV_PORT_TOUCH_CAP=2 \
    bash "$RUADAN/trap_census.sh" 127.0.0.2 "$C2ST" "${TP[5]},${TP[6]},${TP[7]},${TP[8]},7777,31337" \
    > "$RES/c2.log" 2>&1
n_trapports=$(cnt '^tp_[0-9]+=trap$' "$C2ST/evasion_state.env")
n_suspect=$(cnt '^tp_[0-9]+=suspect$' "$C2ST/evasion_state.env")
n_live=$(cnt "LIVE_PORT: 127.0.0.2:7777" "$RES/c2.log")
c2_bans=0
for i in 4 5 6 7 8 9 10 11 12; do
    b=$(scan_count "127.0.0.$i"); c2_bans=$((c2_bans + b))
done
if [ "$n_trapports" -ge 2 ] && [ "$n_suspect" -ge 3 ] && [ "$n_live" -ge 1 ] && [ "$c2_bans" -eq 0 ]; then
    _ok "C2 census: ${n_trapports} traps (cluster), ${n_suspect} suspeitas (canned/swallow), porta REAL ok, ZERO bans"
else
    _bad "C2 trap=$n_trapports suspect=$n_suspect live=$n_live bans=$c2_bans (esperado ≥2, ≥3, ≥1, 0) — ver $RES/c2.log"
fi
grep -E "TRAP_|PORT_SUSPECT|LIVE_PORT" "$RES/c2.log" | sed 's/^/      /' | head -8

# ══════════════════════════════════════════════════════════════════════════════
echo ""; echo "═══ C3 — PORTA REAL ILIMITADA (defesa cega em serviço legítimo) ═══"
for i in $(seq 1 30); do
    curl -s --interface 127.0.0.13 --max-time 2 -o /dev/null "http://127.0.0.2:7777/" 2>/dev/null
done
n=$(scan_count "127.0.0.13"); r=$(rate_count "127.0.0.13")
if [ "$n" = 0 ] && [ "$r" = 0 ]; then
    _ok "C3 30 requests na porta REAL: zero eventos (defesa não vê serviço legítimo)"
else
    _bad "C3 eventos na porta real: SCAN=$n RATE=$r (esperado 0/0)"
fi

# ══════════════════════════════════════════════════════════════════════════════
echo ""; echo "═══ C4 — IPv6 CEGO (gap documentado) ═══"
ok4=1
for i in $(seq 1 20); do
    curl -s --max-time 2 -o /dev/null "http://[::1]:7777/" 2>/dev/null || ok4=0
done
v6ev=$(cnt "SCAN ip=::1|RATE ip=::1" "$BLOCKS")
r6=$(python3 "$PROBE" - ::1 "${TP[9]}" banner 2>/dev/null)
if [ "$ok4" = 1 ] && [ "$v6ev" = 0 ]; then
    _ok "C4 20 conexões IPv6 ao serviço real: ZERO eventos (defesa é cega a v6)"
    echo "      (traps via ::1: ${r6%% *} — sockets da defesa são v4-only)"
else
    _bad "C4 ok4=$ok4 eventos_v6=$v6ev"
fi

# ══════════════════════════════════════════════════════════════════════════════
echo ""; echo "═══ C5 — ESCALONAMENTO (curva 10→30→60s aprendida empiricamente) ═══"
trigger_round() {  # 3 portas únicas → ban; $1..$3 portas
    python3 "$PROBE" 127.0.0.14 127.0.0.2 "$1" banner >/dev/null 2>&1
    python3 "$PROBE" 127.0.0.14 127.0.0.2 "$2" banner >/dev/null 2>&1
    python3 "$PROBE" 127.0.0.14 127.0.0.2 "$3" banner >/dev/null 2>&1
    sleep 1
}
trigger_round "${TP[0]}" "${TP[1]}" "${TP[2]}"      # 1ª ofensa → 10s
wait_unblock 127.0.0.14 || true
trigger_round "${TP[3]}" "${TP[4]}" "${TP[5]}"      # 2ª ofensa → 30s
wait_unblock 127.0.0.14 || true
trigger_round "${TP[6]}" "${TP[7]}" "${TP[8]}"      # 3ª ofensa → 60s
sleep 1
grep "SCAN ip=127.0.0.14" "$BLOCKS" > "$RES/c5.log" 2>&1
b1=$(grep -oE "ban=[0-9]+s" "$RES/c5.log" | sed -n 1p)
b2=$(grep -oE "ban=[0-9]+s" "$RES/c5.log" | sed -n 2p)
b3=$(grep -oE "ban=[0-9]+s" "$RES/c5.log" | sed -n 3p)
if [ "$b1" = "ban=10s" ] && [ "$b2" = "ban=30s" ] && [ "$b3" = "ban=60s" ]; then
    _ok "C5 escalonamento confirmado: $b1 → $b2 → $b3"
else
    _bad "C5 curva: '$b1' '$b2' '$b3' (esperado 10/30/60) — ver $RES/c5.log"
fi

# ══════════════════════════════════════════════════════════════════════════════
echo ""; echo "═══ C6 — ORÁCULO DO THRESHOLD (census de 1 IP aprende o valor real) ═══"
# portas de BANNER rápido (responders que falam primeiro): 3 toques < 3s →
# ban de 10s ainda ativo na 4ª sonda → timeout → oráculo dispara
C6ST="$RES/c6_state"; mkdir -p "$C6ST"
EV_CONFIG=/nonexistent EV_IP_POOL="127.0.0.15" \
    bash "$RUADAN/trap_census.sh" 127.0.0.2 "$C6ST" "${TP[0]},${TP[1]},${TP[2]},${TP[3]},${TP[4]}" \
    > "$RES/c6.log" 2>&1
learned=$(grep -m1 '^porttouch_threshold_learned=' "$C6ST/evasion_state.env" 2>/dev/null | cut -d= -f2)
offender=$(grep -m1 "^offender_127.0.0.15=1$" "$C6ST/evasion_state.env" 2>/dev/null)
if [ -n "$learned" ] && [ "$learned" -ge 2 ] && [ -n "$offender" ]; then
    _ok "C6 oráculo aprendeu threshold=${learned} (real=3) e aposentou o IP ofensor"
else
    _bad "C6 learned='$learned' offender='$offender' — ver $RES/c6.log"
fi
grep -m1 "DEFENSE_PORT_THRESHOLD_LEARNED" "$RES/c6.log" | sed 's/^/      /'

# ---------- resumo ----------------------------------------------------------------
echo ""
echo "════════════════════════════════════════════"
echo " RESULTADO: ${PASS} PASS / ${FAIL} FAIL"
echo " Logs: $RES"
echo "════════════════════════════════════════════"
cp -a "$BLOCKS" "$FWLOG" "$RES/" 2>/dev/null
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
