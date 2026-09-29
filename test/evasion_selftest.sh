#!/bin/bash
# ==============================================================================
# Ruadan — Bateria de testes da camada de evasão (contra mocks em 127.0.0.1)
# ==============================================================================
# NÃO toca na rede real: mocks da defesa em loopback + aliases 127.0.0.2-11.
# Roda direto no host (bash/curl/flock/python3) — não precisa de container.
#
# Valida:
#   T1  Modo desligado (enabled=0): padrão de requests IDÊNTICO ao original
#       (2 requests por par body+code, 1 por code) e nenhum arquivo de estado
#   T2  Budget global: aborta exatamente no limite
#   T3  Bloqueio 403 → TARGET_BLOCKED + IP_ROTATED com IPs de origem distintos
#   T4  Bloqueio por DROP (sem resposta) → detecção via timeouts (000)
#   T5  Detecção de fita: porta emulada → EMULATED_SERVICE high + fuzzer pula;
#       porta wildcard-403 real → NÃO marca como emulada
#   T6  Fingerprint da defesa: FIREWALL_DETECTED com behavior/block_layer
#   T7  Cooldown APRENDIDO: rotação volta a um IP queimado depois que a defesa
#       desbloqueia → cooldown_learned persistido no estado
#   T8  Pool lifecycle: up adiciona aliases, down remove
#
# Uso: bash test/evasion_selftest.sh   (logs em /tmp/opencode/evselftest/)
# ==============================================================================
set -u

RUADAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTDIR="${TESTDIR:-/tmp/opencode/evselftest}"
mkdir -p "$TESTDIR"
PASS=0; FAIL=0
_ok() { echo "  PASS: $1"; PASS=$((PASS+1)); }
_bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
_section() { echo ""; echo "═══ $1 ═══"; }

# ---------- Pool de aliases de loopback (invisível para a rede real) ----------
EV_IFACE=lo EV_IP_POOL=127.0.0.2-127.0.0.11 EV_CONFIG=/nonexistent \
    bash "${RUADAN_DIR}/evasion_pool.sh" up > "$TESTDIR/pool_up.log" 2>&1
if ip addr show dev lo 2>/dev/null | grep -q "127.0.0.5"; then
    _ok "T8a aliases de loopback adicionados (127.0.0.2-11 em lo)"
else
    _bad "T8a aliases de loopback não apareceram (ver $TESTDIR/pool_up.log)"
fi

start_mock() {  # $1=port $2=thresh $3=blocktime $4=mode $5=logfile
    python3 "${RUADAN_DIR}/test/mock_blocker.py" --port "$1" --thresh "$2" \
        --blocktime "$3" --mode "$4" > "$5" 2>&1 &
    echo $!
    sleep 0.5
}
MOCK_PIDS=""
cleanup() {
    [ -n "$MOCK_PIDS" ] && kill $MOCK_PIDS 2>/dev/null
    EV_IFACE=lo EV_IP_POOL=127.0.0.2-127.0.0.11 EV_CONFIG=/nonexistent \
        bash "${RUADAN_DIR}/evasion_pool.sh" down > "$TESTDIR/pool_down.log" 2>&1
}
trap cleanup EXIT

mock_lines() { grep -cE '^[0-9]+\.[0-9]+ ' "$1" 2>/dev/null || echo 0; }
mock_ips() { grep -oE '^[0-9]+\.[0-9]+ 127[0-9.]*' "$1" 2>/dev/null | awk '{print $2}' | sort -u | wc -l; }

# ==============================================================================
_section "T1 — Modo desligado (enabled=0): padrão de requests idêntico"
T="$TESTDIR/t1"; mkdir -p "$T"
MP=$(start_mock 8891 999 60 403 "$T/mock.log"); MOCK_PIDS="$MOCK_PIDS $MP"
EV_OUTPUT_DIR="$T/state" EV_CONFIG=/nonexistent bash -c "
    . '${RUADAN_DIR}/evasion_lib.sh'
    ev_init 127.0.0.1 8891 http
    for i in 1 2 3; do ev_body_and_code -sk --max-time 5 \"http://127.0.0.1:8891/pair\$i\"; done
    for i in 1 2; do ev_code -sk --max-time 5 \"http://127.0.0.1:8891/code\$i\"; done
" > "$T/out.log" 2>&1
n=$(mock_lines "$T/mock.log")
if [ "$n" = "8" ]; then
    _ok "T1a 8 requests para 3 pares + 2 singles (padrão original: 2+2+2+1+1) — mock contou $n"
else
    _bad "T1a esperado 8 requests, mock contou $n (ver $T/mock.log)"
fi
if [ ! -f "$T/state/127_0_0_1/evasion_state.env" ]; then
    _ok "T1b desligado não cria arquivo de estado"
else
    _bad "T1b desligado criou estado (não deveria)"
fi

# ==============================================================================
_section "T2 — Budget global aborta no limite"
T="$TESTDIR/t2"; mkdir -p "$T"
MP=$(start_mock 8892 999 60 403 "$T/mock.log"); MOCK_PIDS="$MOCK_PIDS $MP"
EV_OUTPUT_DIR="$T/state" EV_CONFIG=/nonexistent \
EV_ENABLED=1 EV_BUDGET=5 EV_JITTER_MIN=0 EV_JITTER_MAX=0 \
EV_EMULATION_CHECK=0 EV_DEFENSE_FINGERPRINT=0 EV_PORT_TIME_BUDGET=0 \
    bash -c "
    . '${RUADAN_DIR}/evasion_lib.sh'
    ev_init 127.0.0.1 8892 http
    for i in \$(seq 1 20); do
        ev_code -sk --max-time 5 \"http://127.0.0.1:8892/b\$i\"
        ev_should_abort && break
    done
" > "$T/out.log" 2>&1
n=$(mock_lines "$T/mock.log")
if [ "$n" = "5" ] && grep -q "EVASION_BUDGET_EXHAUSTED" "$T/out.log"; then
    _ok "T2a abortou exatamente no budget 5/5 e logou EVASION_BUDGET_EXHAUSTED"
else
    _bad "T2a mock contou $n (esperado 5) ou faltou log (ver $T/out.log)"
fi

# ==============================================================================
_section "T3 — Bloqueio 403 → TARGET_BLOCKED + IP_ROTATED com IPs distintos"
T="$TESTDIR/t3"; mkdir -p "$T"
MP=$(start_mock 8893 20 600 403 "$T/mock.log"); MOCK_PIDS="$MOCK_PIDS $MP"
EV_OUTPUT_DIR="$T/state" EV_CONFIG=/nonexistent \
EV_ENABLED=1 EV_IP_POOL=127.0.0.2-127.0.0.11 EV_BUDGET=2000 \
EV_JITTER_MIN=0 EV_JITTER_MAX=0 EV_EMULATION_CHECK=0 EV_DEFENSE_FINGERPRINT=0 \
EV_PORT_TIME_BUDGET=0 EV_COOLDOWN_BASE=900 \
    bash -c "
    . '${RUADAN_DIR}/evasion_lib.sh'
    ev_init 127.0.0.1 8893 http
    for i in \$(seq 1 150); do
        ev_code -sk --max-time 5 \"http://127.0.0.1:8893/r\$i\"
        ev_should_abort && break
    done
" > "$T/out.log" 2>&1
nb=$(grep -c "TARGET_BLOCKED" "$T/out.log" || true)
nr=$(grep -c "IP_ROTATED" "$T/out.log" || true)
nip=$(mock_ips "$T/mock.log")
if [ "$nb" -ge 1 ] && [ "$nr" -ge 1 ]; then
    _ok "T3a bloqueio detectado (${nb}x) e rotação executada (${nr}x)"
else
    _bad "T3a bloqueio=${nb} rotacao=${nr} (ver $T/out.log)"
fi
if [ "$nip" -ge 3 ]; then
    _ok "T3b mock viu ${nip} IPs de origem distintos (rotação real de source-IP)"
else
    _bad "T3b mock viu só ${nip} IP(s) — --interface não está variando (ver $T/mock.log)"
fi

# ==============================================================================
_section "T4 — Bloqueio por DROP (sem resposta) → detecção via timeout 000"
T="$TESTDIR/t4"; mkdir -p "$T"
MP=$(start_mock 8894 8 90 drop "$T/mock.log"); MOCK_PIDS="$MOCK_PIDS $MP"
EV_OUTPUT_DIR="$T/state" EV_CONFIG=/nonexistent \
EV_ENABLED=1 EV_IP_POOL=127.0.0.2-127.0.0.11 EV_BUDGET=2000 \
EV_JITTER_MIN=0 EV_JITTER_MAX=0 EV_EMULATION_CHECK=0 EV_DEFENSE_FINGERPRINT=0 \
EV_PORT_TIME_BUDGET=0 EV_BLOCK_TIMEOUT_THRESHOLD=3 EV_COOLDOWN_BASE=900 \
    bash -c "
    . '${RUADAN_DIR}/evasion_lib.sh'
    ev_init 127.0.0.1 8894 http
    ev_set_probe_url 'http://127.0.0.1:8894/'
    for i in \$(seq 1 40); do
        ev_code -sk --max-time 2 \"http://127.0.0.1:8894/d\$i\"
        ev_should_abort && break
    done
" > "$T/out.log" 2>&1
nb=$(grep -c "TARGET_BLOCKED" "$T/out.log" || true)
nip=$(mock_ips "$T/mock.log")
if [ "$nb" -ge 1 ] && [ "$nip" -ge 2 ]; then
    _ok "T4a drop detectado via timeouts (${nb}x bloqueio, ${nip} IPs distintos)"
else
    _bad "T4a bloqueio=${nb} IPs=${nip} (ver $T/out.log e $T/mock.log)"
fi

# ==============================================================================
_section "T5 — Detecção de fita: porta emulada é marcada e pulada"
T="$TESTDIR/t5"; mkdir -p "$T"
MP=$(start_mock 8895 999 60 emulated "$T/mock_emul.log"); MOCK_PIDS="$MOCK_PIDS $MP"
MP=$(start_mock 8896 999 60 403 "$T/mock_real.log"); MOCK_PIDS="$MOCK_PIDS $MP"
bash "${RUADAN_DIR}/emulation_check.sh" 127.0.0.1 8895 http "$T/state" > "$T/emul.out" 2>&1
bash "${RUADAN_DIR}/emulation_check.sh" 127.0.0.1 8896 http "$T/state" > "$T/real.out" 2>&1
if grep -q "EMULATED_SERVICE: 127.0.0.1:8895 confidence=high" "$T/emul.out"; then
    _ok "T5a porta emulada (corpo idêntico p/ qualquer path) → EMULATED_SERVICE high"
else
    _bad "T5a porta emulada não foi marcada high (ver $T/emul.out)"
fi
if grep -q "emulated_ports=8895" "$T/state/evasion_state.env" 2>/dev/null || \
   grep -qE "^emulated_ports=.*8895" "$T/state/evasion_state.env" 2>/dev/null; then
    _ok "T5b porta 8895 registrada em emulated_ports no estado"
else
    _bad "T5b emulated_ports não contém 8895 (ver $T/state/evasion_state.env)"
fi
if grep -q "EMULATED_SERVICE: 127.0.0.1:8896" "$T/real.out"; then
    _bad "T5c porta 403-wildcard REAL foi marcada como emulada (falso positivo! ver $T/real.out)"
else
    _ok "T5c porta wildcard-403 real NÃO marcada como emulada"
fi
# fuzzer pula a porta emulada?
EV_OUTPUT_DIR="$T/state" EV_CONFIG=/nonexistent \
EV_ENABLED=1 EV_JITTER_MIN=0 EV_JITTER_MAX=0 EV_DEFENSE_FINGERPRINT=0 EV_PORT_TIME_BUDGET=0 \
    bash -c "
    . '${RUADAN_DIR}/evasion_lib.sh'
    ev_init 127.0.0.1 8895 http
    if ev_skip_port; then echo 'SKIP_CONFIRMED'; fi
" > "$T/skip.out" 2>&1
grep -q "SKIP_CONFIRMED" "$T/skip.out" && _ok "T5d fuzzer pula porta emulada (ev_skip_port)" \
    || _bad "T5d fuzzer não pulou a porta emulada (ver $T/skip.out)"

# ==============================================================================
_section "T6 — Fingerprint da defesa no bloqueio"
T="$TESTDIR/t6"; mkdir -p "$T"
MP=$(start_mock 8897 1 300 403 "$T/mock.log"); MOCK_PIDS="$MOCK_PIDS $MP"
curl -sk --max-time 3 "http://127.0.0.1:8897/warmup1" -o /dev/null
curl -sk --max-time 3 "http://127.0.0.1:8897/warmup2" -o /dev/null
bash "${RUADAN_DIR}/defense_fingerprint.sh" 127.0.0.1 8897 http "$T/state" > "$T/out.log" 2>&1
if grep -q "FIREWALL_DETECTED: 127.0.0.1:8897 behavior=http_responds block_layer=http_403" "$T/out.log"; then
    _ok "T6a FIREWALL_DETECTED com behavior/block_layer corretos (defesa responde 403)"
else
    _bad "T6a linha FIREWALL_DETECTED incorreta (ver $T/out.log)"
fi
grep -q "defense_profile=http_responds/http_403" "$T/state/evasion_state.env" 2>/dev/null \
    && _ok "T6b defense_profile persistido no estado" \
    || _bad "T6b defense_profile não persistiu (ver $T/state/evasion_state.env)"

# ==============================================================================
_section "T7 — Cooldown APRENDIDO (defesa desbloqueia sozinha)"
T="$TESTDIR/t7"; mkdir -p "$T"
MP=$(start_mock 8898 5 3 403 "$T/mock.log"); MOCK_PIDS="$MOCK_PIDS $MP"
EV_OUTPUT_DIR="$T/state" EV_CONFIG=/nonexistent \
EV_ENABLED=1 EV_IP_POOL=127.0.0.2-127.0.0.3 EV_BUDGET=2000 \
EV_JITTER_MIN=0.3 EV_JITTER_MAX=0.3 EV_EMULATION_CHECK=0 EV_DEFENSE_FINGERPRINT=0 \
EV_PORT_TIME_BUDGET=0 EV_COOLDOWN_BASE=4 EV_COOLDOWN_MAX=60 EV_COOLDOWN_LEARN_MIN=2 \
    bash -c "
    . '${RUADAN_DIR}/evasion_lib.sh'
    ev_init 127.0.0.1 8898 http
    for i in \$(seq 1 80); do
        ev_code -sk --max-time 5 \"http://127.0.0.1:8898/c\$i\"
        ev_should_abort && break
    done
" > "$T/out.log" 2>&1
learned=$(grep -m1 '^cooldown_learned=' "$T/state/127_0_0_1/evasion_state.env" 2>/dev/null | cut -d= -f2)
if [ -n "$learned" ] && [ "$learned" -ge 3 ] && [ "$learned" -le 60 ]; then
    _ok "T7a cooldown aprendido empiricamente: ${learned}s (defesa desbloqueou e voltamos ao IP)"
else
    _bad "T7a cooldown_learned='${learned}' (esperado 3..60) — ver $T/out.log"
fi
n=$(mock_lines "$T/mock.log")
if [ "$n" -ge 40 ]; then
    _ok "T7b rotação sustentou ${n} requests ciclando identidades queimadas (cooldown respeitado)"
else
    _bad "T7b só ${n} requests — rotação não sustentou o ciclo (ver $T/out.log)"
fi

# ==============================================================================
_section "T8b — Pool lifecycle: down remove aliases"
EV_IFACE=lo EV_IP_POOL=127.0.0.2-127.0.0.11 EV_CONFIG=/nonexistent \
    bash "${RUADAN_DIR}/evasion_pool.sh" down > "$TESTDIR/pool_down.log" 2>&1
if ! ip addr show dev lo 2>/dev/null | grep -q "127.0.0.5"; then
    _ok "T8c aliases removidos após down"
else
    _bad "T8c aliases continuam presentes após down (ver $TESTDIR/pool_down.log)"
fi

# ==============================================================================
echo ""
echo "════════════════════════════════════════════"
echo " RESULTADO: ${PASS} PASS / ${FAIL} FAIL"
echo " Logs: ${TESTDIR}/"
echo "════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
