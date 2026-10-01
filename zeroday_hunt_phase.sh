#!/bin/bash
# ==============================================================================
# Ruadan — FASE A: Ponte para o Caçador 0-Day (zeroday_hunt do red-MPPO)
# ==============================================================================
# Uso: zeroday_hunt_phase.sh <targets_csv> <output_folder>
#
# O QUE FAZ:
#   1. Gera o inventory YAML DINAMICAMENTE a partir dos alvos do ciclo
#      (hostFile → CIDRs /32 por alvo = gate de autorização; subnet /24 do
#      primeiro alvo para o sweep descobrir; credenciais declaradas em
#      targets/credentials.txt, se existirem; listener C2 em porta própria).
#   2. Invoca o ZeroDayHunter dentro do próprio container ruadan:kali:
#      sweep → scan 1-65535 → bateria determinística por protocolo →
#      LLM (gpt-oss:20b) dirigindo a caça com tools ssh_login/remote_exec/
#      check_root/read_file/privesc_scan → verify_suspect anti-FP →
#      findings.json + hunt_report.md + auditoria com manifest sha256.
#   3. Emite marcadores parseáveis para a kill chain do Ruadan:
#      ZERODAY_FINDING / CRED_DISCOVERED / SHELL_OBTAINED
#
# Gates: budget 20min/host (RUADAN_HUNT_PER_HOST=1200), wall-clock total
# (RUADAN_HUNT_WALLCLOCK default: hosts×1200+300), modelo RUADAN_HUNT_MODEL
# (default gpt-oss:20b, timeouts longos — decisão do operador).
# ==============================================================================
set -u

# Aceita: zeroday_hunt_phase.sh --hostfile <arquivo> <output_folder>
#      ou: zeroday_hunt_phase.sh <targets_csv> <output_folder>
if [ "${1:-}" = "--hostfile" ]; then
    HF="${2:?--hostfile exige caminho}"
    OUT_DIR="${3:-/ruadan/output}"
    TARGETS_CSV=$(grep -vE '^\s*#|^\s*$' "$HF" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -z "$TARGETS_CSV" ]; then
        echo "[0day] hostFile '$HF' vazio ou ilegível — nada a caçar."
        exit 0
    fi
else
    TARGETS_CSV="${1:?uso: zeroday_hunt_phase.sh [--hostfile <arq>] <targets_csv> <output_folder>}"
    OUT_DIR="${2:-/ruadan/output}"
fi
MODEL="${RUADAN_HUNT_MODEL:-gpt-oss:20b}"
PER_HOST="${RUADAN_HUNT_PER_HOST:-1200}"          # 20min por host (decisão)
N_TARGETS=$(echo "$TARGETS_CSV" | awk -F',' '{print NF}')
WALLCLOCK="${RUADAN_HUNT_WALLCLOCK:-$((N_TARGETS * PER_HOST + 300))}"
ROUNDS="${RUADAN_HUNT_ROUNDS:-8}"
LHOST_IP="${RUADAN_LHOST:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
[ -z "$LHOST_IP" ] && LHOST_IP="0.0.0.0"
HUNT_RUNS="${OUT_DIR}/zeroday_runs"
mkdir -p "$HUNT_RUNS"

echo "[0day] === CAÇADA 0-DAY — ${N_TARGETS} alvo(s) | modelo ${MODEL} | ${PER_HOST}s/host | total ${WALLCLOCK}s ==="

# ---- 1. Resolve alvos (hostname → IP) e monta o gate de autorização -----------
IPS=()
for t in ${TARGETS_CSV//,/ }; do
    ip="$t"
    if ! echo "$t" | grep -qE '^[0-9.]+$'; then
        ip=$(getent hosts "$t" 2>/dev/null | awk '{print $1}' | head -1)
        [ -z "$ip" ] && ip="$t"
    fi
    IPS+=("$ip")
done
CIDRS=""
for ip in "${IPS[@]}"; do
    CIDRS+="      - ${ip}/32"$'\n'
done
SEED="${IPS[0]}"
SUBNET="$(echo "$SEED" | awk -F. '{print $1"."$2"."$3".0/24"}')"

# Credenciais declaradas (targets/credentials.txt — "user:pass" por linha)
SSH_CREDS_YAML=""
if [ -f /ruadan/targets/credentials.txt ]; then
    while IFS=: read -r u p; do
        [ -z "$u" ] && continue
        SSH_CREDS_YAML+="    - username: \"${u}\""$'\n'"      password: \"${p}\""$'\n'
    done < /ruadan/targets/credentials.txt
fi

# ---- 2. Inventory YAML dinâmico ------------------------------------------------
INV_FILE="/tmp/ruadan_hunt_$$.yaml"
cat > "$INV_FILE" <<EOF
# Gerado automaticamente pelo Ruadan (zeroday_hunt_phase.sh) — NÃO editar
authorization:
  owner: "ruadan-lab-operator"
  allowed_cidrs:
$(echo -n "$CIDRS")
target:
  seed_host_ip: "${SEED}"
  subnet: "${SUBNET}"
$( [ -n "$SSH_CREDS_YAML" ] && printf '  ssh_creds:\n%s' "$SSH_CREDS_YAML" || printf '  ssh_creds:\n    - username: "root"\n      password: "ruadan-lab-probe"\n' )
crown_jewel:
  path: "/etc/passwd"
  min_bytes: 100
c2:
  listener_host: "${LHOST_IP}"
  listener_port: 4446
impact:
  allowed_services: []
limits:
  max_wall_clock_seconds: ${WALLCLOCK}
  ssh_connect_timeout: 15
  c2_callback_wait: 90
bruteforce:
  enabled: true
  users: ["root", "admin", "test", "pi", "ubuntu"]
  passwords: ["admin", "password", "root", "123456", "raspberry", "ubuntu", ""]
  max_attempts: 20
  services: ["ssh", "ftp", "mysql", "redis"]
EOF
echo "[0day] Inventory: ${INV_FILE} (seed=${SEED}, subnet=${SUBNET}, ${#IPS[@]} CIDRs /32 autorizados)"

# ---- 3. Invoca o ZeroDayHunter (PYTHONPATH do container já tem /app/red-mppo) --
cd /app/red-mppo 2>/dev/null || cd "$(dirname "$0")/.."
echo "[0day] Iniciando caçada (bateria determinística + LLM ${MODEL})..."
timeout $((WALLCLOCK + 240)) python3 -m services.pentest.app.zeroday_hunt \
    --inventory "$INV_FILE" \
    --i-am-authorized \
    --model "$MODEL" \
    --rounds "$ROUNDS" \
    --per-host-budget "$PER_HOST" \
    --llm-budget-reserve "${RUADAN_HUNT_LLM_RESERVE:-240}" \
    --wall-clock "$WALLCLOCK" \
    --runs-root "$HUNT_RUNS" 2>&1 | tail -20
RC=$?

# ---- 4. Parse do findings.json mais recente → marcadores da kill chain ---------
LATEST_RUN=$(ls -1dt "${HUNT_RUNS}"/*/ 2>/dev/null | head -1)
if [ -z "$LATEST_RUN" ] || [ ! -f "${LATEST_RUN}/findings.json" ]; then
    echo "[0day] Nenhum findings.json gerado (rc=${RC}) — verificando erro acima."
    rm -f "$INV_FILE"
    exit 0
fi
echo "[0day] === RESULTADO (${LATEST_RUN}) ==="
python3 - "$LATEST_RUN" <<'PYEOF'
import json, sys
run = sys.argv[1]
doc = json.load(open(f"{run}/findings.json", encoding="utf-8"))
c = doc.get("counts", {})
print(f"[0day] findings: {c.get('findings',0)} | CONFIRMADOS: {c.get('confirmed',0)} "
      f"| suspect: {c.get('suspect',0)} | FP descartados: {c.get('descartados_fp',0)}")
for cl in doc.get("classes_confirmadas", []):
    print(f"ZERODAY_CLASS_CONFIRMADA: {cl}")
for f in (doc.get("findings") or []):
    if f.get("verdict") == "confirmed":
        print(f"ZERODAY_FINDING: host={f.get('host')} class={f.get('class')} | {str(f.get('detail',''))[:140]}")
        if "shell" in str(f.get("class", "")).lower() or "remote_exec" in str(f):
            print(f"SHELL_OBTAINED: host={f.get('host')} | {str(f.get('detail',''))[:140]}")
        if "root" in str(f.get("class", "")).lower():
            print(f"ROOT_OBTAINED: host={f.get('host')} | {str(f.get('detail',''))[:140]}")
for ip, h in (doc.get("hosts") or {}).items():
    if h.get("outcome") == "SHELL_OBTAINED":
        print(f"SHELL_OBTAINED: host={ip} | {str(h.get('detail',''))[:140]}")
    for cred in (h.get("discovered_creds") or []):
        user = cred.get("username") or cred.get("user") or "?"
        print(f"CRED_DISCOVERED: host={ip} user={user} origem={cred.get('origin', cred.get('source','hunt'))}")
PYEOF
rm -f "$INV_FILE"
echo "[0day] Relatórios completos: ${LATEST_RUN}/hunt_report.md e findings.json"
exit 0
