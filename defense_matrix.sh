#!/bin/bash
# ==============================================================================
# Ruadan — Matriz Blue × Red (inteligência da defesa a partir do run real)
# ==============================================================================
# Uso: defense_matrix.sh [output_dir]
#   output_dir default: ${RUADAN_OUTPUT_DIR:-/ruadan/output}
#
# Consome os dados coletados PELA CAMPANHA (evasion_state.env de cada alvo +
# findings EMULATED_SERVICE/FIREWALL_DETECTED nos outputs das ferramentas) e
# produz:
#   1. INVENTÁRIO DE ADVERSÁRIOS — quem é real e quem é FITA (emulado)
#   2. HASHES, ORIGEM E DEPENDÊNCIAS — md5 por porta, cross-port e cross-host
#      (mesma fita servindo N portas/hosts), TTL mismatch, dependências da
#      defesa (chave de bloqueio, threshold, cooldown)
#   3. QUALIFICAÇÃO DE COMPETÊNCIA — score de sofisticação da defesa
#   4. MATRIZ BLUE × RED — capacidade azul × contramedida vermelha × cobertura
#   5. GAPS E RECOMENDAÇÕES
#
# Saída: stdout + <output_dir>/defense_matrix.md
# ==============================================================================
set -u

OUT="${1:-${RUADAN_OUTPUT_DIR:-/ruadan/output}}"
[ -d "$OUT" ] || { echo "[matrix][ERRO] output dir '$OUT' não existe"; exit 1; }
REPORT="$OUT/defense_matrix.md"
TS="$(date '+%Y-%m-%d %H:%M:%S')"

_sec() { echo ""; echo "## $1"; echo ""; }
_kv()  { printf '%s\n' "$1"; }

# ---------- Coleta ----------------------------------------------------------------
declare -a TARGETS=()
for st in "$OUT"/*/evasion_state.env; do
    [ -f "$st" ] || continue
    t=$(basename "$(dirname "$st")")
    TARGETS+=("$t")
done
[ "${#TARGETS[@]}" -gt 0 ] || { echo "[matrix] Nenhum evasion_state.env ainda — rode a campanha com [EVASION] enabled=1 primeiro."; exit 0; }

st_get() { grep -m1 "^$2=" "$OUT/$1/evasion_state.env" 2>/dev/null | cut -d= -f2-; }

{
echo "# Matriz Blue × Red — Ruadan × Defesa do Lab"
echo ""
echo "Gerada em: ${TS} | Fonte: ${OUT} | Alvos com estado: ${#TARGETS[@]}"
echo ""

# ============ 1. INVENTÁRIO ====================================================
_sec "1. INVENTÁRIO DE ADVERSÁRIOS (quem é real, quem é FITA)"
for t in "${TARGETS[@]}"; do
    em=$(st_get "$t" emulated_ports)
    fp=$(st_get "$t" defense_profile)
    req=$(st_get "$t" req_count)
    be=$(st_get "$t" blocked_events)
    th=$(st_get "$t" block_threshold_learned)
    cd=$(st_get "$t" cooldown_learned)
    ips=$(st_get "$t" ips_inline)
    echo "### ${t}"
    echo ""
    echo "| Campo | Valor |"
    echo "|---|---|"
    echo "| Requests consumidos (budget compartilhado) | ${req:-0} |"
    echo "| Bloqueios sofridos | ${be:-0} |"
    echo "| Threshold de bloqueio APRENDIDO | ${th:-(desconhecido — nenhum bloqueio ainda)} |"
    echo "| Cooldown APRENDIDO | ${cd:-(desconhecido)}s |"
    echo "| Perfil da defesa | ${fp:-(não fingerprintado ainda)} |"
    echo "| IPS inline (assinatura de payload) | ${ips:+SIM}${ips:-não detectado} |"
    echo "| Portas EMULADAS (fita — pular) | ${em:-nenhuma confirmada} |"
    # portas verificadas reais = chaves md5_<port> que NÃO estão em emulated_ports
    reais=""
    while IFS='=' read -r k v; do
        case "$k" in
            md5_*) p="${k#md5_}"
                case ",$em," in
                    *",$p,"*) : ;;
                    *) reais="${reais}${p} " ;;
                esac ;;
        esac
    done < "$OUT/$t/evasion_state.env"
    echo "| Portas verificadas REAIS | ${reais:-nenhuma verificada ainda} |"
    echo ""
done

# ============ 2. HASHES / ORIGEM / DEPENDÊNCIAS =================================
_sec "2. HASHES, ORIGEM E DEPENDÊNCIAS"
echo "### Hashes de corpo por porta (md5 de GET / — mesma hash = mesma fita/middleware)"
echo ""
echo "| Alvo:Porta | md5 de / |"
echo "|---|---|"
for t in "${TARGETS[@]}"; do
    grep -E '^md5_[0-9]+=' "$OUT/$t/evasion_state.env" 2>/dev/null | while IFS='=' read -r k v; do
        p="${k#md5_}"
        echo "| ${t}:${p} | \`${v}\` |"
    done
done
echo ""

# cross-port/cross-host: mesma hash servindo portas/hosts diferentes
echo "### Cross-referência (mesma hash em portas/hosts distintos = emulador centralizado)"
echo ""
xref=$(cat $(for t in "${TARGETS[@]}"; do echo "$OUT/$t/evasion_state.env"; done) 2>/dev/null \
    | grep -E '^md5_[0-9]+=' | sort -t= -k2 | awk -F= '{
        h[$2] = h[$2] (h[$2]==""?"":", ") $1
    } END { for (k in h) if (h[k] ~ /,/) print h[k] " -> " k }')
if [ -n "$xref" ]; then
    echo '```'
    echo "$xref"
    echo '```'
    echo "→ Fita CENTRALIZADA: o mesmo emulador serve múltiplas portas/hosts."
else
    echo "Nenhuma hash compartilhada (até agora) — emulação por porta/host isolada, ou só 1 porta verificada."
fi
echo ""

echo "### Origem (TTL mismatch — fita respondendo de hop/appliance distinto)"
echo '```'
grep -rh "EMULATED_SERVICE:.*ttl_mismatch" "$OUT" 2>/dev/null | sort -u | head -10
ttl_hits=$(grep -rh "EMULATED_SERVICE:.*ttl_mismatch" "$OUT" 2>/dev/null | wc -l)
[ "$ttl_hits" -eq 0 ] && echo "nenhum registro com ttl_mismatch (ainda)"
echo '```'
echo ""

echo "### Dependências da defesa (o que ela PRECISA para funcionar)"
echo ""
echo "| Dependência | Observado no run |"
echo "|---|---|"
nrot=0; for t in "${TARGETS[@]}"; do
    nrot=$(( nrot + $(grep -cE '^burned_' "$OUT/$t/evasion_state.env" 2>/dev/null || echo 0) ))
done
echo "| Chave de bloqueio | por IP de origem (conf. usuário) |"
echo "| Threshold de tentativas | ${th:-?} requests (aprendido) |"
echo "| Cooldown de desbloqueio | ${cd:-?}s (aprendido) |"
echo "| IPs que ela já queimou do nosso pool | ${nrot} |"

echo ""
echo "### Census adaptativo de armadilhas (aprendido em campo, zero hardcode)"
echo ""
echo "| Alvo | Traps | Vivas(REAL) | Fechadas | Threshold portas (oráculo) | Ofensores aposentados |"
echo "|---|---|---|---|---|---|"
for t in "${TARGETS[@]}"; do
    st="$OUT/$t/evasion_state.env"
    [ -f "$st" ] || continue
    ntrap=$(grep -cE '^tp_[0-9]+=trap$' "$st" 2>/dev/null); ntrap="${ntrap:-0}"
    nlive=$(grep -cE '^tp_[0-9]+=live$' "$st" 2>/dev/null); nlive="${nlive:-0}"
    nclosed=$(grep -cE '^tp_[0-9]+=closed$' "$st" 2>/dev/null); nclosed="${nclosed:-0}"
    ptl=$(grep -m1 '^porttouch_threshold_learned=' "$st" 2>/dev/null | cut -d= -f2-)
    noff=$(grep -cE '^offender_' "$st" 2>/dev/null || echo 0)
    echo "| ${t} | ${ntrap} | ${nlive} | ${nclosed} | ${ptl:-(desconhecido)} | ${noff} |"
done
echo ""

# ============ 3. QUALIFICAÇÃO DE COMPETÊNCIA =====================================
_sec "3. QUALIFICAÇÃO DE COMPETÊNCIA DA DEFESA (Blue)"
SCORE=0
em_any=""
TRAP_TOTAL=0
for t in "${TARGETS[@]}"; do
    em=$(st_get "$t" emulated_ports)
    [ -n "$em" ] && em_any="1"
    ntrap=$(grep -cE '^tp_[0-9]+=trap$' "$OUT/$t/evasion_state.env" 2>/dev/null); ntrap="${ntrap:-0}"
    TRAP_TOTAL=$((TRAP_TOTAL + ntrap))
done
[ -n "$em_any" ] && SCORE=$((SCORE+1)) && echo "- [+1] Emulação de portas/serviços presente (fita identificada e pulada)"
[ "$TRAP_TOTAL" -ge 2 ] && SCORE=$((SCORE+1)) && echo "- [+1] Census adaptativo confirmou ${TRAP_TOTAL} portas-armadilha (mesma resposta em N portas)"
[ -n "$xref" ]   && SCORE=$((SCORE+1)) && echo "- [+1] Fita centralizada (mesma hash em múltiplas portas/hosts)"
[ "${ttl_hits:-0}" -gt 0 ] && SCORE=$((SCORE+1)) && echo "- [+1] Fita em hop/appliance distinto (TTL mismatch)"
ips_any=""
for t in "${TARGETS[@]}"; do [ -n "$(st_get "$t" ips_inline)" ] && ips_any="1"; done
[ -n "$ips_any" ] && SCORE=$((SCORE+2)) && echo "- [+2] IPS inline com assinatura de payload (inspeção profunda)"
be_any=""
for t in "${TARGETS[@]}"; do [ "$(st_get "$t" blocked_events)" -gt 0 ] 2>/dev/null && be_any="1"; done
[ -n "$be_any" ] && SCORE=$((SCORE+1)) && echo "- [+1] Bloqueio adaptativo por IP em produção (nos bloqueou)"
th_min=""
for t in "${TARGETS[@]}"; do v=$(st_get "$t" block_threshold_learned); [ -n "$v" ] && { [ -z "$th_min" ] || [ "$v" -lt "$th_min" ] && th_min="$v"; }; done
[ -n "$th_min" ] && [ "$th_min" -le 30 ] && SCORE=$((SCORE+1)) && echo "- [+1] Threshold agressivo (≤30 requests por IP: ${th_min})"
cd_any=""
for t in "${TARGETS[@]}"; do v=$(st_get "$t" cooldown_learned); [ -n "$v" ] && [ "$v" -gt 0 ] && cd_any="$v"; done
[ -n "$cd_any" ] && [ "$cd_any" -le 300 ] && SCORE=$((SCORE+1)) && echo "- [+1] Recuperação rápida (cooldown ≤300s: ${cd_any}s)"
sd_any=""
for t in "${TARGETS[@]}"; do st_get "$t" defense_profile | grep -q "silent_drop" && sd_any="1"; done
[ -n "$sd_any" ] && SCORE=$((SCORE+1)) && echo "- [+1] Bloqueio silencioso (tarpit/drop — difícil de detectar sem janela)"
# escalonamento aprendido em campo: múltiplas ofensas do mesmo par
esc_any=""
for t in "${TARGETS[@]}"; do
    n_off=$(grep -cE '^offender_' "$OUT/$t/evasion_state.env" 2>/dev/null); n_off="${n_off:-0}"
    [ "$n_off" -ge 3 ] && esc_any="1"
done
[ -n "$esc_any" ] && SCORE=$((SCORE+1)) && echo "- [+1] Escalonamento de ofensas confirmado (≥3 IPs aposentados como reincidentes)"
echo ""
if   [ "$SCORE" -ge 9 ]; then NIVEL="ESPECIALISTA"
elif [ "$SCORE" -ge 7 ]; then NIVEL="AVANÇADA"
elif [ "$SCORE" -ge 5 ]; then NIVEL="INTERMEDIÁRIA"
elif [ "$SCORE" -ge 3 ]; then NIVEL="BÁSICA"
else NIVEL="NOVICE"; fi
echo "**SCORE: ${SCORE}/10 → Competência avaliada: ${NIVEL}**"
echo ""

# ============ 4. MATRIZ BLUE × RED ==============================================
_sec "4. MATRIZ BLUE × RED"
echo "| Capacidade Blue (defesa) | Contramedida Red (Ruadan) | Cobertura |"
echo "|---|---|---|
| Emulação de portas/serviços (fita) | emulation_check: TTL + timing + body-clone + cross-port → skip | $([ -n "$em_any" ] && echo "**COBERTO** (fita identificada e pulada)" || echo "AGUARDANDO DADOS") |
| Bloqueio por IP após X tentativas | Pool 192.168.50.240-249 + rotação proativa (70% do X aprendido) | $([ "$nrot" -gt 0 ] && echo "**COBERTO** (${nrot} queimas tratadas com rotação)" || echo "AGUARDANDO DADOS") |
| Contagem por IP (não por ferramenta) | Budget GLOBAL compartilhado entre todas as ferramentas | **COBERTO** (design) |
| Desbloqueio por cooldown | Cooldown APRENDIDO empiricamente (probe de re-disponibilidade) | $([ -n "$cd_any" ] && echo "**COBERTO** (aprendido: ${cd_any}s)" || echo "AGUARDANDO DADOS") |
| Bloqueio silencioso / drop | Janela deslizante de timeouts (000) + probe por lote | $([ -n "$sd_any" ] && echo "**COBERTO** (detectado)" || echo "COBERTO (design) — aguardando observação") |
| IPS inline (assinatura de payload) | defense_fingerprint detecta e reporta | **PARCIAL** — detecta; modo cauteloso de payload (encode/fragmentação) é pendência |
| Ofuscação de origem (hop distinto) | nping TTL vs ICMP por porta | $([ "${ttl_hits:-0}" -gt 0 ] && echo "**COBERTO** (${ttl_hits} registros)" || echo "COBERTO (design)") |
| Corpo idêntico p/ qualquer path | md5 clone + cross-referência de hashes | **COBERTO** (design) |
| Rate/timing como gatilho | Jitter 0.2-1.5s + rate 8/s + chunks com probe | **COBERTO** (design) |"
echo ""

# ============ 5. GAPS ============================================================
_sec "5. GAPS E RECOMENDAÇÕES"
echo "- [ ] IPS inline: implementar modo cauteloso de payload (encode/fragmentação) nos fuzzers"
echo "- [ ] sqlmap_login_probe e tools de exploit (MSF) ainda não são budget-aware"
echo "- [ ] TTL fingerprint da defesa em camada não-HTTP (nmap) — atual só cobre portas HTTP-candidatas"
echo "- [ ] Reexecutar este script ao final da campanha para a matriz final com dados completos"
echo ""

} | tee "$REPORT"

echo ""
echo "[matrix] Relatório salvo em: ${REPORT}"
exit 0
