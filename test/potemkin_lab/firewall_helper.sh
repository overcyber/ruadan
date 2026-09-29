#!/bin/bash
# ============================================================================
# Helper REAL de firewall para o lab de teste Potemkin (container, host netns).
# Implementa setup/block/unblock/cleanup com iptables de verdade — os drops
# precisam ser reais para o oráculo de ban (timeout do atacante) funcionar.
# LOG em /lab/potemkin_fw.log (block/unblock com timestamp) = ground truth.
# ============================================================================
set -u
LOG=/lab/potemkin_fw.log
cmd="$1"
case "$cmd" in
    setup)
        iptables -N POTEMKIN 2>/dev/null
        iptables -C INPUT -j POTEMKIN 2>/dev/null || iptables -I INPUT -j POTEMKIN
        echo "$(date +%s) SETUP" >> "$LOG"
        ;;
    block)
        # $3=ip $4=duração — loga o rc do iptables (falha silenciosa = oráculo cego)
        iptables -C POTEMKIN -s "$3" -j DROP 2>/dev/null || iptables -I POTEMKIN -s "$3" -j DROP 2>>"$LOG.err"
        echo "$(date +%s) BLOCK $3 $4 rc=$?" >> "$LOG"
        ;;
    unblock)
        iptables -D POTEMKIN -s "$3" -j DROP 2>/dev/null
        echo "$(date +%s) UNBLOCK $3" >> "$LOG"
        ;;
    cleanup)
        iptables -D INPUT -j POTEMKIN 2>/dev/null
        iptables -F POTEMKIN 2>/dev/null
        iptables -X POTEMKIN 2>/dev/null
        echo "$(date +%s) CLEANUP" >> "$LOG"
        ;;
esac
exit 0
