#!/usr/bin/env python3

from collections import defaultdict  
from email.utils import formatdate     
import concurrent.futures       
import subprocess                 
import threading                   
import selectors                  
import argparse                   
import logging                    
import random                     
import signal                     
import socket                     
import string                     
import struct                     
import json                       
import time                        
import sys                        
import os                         

__VERSION__ = "3.0.1"

# --------------------------------------------------------------------------
# Limite maximo de IPs distintos rastreados simultaneamente.
# Evita consumo exagerado de memoria sob ataque distribuido (DoS).
# --------------------------------------------------------------------------
_MAX_TRACKED_IPS = 50000


# =========================================================================
# CONFIGURACAO
# =========================================================================
#
# Valores padrao para todas as opcoes. Sao sobrescritos pelo arquivo
# JSON em /etc/potemkin/potemkin.conf (ou caminho indicado por -c).
# A funcao load_config() faz merge recursivo e validacao de tipos.
# =========================================================================

# --------------------------------------------------------------------------
# Caminhos where procurar o arquivo de config (em ordem de prioridade)
# --------------------------------------------------------------------------
CONFIG_PATHS = [
    "/etc/potemkin/potemkin.conf",
    "/etc/potemkin.conf",
    "/usr/local/etc/potemkin/potemkin.conf",
    os.path.expanduser("~/.config/potemkin/potemkin.conf"),
]

# --------------------------------------------------------------------------
# Caminhos onde procurar o arquivo de configuração
# --------------------------------------------------------------------------

CONFIG_PATHS = [
    "/etc/potemkin/potemkin.conf",
    "/etc/potemkin.conf",
    "/usr/local/etc/potemkin/potemkin.conf",
    os.path.expanduser("~/.config/potemkin/potemkin.conf"),
]
def load_config(path=None):
    """
    Carrega configuracao JSON diretamente do arquivo sem fallbacks hardcoded.
    Encerra a execucao se faltar configuracao ou se os valores forem invalidos.
    """
    cfg = {}

    # --- Busca automatica do arquivo de config se nenhum caminho foi dado ---
    if path is None:
        for candidate in CONFIG_PATHS:
            if os.path.isfile(candidate):
                path = candidate
                break

    # --- Leitura (obrigatoria) ---
    if not path or not os.path.isfile(path):
        print("[FATAL] Arquivo de configuracao nao encontrado. Abortando.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[FATAL] Nao foi possivel ler config {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    # --- Validacao rigorosa de tipos ---
    det = cfg.get("detection", {})
    rl = cfg.get("rate_limit", {})

    try:
        _validate_int(cfg, "max_threads", 1, 4096)
        _validate_int(cfg, "socket_timeout", 1, 30)
        _validate_int(det, "threshold", 1, 65535, parent_key="detection")
        _validate_int(det, "window", 5, 3600, parent_key="detection")
        _validate_int(det, "ban_duration", 10, 86400, parent_key="detection")
        _validate_int(det, "max_ban_duration", 10, 86400, parent_key="detection")
        _validate_int(rl, "max_connections", 5, 10000, parent_key="rate_limit")
        _validate_int(rl, "window", 1, 3600, parent_key="rate_limit")
    except ValueError as e:
        print(f"[FATAL] Erro na configuracao do potemkin.conf: {e}", file=sys.stderr)
        sys.exit(1)

    return cfg


def _validate_int(container, key, min_val, max_val, parent_key=None):
    """
    Validacao auxiliar: verifica se container[key] e um int dentro do range.
    Gera ValueError em caso de falta da chave ou formato incorreto.
    """
    if key not in container:
        full_key = f"{parent_key}.{key}" if parent_key else key
        raise ValueError(f"Chave obrigatoria ausente: '{full_key}'")
        
    val = container[key]
    full_key = f"{parent_key}.{key}" if parent_key else key
    if not isinstance(val, int) or val < min_val or val > max_val:
        raise ValueError(f"'{full_key}'={repr(val)} fora do limite ou tipo invalido. Use entre {min_val} e {max_val}.")
        
# =========================================================================
# SYSLOG - Cliente RFC 5424 para eventos JSON do honeypot
# =========================================================================
#
# Envia eventos estruturados em JSON via syslog UDP (porta 514) ou
# socket Unix (/dev/log). Usado pelo Wazuh para correlacionar alertas.
# =========================================================================

# Tabelas de mapeamento RFC 5424
_SYSLOG_FAC = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4,
    "syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9,
    "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

_SYSLOG_SEV = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}


class Syslog:
    """
    Cliente syslog minimalista que envia eventos JSON.
    Tenta socket Unix /dev/log primeiro (padrao Linux),
    com fallback para UDP 127.0.0.1:514.
    """

    def __init__(self, facility="local6", ident="potemkin"):
        self.facility = _SYSLOG_FAC.get(facility, 22)
        self.ident = ident
        self._sock = None

        # Tenta socket Unix (padrao em sistemas Linux)
        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self._sock.connect("/dev/log")
        except (OSError, FileNotFoundError):
            # Fallback: UDP para localhost
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.settimeout(2)
                self._addr = ("127.0.0.1", 514)
            except OSError:
                self._sock = None

    def _send(self, severity, msg):
        """Envia mensagem formatada RFC 5424 ao syslog."""
        if not self._sock:
            return
        try:
            pri = (self.facility * 8) + _SYSLOG_SEV.get(severity, 6)
            ts = formatdate(localtime=False, usegmt=True)
            frame = f"<{pri}>{ts} {self.ident}: {msg}"
            if self._sock.family == socket.AF_UNIX:
                self._sock.send(frame.encode("utf-8"))
            else:
                self._sock.sendto(frame.encode("utf-8"), self._addr)
        except OSError:
            pass

    def _json(self, event_type, **kw):
        """Constroi payload JSON compacto para o evento."""
        payload = {"event": event_type, "version": __VERSION__, "ts": time.time()}
        payload.update(kw)
        return json.dumps(payload, separators=(",", ":"))

    # --- API publica: um metodo por tipo de evento ---

    def connection(self, ip, port, service):
        """Log de conexao recebida (info)."""
        self._send("info", self._json("connection", src_ip=ip, dst_port=port, service=service))

    def scan_detected(self, ip, count, ports, ban_duration):
        """Log de portscan detectado (warning)."""
        self._send(
            "warning",
            self._json(
                "scan_detected",
                src_ip=ip,
                port_count=count,
                ports=ports[:50],  # Limita lista de portas para nao inundar
                ban_duration=ban_duration,
            ),
        )

    def ip_blocked(self, ip, duration, reason="portscan"):
        """Log de IP bloqueado (warning)."""
        self._send("warning", self._json("ip_blocked", src_ip=ip, duration=duration, reason=reason))

    def ip_unblocked(self, ip):
        """Log de IP desbloqueado apos expiracao (notice)."""
        self._send("notice", self._json("ip_unblocked", src_ip=ip))

    def close(self):
        """Fecha o socket syslog."""
        try:
            self._sock.close()
        except (OSError, AttributeError):
            pass


# =========================================================================
# FIREWALL - Wrapper para o helper privilegiado potemkin-firewall
# =========================================================================
#
# O processo potemkin roda como usuario 'potemkin' (sem root). Para
# manipular regras iptables, ele invoca o shell script
# /usr/local/bin/potemkin-firewall via sudo -n (no-interactive).
# O sudoers permite SOMENTE esse script com argumentos validados.
#
# SEGURANCA: O helper do shell faz propria validacao de IP e duracao.
# Aqui fazemos double-validation antes de chamar o helper.
# =========================================================================

class Firewall:
    """Wrapper para o shell helper potemkin-firewall (iptables-only)."""

    def __init__(self, helper="/usr/local/bin/potemkin-firewall", backend="iptables"):
        self.helper = helper
        # v3.0: backend e SEMPRE iptables. Ignora auto-detect.
        self._backend = backend
        self._chain = "POTEMKIN"
        self._ok = False

    @staticmethod
    def _valid_ip(ip):
        """
        Validacao rigorosa de IPv4.
        Rejeita qualquer coisa que nao seja 4 octetos decimais 0-255.
        SEGURANCA: Previne injection no comando iptables.
        """
        if not isinstance(ip, str):
            return False
        # Rejeita IPv6 (contem ':'), strings vazias, etc.
        if ':' in ip or len(ip) < 7 or len(ip) > 15:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            # Cada octeto: apenas digitos, sem zeros a esquerda extras,
            # sem sinal, sem espacos
            if not part.isdigit() or len(part) > 3:
                return False
            val = int(part)
            if val < 0 or val > 255:
                return False
        return True

    def _run(self, *args):
        """
        Executa o helper via sudo -n (non-interactive).
        Retorna True em sucesso, False em falha.
        Timeout de 5s previne hang no sudo.
        """
        cmd = ["sudo", "-n", self.helper] + list(args)
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5, check=False,
            )
            if r.returncode != 0:
                err = r.stderr.strip() if r.stderr else "erro desconhecido"
                logging.getLogger("potemkin").error(
                    "firewall cmd falhou (rc=%d): %s -> %s",
                    r.returncode, " ".join(args), err[:256],
                )
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            logging.getLogger("potemkin").error(
                "firewall cmd exception: %s -> %s", " ".join(args), exc
            )
            return False

    def init(self):
        """Cria chain POTEMKIN no iptables e adiciona jump da chain INPUT."""
        ok = self._run("setup", self._backend, self._chain)
        if not ok:
            logging.getLogger("potemkin").error(
                "Firewall setup FALHOU para backend=%s chain=%s", self._backend, self._chain
            )
        self._ok = ok
        return ok

    def block(self, ip, duration=600):
        """
        Bloqueia IP no iptables.
        - Valida IPv4 rigorosamente (anti-injection)
        - Limita duracao entre 1s e 86400s (1 dia)
        """
        if not self._valid_ip(ip):
            logging.getLogger("potemkin").warning("BLOCK IGNORADO: IP invalido '%s'", ip)
            return False
        if not isinstance(duration, int) or duration < 1:
            duration = 600
        if duration > 86400:
            duration = 86400
        ok = self._run("block", self._backend, ip, str(duration))
        if not ok:
            logging.getLogger("potemkin").error(
                "Firewall BLOCK FALHOU para %s (backend=%s)", ip, self._backend
            )
        return ok

    def unblock(self, ip):
        """
        Remove regra de bloqueio do IP no iptables.
        Valida IPv4 antes de chamar o helper.
        """
        if not self._valid_ip(ip):
            logging.getLogger("potemkin").warning("UNBLOCK IGNORADO: IP invalido '%s'", ip)
            return
        self._run("unblock", self._backend, ip)

    def cleanup(self):
        """Remove chain POTEMKIN inteira do iptables (usado no shutdown)."""
        self._run("cleanup", self._backend, self._chain)


# =========================================================================
# RATE LIMITER - Controle de taxa de conexoes por IP
# =========================================================================
#
# Usa bucket de timestamps: conta conexoes de cada IP dentro de uma
# janela de tempo. Se ultrapassar o limite, bloqueia via firewall
# e registra o ban para desbloqueio automatico futuro.
# =========================================================================

class RateLimiter:
    """Limitador de taxa de conexoes por IP (sliding window)."""

    def __init__(self, max_conn=30, window=10, ban_on_exceed=True, ban_duration=300):
        self.max_conn = max_conn          # Maximo de conexoes na janela
        self.window = window              # Janela de tempo (segundos)
        self.ban_on_exceed = ban_on_exceed
        self.ban_duration = ban_duration  # Duracao do bloqueio (segundos)
        self.buckets = defaultdict(list)  # ip -> [timestamp, ...]
        self.lock = threading.Lock()

    def check(self, ip):
        """
        Verifica se o IP esta dentro do limite.
        Retorna True se permitido, False se excedeu (e deve ser bloqueado).
        Thread-safe via lock.
        """
        now = time.time()
        with self.lock:
            # Remove timestamps fora da janela
            cutoff = now - self.window
            self.buckets[ip] = [t for t in self.buckets[ip] if t > cutoff]

            if len(self.buckets[ip]) >= self.max_conn:
                if self.ban_on_exceed:
                    del self.buckets[ip] # EM VEZ DE self.buckets[ip].clear()
                return False            

            #if len(self.buckets[ip]) >= self.max_conn:
            #    if self.ban_on_exceed:
            #        self.buckets[ip].clear()  # Zera contagem apos trigger
            #    return False

            self.buckets[ip].append(now)
            return True

    def cleanup_loop(self, interval=30):
        while True:
            time.sleep(interval)
            now = time.time()
            with self.lock:
                cutoff = now - self.window
                for ip in list(self.buckets):
                    self.buckets[ip] = [t for t in self.buckets[ip] if t > cutoff]
                    if not self.buckets[ip]:
                        del self.buckets[ip]  # ESTA LINHA JÁ ESTÁ CERTA NO SEU CÓDIGO

     #def cleanup_loop(self, interval=30):
     #   """
     #   Thread de background: remove buckets vazios periodicamente.
     #   Previne consumo de memoria com muitos IPs inativos.
     #   """
     #   while True:
     #       time.sleep(interval)
     #       now = time.time()
     #       with self.lock:
     #           cutoff = now - self.window
     #           for ip in list(self.buckets):
     #               self.buckets[ip] = [t for t in self.buckets[ip] if t > cutoff]
     #               if not self.buckets[ip]:
     #                   del self.buckets[ip]


# =========================================================================
# DETECTOR DE PORTSCAN - Janela deslizante com ban escalonado
# =========================================================================
#
# Logica central do sistema:
# 1. Cada conexao e registrada com (IP, porta, timestamp)
# 2. Se um IP tocar em >= threshold portas unicas dentro da janela,
#    ele e bloqueado e banido por ban_duration segundos
# 3. Ofensas repetidas escalonam: 1a=10min, 2a=30min, 3a+=1h
# 4. Bans expiram automaticamente; o callback on_expire remove
#    a regra do firewall e emite syslog
#
# SEGURANCA v3.0:
# - Callbacks (on_detect, on_expire) sao chamados FORA do lock
#   para evitar deadlock com subprocess de firewall
# - Limite de IPs rastreados para evitar DoS por memoria
# - IPv6 e rejeitado silenciosamente (nao e suportado pelo iptables)
# =========================================================================

class Detector:
    """Detector de portscan com janela deslizante e ban escalonado."""

    def __init__(self, threshold=10, window=60, ban_duration=600,
                 escalation=True, max_ban_duration=86400,
                 on_detect=None, on_expire=None):
        # --- Parametros de configuracao ---
        self.threshold = threshold          # Portas unicas para acionar
        self.window = window                # Janela de tempo (segundos)
        self.ban_dur = ban_duration         # Duracao base do bloqueio
        self.escalation = escalation        # Ativar escalonamento
        self.max_ban_dur = max_ban_duration # Teto maximo de ban

        # --- Callbacks (chamados FORA do lock) ---
        self.on_detect = on_detect  # (ip, count, ports, duration)
        self.on_expire = on_expire  # (ip,)

        # --- Estado interno ---
        self.hits = defaultdict(list)       # ip -> [timestamps]
        self.ports_seen = defaultdict(set)   # ip -> {porta, ...}
        self.blocked = {}                    # ip -> timestamp_unblock
        self.offenses = defaultdict(int)     # ip -> numero de ofensas
        self.lock = threading.Lock()

    def record(self, ip, port):
        """
        Registra uma conexao do IP na porta.
        Retorna True se acabou de acionar um bloqueio (caller deve agir).
        Retorna False se o IP ja esta bloqueado ou nao atingiu threshold.

        SEGURANCA: Callbacks sao chamados FORA do lock para evitar
        deadlock com subprocess de firewall (sudo iptables).
        """
        now = time.time()

        # ---- FASE 1: Verificacao inside lock (rapida) ----
        expired_ips = []     # IPs cujo ban expirou
        triggered = False
        trigger_info = None  # (ip, count, ports, duration)

        with self.lock:
            # Rejeita IPv6: o iptables nativo nao suporta, nao rastreie
            if ':' in ip:
                return False

            # Limite de IPs rastreados (anti-DoS por memoria)
            if (ip not in self.hits and ip not in self.blocked
                    and len(self.hits) + len(self.blocked) >= _MAX_TRACKED_IPS):
                return False

            # Verifica se IP ja esta bloqueado
            if ip in self.blocked:
                if now < self.blocked[ip]:
                    return False  # Ainda bloqueado, ignora
                else:
                    # Ban expirou! Remove e agenda unban
                    del self.blocked[ip]
                    expired_ips.append(ip)

            # Registra hit e porta
            self.hits[ip].append(now)
            self.ports_seen[ip].add(port)

            # Remove hits antigos fora da janela
            cutoff = now - self.window
            self.hits[ip] = [t for t in self.hits[ip] if t > cutoff]
            # Se nao restaram hits, reseta portas vistas tambem
            if not self.hits[ip]:
                self.ports_seen[ip].clear()

            # Verifica se atingiu threshold de portas unicas
            unique = len(self.ports_seen[ip])
            if unique >= self.threshold:
                duration = self._ban(ip)
                trigger_info = (ip, unique, sorted(self.ports_seen[ip]), duration)
                triggered = True

        # ---- FASE 2: Callbacks OUTSIDE do lock (anti-deadlock) ----
        #
        # Os callbacks podem chamar subprocess.run() (sudo iptables)
        # que leva ate 5s. Chamar dentro do lock travaria o detector
        # para todos os outros IPs durante esse tempo.

        # Desbloqueia IPs cujo ban expirou
        for exp_ip in expired_ips:
            if self.on_expire:
                self.on_expire(exp_ip)

        # Aciona bloqueio para novo scanner detectado
        if triggered and trigger_info and self.on_detect:
            self.on_detect(*trigger_info)

        return triggered

    def is_blocked(self, ip):
        """
        Verificacao rapida sem lock (best-effort).
        Usada no hotpath de aceitar conexoes para rejeitar rapido.
        """
        if ip in self.blocked:
            if time.time() < self.blocked[ip]:
                return True
        return False

    def add_rate_ban(self, ip, duration):
        """
        Adiciona ban de rate limit ao dicionario blocked.
        Assim o cleanup_loop existente tambem faz unban automatico
        de bans por rate limit, sem precisar de mecanismo separado.
        Chamado pelo Potemkin quando rate limit e excedido.
        """
        with self.lock:
            self.blocked[ip] = time.time() + duration

    def _ban(self, ip):
        """
        Calcula duracao do ban com escalonamento e registra no dict.
        Retorna a duracao aplicada.

        Escalonamento:
          1a ofensa: ban_duration (10 min)
          2a ofensa: ban_duration * 3 (30 min)
          3a+ ofensas: ban_duration * 6 (1 hora), teto em max_ban_duration
        """
        if self.escalation:
            self.offenses[ip] += 1
            n = self.offenses[ip]
            if n == 1:
                dur = self.ban_dur
            elif n == 2:
                dur = min(self.ban_dur * 3, self.max_ban_dur)  # 30 min
            else:
                dur = min(self.ban_dur * 6, self.max_ban_dur)  # 1 hora
        else:
            dur = self.ban_dur

        self.blocked[ip] = time.time() + dur

        # Reseta tracking da janela para comecar limpo
        self.hits[ip].clear()
        self.ports_seen[ip].clear()

        return dur

    def cleanup_loop(self, interval=60):
        """
        Thread de background: expira bans antigos e limpa entries inuteis.
        Roda a cada 60 segundos.

        SEGURANCA: Callbacks on_expire sao chamados FORA do lock.
        """
        while True:
            time.sleep(interval)
            now = time.time()

            with self.lock:
                # Coleta IPs com ban expirado
                expired = [ip for ip, t in self.blocked.items() if now >= t]
                for ip in expired:
                    del self.blocked[ip]

                # Limpa hits antigos (janela x2 para margem)
                cutoff = now - self.window * 2
                for ip in list(self.hits):
                    self.hits[ip] = [t for t in self.hits[ip] if t > cutoff]
                    if not self.hits[ip] and ip not in self.blocked:
                        del self.hits[ip]
                        if ip in self.ports_seen:
                            del self.ports_seen[ip]

            # Callbacks FORA do lock (anti-deadlock com subprocess)
            if expired and self.on_expire:
                for ip in expired:
                    self.on_expire(ip)

    def get_stats(self):
        """
        Retorna estatisticas atuais (thread-safe via copia).
        Usado para monitoramento e debugging.
        """
        with self.lock:
            return {
                "tracked_ips": len(self.hits),
                "blocked_ips": len(self.blocked),
                "total_offenses": dict(self.offenses),
            }


# =========================================================================
# RESPONDERS - Simulacao de servicos de rede
# =========================================================================
#
# Cada classe simula um servico de rede diferente. Quando um scanner
# conecta a uma porta, o responder correspondente envia banners e
# respostas realistas para enganar o atacante e aumentar o tempo
# gasto, enquanto o detector analisa o padrao de portas tocadas.
#
# SEGURANCA v3.0:
# - Limite de 4KB por recv (anti-buffer overflow)
# - EchoResp/ChargenResp com limite de bytes enviados (anti-amplificacao)
# - Timeouts curtos (1-3s) previnem holding de threads
# - Todas as excecoes sao capturadas (nunca crasha o handler)
# =========================================================================

# --------------------------------------------------------------------------
# Banners realistas para servicos comuns (rotacionados aleatoriamente)
# --------------------------------------------------------------------------
_SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2\r\n",
    b"SSH-2.0-OpenSSH_8.9p1 Debian-3+deb12u1\r\n",
    b"SSH-2.0-OpenSSH_8.4p1\r\n",
    b"SSH-2.0-dropbear_2022.83\r\n",
    b"SSH-2.0-libssh_0.10.4\r\n",
    b"SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu7.3\r\n",
]

_HTTP_SERVERS = [
    "Apache/2.4.57 (Ubuntu)",
    "Apache/2.4.54 (Debian)",
    "Apache/2.4.52 (Unix)",
    "nginx/1.22.0",
    "nginx/1.24.0",
]

_MYSQL_VERSIONS = [
    b"8.0.35-0ubuntu0.22.04.1",
    b"8.0.33-0ubuntu0.22.04.1",
    b"5.7.42-0ubuntu0.18.04.1",
    b"8.1.0-1ubuntu2",
]

# Limite maximo de bytes enviados por conexao (anti-amplificacao DoS)
# Evita que EchoResp/ChargenResp consumam banda excessiva
_MAX_SEND_BYTES = 8192  # 8KB por conexao


class SSHResp:
    """Simula servidor SSH: envia banner, recebe client hello, responde mismatch."""
    service = "ssh"

    def handle(self, sock):
        try:
            sock.settimeout(2)
            sock.send(random.choice(_SSH_BANNERS))
            data = sock.recv(1024)
            if data:
                time.sleep(0.1)  # Simula latencia
                sock.sendall(
                    b"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2\r\n"
                    b"Protocol mismatch.\r\n"
                )
        except (OSError, socket.timeout):
            pass


class FTPResp:
    """Simula servidor FTP (vsftpd): responde comandos com erros reais."""
    service = "ftp"

    def handle(self, sock):
        try:
            sock.settimeout(3)
            sock.sendall(b"220 Welcome to vsftpd 3.0.5 (Ubuntu)\r\n")
            for _ in range(5):  # Max 5 comandos
                data = sock.recv(1024)
                if not data:
                    break
                cmd = data.decode("utf-8", errors="replace").strip().upper()
                if cmd.startswith("USER"):
                    sock.sendall(b"331 Please specify the password.\r\n")
                elif cmd.startswith("PASS"):
                    sock.sendall(b"530 Permission denied.\r\n")
                    break
                elif cmd.startswith("QUIT"):
                    sock.sendall(b"221 Goodbye.\r\n")
                    break
                elif cmd.startswith("SYST"):
                    sock.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd.startswith("FEAT"):
                    sock.sendall(
                        b"211-Features:\r\n"
                        b" EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n"
                        b" REST\r\n SIZE\r\n UTF8\r\n"
                        b"211 End\r\n"
                    )
                else:
                    sock.sendall(b"530 Please login first.\r\n")
        except (OSError, socket.timeout):
            pass


class SMTPResp:
    """Simula servidor SMTP (Postfix): responde com erro 502 para comandos invalidos."""
    service = "smtp"

    def handle(self, sock):
        try:
            sock.settimeout(3)
            sock.sendall(b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n")
            for _ in range(6):
                data = sock.recv(1024)
                if not data:
                    break
                line = data.decode("utf-8", errors="replace").strip().upper()
                if line.startswith("EHLO") or line.startswith("HELO"):
                    sock.sendall(
                        b"250-mail.example.com\r\n"
                        b"250-PIPELINING\r\n"
                        b"250-SIZE 10240000\r\n"
                        b"250-VRFY\r\n"
                        b"250-ETRN\r\n"
                        b"250-STARTTLS\r\n"
                        b"250-ENHANCEDSTATUSCODES\r\n"
                        b"250-8BITMIME\r\n"
                        b"250 DSN\r\n"
                    )
                elif line.startswith("MAIL FROM"):
                    sock.sendall(b"250 2.1.0 Ok\r\n")
                elif line.startswith("RCPT TO"):
                    sock.sendall(b"250 2.1.5 Ok\r\n")
                elif line.startswith("DATA"):
                    sock.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                elif line == ".":
                    sock.sendall(b"250 2.0.0 Ok: queued as ABC123\r\n")
                elif line.startswith("QUIT"):
                    sock.sendall(b"221 2.0.0 Bye\r\n")
                    break
                elif line.startswith("NOOP"):
                    sock.sendall(b"250 2.0.0 Ok\r\n")
                elif line.startswith("RSET"):
                    sock.sendall(b"250 2.0.0 Ok\r\n")
                else:
                    sock.sendall(b"502 5.5.2 Command not implemented\r\n")
        except (OSError, socket.timeout):
            pass


class TelnetResp:
    """Simula login Telnet: pede usuario/senha, sempre rejeita."""
    service = "telnet"

    def handle(self, sock):
        try:
            sock.settimeout(3)
            # Negociacao Telnet (RFC 854)
            sock.sendall(
                b"\xff\xfb\x18\xff\xfb\x1f\xff\xfb\x20\xff\xfb\x21"
                b"\xff\xfb\x22\xff\xfb\x27\xff\xfd\x18\xff\xfd\x1f"
            )
            sock.sendall(
                b"\r\nUbuntu 22.04.3 LTS\r\n"
                b"login: "
            )
            for _ in range(3):
                data = sock.recv(1024)
                if not data:
                    break
                cleaned = data.replace(b"\xff\xfc", b"").replace(b"\xff\xfe", b"")
                cleaned.decode("utf-8", errors="replace").strip()
                sock.sendall(b"Password: ")
                data = sock.recv(1024)
                if not data:
                    break
                sock.sendall(
                    b"\r\nLogin incorrect\r\n\r\nlogin: "
                )
        except (OSError, socket.timeout):
            pass


class HTTPResp:
    """Simula servidor HTTP: retorna pagina default do Apache."""
    service = "http"

    def handle(self, sock):
        srv = random.choice(_HTTP_SERVERS)
        try:
            sock.settimeout(3)
            data = sock.recv(4096)
            if not data:
                return
            req = data.decode("utf-8", errors="replace").splitlines()
            if not req:
                return
            parts = req[0].split()
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
            if method == "HEAD":
                body = b""
            elif path == "/robots.txt":
                body = b"User-agent: *\r\nDisallow: /\r\n"
            else:
                body = (
                    b"<!DOCTYPE html>\r\n"
                    b"<html><head><title>Apache2 FreeBSD Default Page</title></head>\r\n"
                    b"<body><h1>Apache2 FreeBSD Default Page</h1>"
                    b"<p>It works!</p></body></html>\r\n"
                )

            header = (
                f"HTTP/1.1 200 OK\r\n"
                f"Date: {now}\r\n"
                f"Server: {srv}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Type: text/html; charset=UTF-8\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("utf-8")
            sock.sendall(header + body)
        except (OSError, socket.timeout):
            pass


class MySQLResp:
    """Simula handshake MySQL: envia greeting, recebe auth, responde access denied."""
    service = "mysql"

    def handle(self, sock):
        try:
            sock.settimeout(2)
            version = random.choice(_MYSQL_VERSIONS)

            # --- Construcao do Greeting Packet (MySQL Protocol 10) ---
            plugin = b"mysql_native_password"
            salt = os.urandom(20)  # Salt aleatorio (criptograficamente seguro)
            packet = bytearray()
            packet.append(10)          # Versao do protocolo
            packet.extend(version)
            packet.append(0x00)       # Null terminator
            packet.extend(struct.pack("<I", random.randint(1, 65535)))  # Thread ID
            packet.extend(salt[:8])   # Salt parte 1
            packet.extend(struct.pack("<H", 0xF7FF))  # Capabilities
            packet.append(0x21)       # Charset (utf8)
            packet.extend(b"\x02\x00" + b"\xff\xf7")  # Status + upper caps
            packet.extend(salt[8:])   # Salt parte 2
            packet.append(0x00)       # Filler
            packet.extend(plugin)
            packet.append(0x00)       # Null terminator

            # Header MySQL: 3 bytes de tamanho + 1 byte de sequencia
            hdr = struct.pack("<I", len(packet))[0:3] + b"\x00"
            sock.sendall(hdr + bytes(packet))

            # Le resposta de autenticacao
            try:
                data = sock.recv(4096)
                if len(data) >= 5:
                    # ER_ACCESS_DENIED_ERROR (codigo 1045)
                    err = (
                        b"\xff"
                        b"\x15"  # Error code (1045 LE)
                        b"#28000"  # SQL state
                        b"Access denied for user ''@'localhost'"
                        b" (using password: NO)"
                    )
                    err_hdr = struct.pack("<I", len(err))[0:3] + b"\x01"
                    sock.sendall(err_hdr + err)
            except (OSError, socket.timeout):
                pass
        except (OSError, socket.timeout):
            pass


class MSSQLResp:
    """Simula resposta pre-login MSSQL (TDS)."""
    service = "mssql"

    def handle(self, sock):
        try:
            sock.settimeout(2)
            # Pre-login packet TDS
            pkt = bytearray()
            pkt.append(0x12)          # Versao major
            pkt.append(0x00)          # Versao minor
            pkt.extend(b"\x00\x00")   # Build
            pkt.extend(b"\x00\x00\x00\x00\x00\x00")  # Padding + encryption
            pkt.extend(b"\x00\x00")   # Instance ID
            pkt.append(0x01)          # Terminator

            # TDS header wrapper
            tds = bytearray()
            tds.extend(struct.pack("<H", len(pkt) + 8))  # Tamanho total
            tds.append(0x04)          # Tipo = pre-login
            tds.append(0x01)          # Status
            tds.extend(b"\x00\x00")   # SPID
            tds.extend(pkt)
            sock.sendall(bytes(tds))
        except (OSError, socket.timeout):
            pass


class POP3Resp:
    """Simula servidor POP3 (Dovecot): aceita USER, rejeita PASS."""
    service = "pop3"

    def handle(self, sock):
        try:
            sock.settimeout(3)
            sock.sendall(b"+OK Dovecot ready.\r\n")
            for _ in range(4):
                data = sock.recv(1024)
                if not data:
                    break
                cmd = data.decode("utf-8", errors="replace").strip().upper()
                if cmd.startswith("USER"):
                    sock.sendall(b"+OK\r\n")
                elif cmd.startswith("PASS"):
                    sock.sendall(b"-ERR [AUTH] Authentication failed.\r\n")
                    break
                elif cmd.startswith("QUIT"):
                    sock.sendall(b"+OK Logging out.\r\n")
                    break
                elif cmd.startswith("CAPA"):
                    sock.sendall(
                        b"+OK\r\nTOP\r\nUSER\r\nUIDL\r\nSTLS\r\n.\r\n"
                    )
                elif cmd.startswith("STAT"):
                    sock.sendall(b"+OK 0 0\r\n")
                elif cmd.startswith("NOOP"):
                    sock.sendall(b"+OK\r\n")
                else:
                    sock.sendall(b"-ERR Unknown command.\r\n")
        except (OSError, socket.timeout):
            pass


class IMAPResp:
    """
    Simula servidor IMAP (Dovecot).
    SEGURANCA: Sanitiza tag do cliente para impedir injection em respostas.
    """
    service = "imap"

    def handle(self, sock):
        try:
            sock.settimeout(3)
            sock.sendall(
                b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS "
                b"ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] "
                b"Dovecot ready.\r\n"
            )
            for _ in range(4):
                data = sock.recv(1024)
                if not data:
                    break
                line = data.decode("utf-8", errors="replace").strip()
                parts = line.split(None, 1)
                # Sanitiza tag: permite apenas alfanumericos e poucos simbolos
                tag = parts[0] if parts else "*"
                tag = "".join(c for c in tag if c.isalnum() or c in "._-+")
                cmd = parts[1].upper() if len(parts) > 1 else ""

                if cmd.startswith("CAPABILITY"):
                    sock.sendall(
                        b"* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS "
                        b"ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN\r\n"
                        + f"{tag} OK Capability completed.\r\n".encode()
                    )
                elif cmd.startswith("LOGIN"):
                    sock.sendall(
                        f"{tag} NO [AUTHENTICATIONFAILED] "
                        f"Authentication failed.\r\n".encode()
                    )
                    break
                elif cmd.startswith("LOGOUT"):
                    sock.sendall(
                        f"* BYE Logging out\r\n{tag} OK Logout completed.\r\n".encode()
                    )
                    break
                elif cmd.startswith("NOOP"):
                    sock.sendall(f"{tag} OK NOOP completed.\r\n".encode())
                elif cmd.startswith("ID"):
                    sock.sendall(f"* ID NIL\r\n{tag} OK ID completed.\r\n".encode())
                else:
                    sock.sendall(f"{tag} BAD Unknown command.\r\n".encode())
        except (OSError, socket.timeout):
            pass


class LDAPResp:
    """Simula resposta LDAP Bind: retorna protocolError."""
    service = "ldap"

    def handle(self, sock):
        try:
            sock.settimeout(2)
            data = sock.recv(4096)
            if not data:
                return
            # Resposta LDAP: BindResponse com protocolError (resultCode 80)
            resp = bytearray()
            resp.extend(b"\x30\x0c")      # SEQUENCE, length 12
            resp.extend(b"\x02\x01\x01")  # messageID = 1
            resp.extend(b"\x61\x07")      # BindResponse, length 7
            resp.extend(b"\x0a\x01\x50")  # resultCode = protocolError
            resp.extend(b"\x04\x00")      # matchedDN = ""
            resp.extend(b"\x04\x00")      # diagnosticMessage = ""
            sock.sendall(bytes(resp))
        except (OSError, socket.timeout):
            pass


class NTPResp:
    """Simula servidor NTP: responde com stratum 2."""
    service = "ntp"

    def handle(self, sock):
        try:
            data = sock.recv(1024)
            if not data or len(data) < 48:
                return
            # Monta resposta NTP (48 bytes)
            resp = bytearray(48)
            resp[0] = 0x1C   # LI=0, VN=3, Mode=4 (server)
            resp[1] = 2       # Stratum 2
            resp[2] = 6       # Poll interval
            resp[3] = 0xEC    # Precision

            now = int(time.time()) + 2208988800  # Offset NTP epoch (1900 vs 1970)
            struct.pack_into("!I", resp, 16, now)  # Reference timestamp
            struct.pack_into("!I", resp, 20, 0)     # Root delay
            resp[24:32] = data[24:32]  # Originate timestamp (echo)

            t = time.time() + 2208988800
            resp[40:44] = struct.pack("!I", int(t))           # Transmit ts (s)
            resp[44:48] = struct.pack("!I", int((t % 1) * 2**32))  # Transmit ts (us)
            sock.sendall(bytes(resp))
        except (OSError, socket.timeout):
            pass


class RPCBindResp:
    """Simula resposta RPC bind minimal."""
    service = "rpcbind"

    def handle(self, sock):
        try:
            sock.settimeout(2)
            data = sock.recv(4096)
            if not data or len(data) < 12:
                return
            resp = bytearray()
            resp.extend(b"\x80\x00\x00\x28")  # Record marker
            resp.extend(b"\x00\x00\x00\x00")  # XID
            resp.extend(b"\x00\x00\x00\x01")  # Reply
            resp.extend(b"\x00\x00\x00\x00")  # Void
            resp.extend(b"\x00\x00\x00\x00")  # Accept
            resp.extend(b"\x00\x00\x00\x00")  # Void
            resp.extend(b"\x00\x00\x00\x02")
            resp.extend(b"\x00\x00\x00\x00")
            resp.extend(b"\x00\x00\x00\x00")
            resp.extend(b"\x00\x00\x00\x00")
            sock.sendall(bytes(resp))
        except (OSError, socket.timeout):
            pass


class SOCKSResp:
    """Simula proxy SOCKS4/5: aceita conexao, rejeita com falha."""
    service = "socks"

    def handle(self, sock):
        try:
            sock.settimeout(3)
            data = sock.recv(1024)
            if not data:
                return
            if data[0] == 0x05:  # SOCKS5
                sock.sendall(b"\x05\x00")  # No auth
                try:
                    req = sock.recv(1024)
                    if req and len(req) >= 7:
                        sock.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                except (OSError, socket.timeout):
                    pass
            elif data[0] == 0x04:  # SOCKS4
                sock.sendall(b"\x00\x5a\x00\x00\x00\x00\x00\x00")
        except (OSError, socket.timeout):
            pass


class DNSResp:
    """Simula servidor DNS: responde com SERVFAIL + eco da query."""
    service = "dns"

    def handle(self, sock):
        try:
            sock.settimeout(2)
            data = sock.recv(1024)
            if not data or len(data) < 12:
                return
            tid = data[0:2]
            flags = b"\x81\x83"  # Response + RD + RA + SERVFAIL
            resp = (
                tid + flags
                + b"\x00\x01"  # QDCOUNT
                + b"\x00\x00"  # ANCOUNT
                + b"\x00\x00"  # NSCOUNT
                + b"\x00\x00"  # ARCOUNT
            )
            if len(data) > 12:
                resp += data[12:]  # Eco da question section
            sock.sendall(resp)
        except (OSError, socket.timeout):
            pass


class EchoResp:
    """
    Simula servico Echo (RFC 862).
    SEGURANCA v3.0: Limita bytes enviados para previnir amplificacao DoS.
    Atacantes podiam usar Echo para refletir trafego e consumir banda.
    """
    service = "echo"

    def handle(self, sock):
        try:
            sock.settimeout(2)
            total_sent = 0
            while total_sent < _MAX_SEND_BYTES:
                data = sock.recv(4096)
                if not data:
                    break
                sock.sendall(data)
                total_sent += len(data)
        except (OSError, socket.timeout):
            pass


class ChargenResp:
    """
    Simula servico Chargen (RFC 864).
    SEGURANCA v3.0: Limita bytes enviados para previnir amplificacao DoS.
    Chargen e um servico classico de amplificacao (gera dados infinitos).
    """
    service = "chargen"

    def handle(self, sock):
        try:
            sock.settimeout(1)
            chars = string.ascii_uppercase + string.digits + string.punctuation
            n = random.randint(0, len(chars))
            total_sent = 0
            while total_sent < _MAX_SEND_BYTES:
                chunk = "".join(chars[(n + i) % len(chars)] for i in range(72))
                sock.sendall((chunk + "\r\n").encode("ascii"))
                total_sent += 74  # 72 chars + \r\n
                n = (n + 1) % len(chars)
                time.sleep(0.05)
        except (OSError, socket.timeout):
            pass


class HTTPSResp:
    """Simula HTTPS: recebe TLS ClientHello, responde com close_notify alert."""
    service = "https"

    def handle(self, sock):
        try:
            sock.settimeout(2)
            data = sock.recv(4096)
            if not data:
                return
            # Verifica se parece TLS (byte 0x16 = handshake)
            if len(data) >= 3 and data[0] == 0x16:
                alert = bytes([
                    0x15, 0x03, 0x03, 0x00, 0x02,  # TLS record header
                    0x01, 0x00,                       # Warning + close_notify
                ])
                sock.sendall(alert)
        except (OSError, socket.timeout):
            pass


class NullResp:
    """Simula servico Null (discards data)."""
    service = "null"

    def handle(self, sock):
        try:
            sock.settimeout(3)
            while True:
                data = sock.recv(4096)
                if not data:
                    break
        except (OSError, socket.timeout):
            pass


class BannerResp:
    """Responder generico que envia um banner estatico."""
    service = "banner"

    def __init__(self, banner=""):
        self.banner = banner if isinstance(banner, bytes) else banner.encode("utf-8")

    def handle(self, sock):
        try:
            sock.settimeout(3)
            sock.sendall(self.banner)
            time.sleep(0.1)
        except (OSError, socket.timeout):
            pass


# =========================================================================
# MAPA DE PORTAS - Mapeamento port -> responder
# =========================================================================
#
# Cobertura de 1000+ portas TCP comumente escaneadas.
# Cada porta aponta para um responder que simula o servico esperado.
# =========================================================================

def build_port_map():
    """
    Constroi e retorna o dicionario {porta: responder_instance}.
    Cada porta aponta para um objeto responsavel por simular o servico.
    """
    # Instancia unica de cada responder (reutilizada entre portas)
    ssh = SSHResp()
    ftp = FTPResp()
    smtp = SMTPResp()
    telnet = TelnetResp()
    http = HTTPResp()
    mysql = MySQLResp()
    mssql = MSSQLResp()
    pop3 = POP3Resp()
    imap = IMAPResp()
    ldap = LDAPResp()
    ntp = NTPResp()
    rpcbind = RPCBindResp()
    socks = SOCKSResp()
    dns = DNSResp()
    echo = EchoResp()
    chargen = ChargenResp()
    https = HTTPSResp()
    null = NullResp()

    pm = {}

    # --- Portas exclusivas (uma porta por servico) ---
    singles = {
        7: echo,
        9: chargen,
        13: BannerResp(b"Mon DD HH:MM:SS YYYY\r\n"),
        17: BannerResp(b"\"\\x22\"\\r\\n"),
        19: chargen,
        21: ftp,
        22: ssh,
        23: telnet,
        25: smtp,
        53: dns,
        79: BannerResp(b"finger: no such user\r\n"),
        80: http,
        88: BannerResp(b"\x00\x00\x00\x01\x00\x00\x00\x01"),
        110: pop3,
        111: rpcbind,
        113: BannerResp(b""),
        119: BannerResp(b"200 news.example.com NNRP service ready (posting ok).\r\n"),
        123: ntp,
        135: BannerResp(b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00"
                         b"\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00"
                         b"\x01\x00\x00\x00\x00\x00\x05\x00"),
        137: BannerResp(b""),
        138: BannerResp(b""),
        139: BannerResp(b"\x00\x00\x00\x00"),
        143: imap,
        161: BannerResp(b""),
        179: BannerResp(b""),
        389: ldap,
        443: https,
        445: BannerResp(b""),
        465: smtp,
        514: BannerResp(b"<155>Jun 01 12:00:00 host rsyslogd: "
                         b"[origin software=\"rsyslogd\" swVersion=\"8.2112.0\"]\r\n"),
        515: BannerResp(b""),          # LPD
        530: BannerResp(b"\x00"),      # RPC
        543: BannerResp(b""),          # klogin
        544: BannerResp(b""),          # kshell
        548: BannerResp(b""),          # AFP
        554: BannerResp(b""),          # RTSP
        587: smtp,                      # Submission
        593: BannerResp(b""),          # HTTP RPC
        623: BannerResp(b""),          # ASF/IPMI
        631: http,                      # IPP/CUPS
        636: https,                     # LDAPS
        646: BannerResp(b""),          # RADIUS
        873: BannerResp(b""),          # rsync
        902: BannerResp(b""),          # VMWare
        990: BannerResp(b""),          # FTPS
        992: BannerResp(b""),          # Telnets
        993: imap,                      # IMAPS
        995: pop3,                      # POP3S
        1025: BannerResp(b""),         # NFS/IIS
        1080: socks,                    # SOCKS proxy
        1099: BannerResp(b""),         # RMI
        1433: mssql,                     # MSSQL
        1434: BannerResp(b""),         # MSSQL browser
        1521: BannerResp(b""),         # Oracle
        1723: BannerResp(b""),         # PPTP
        2049: BannerResp(b""),         # NFS
        2082: http,                      # cPanel
        2083: https,                     # cPanel SSL
        2086: http,                      # WHM
        2087: https,                     # WHM SSL
        2222: BannerResp(b""),         # SSH alt
        2375: BannerResp(b""),         # Endpoint mapper
        3128: BannerResp(b""),         # Squid
        3306: mysql,                     # MySQL
        3389: BannerResp(b""),         # RDP
        3690: BannerResp(b""),         # Subversion
        4369: BannerResp(b""),         # EPMD
        5432: BannerResp(b""),         # PostgreSQL
        5800: http,                      # VNC HTTP
        5900: BannerResp(b""),         # VNC
        5984: http,                      # CouchDB
        6379: BannerResp(b""),         # Redis
        6443: https,                     # Kubernetes API
        7443: https,                     # Vault
        8080: http,                      # HTTP alt
        8081: http,                      # HTTP alt
        8443: https,                     # HTTPS alt
        8888: http,                      # HTTP alt
        9090: http,                      # Prometheus
        9200: BannerResp(b""),         # Elasticsearch
        9300: BannerResp(b""),         # Elasticsearch transport
        10000: BannerResp(b""),        # Webmin
        11211: BannerResp(b""),        # Memcached
        15672: http,                     # RabbitMQ management
        27017: BannerResp(b""),        # MongoDB
        63791: BannerResp(b""),        # WSMAN
        63793: BannerResp(b""),        # WSMAN
    }
    pm.update(singles)

    # --- Ranges de portas que repetem o mesmo servico ---
    # HTTP em portas comuns de webservers/proxies
    for p in [81, 82, 83, 84, 85, 8000, 8001, 8008, 8009,
              8010, 8080, 8081, 8082, 8083, 8088, 8888,
              8880, 8443, 8843, 9000, 9001, 9090, 9091,
              4443, 444, 2288, 2289, 2290, 2291]:
        pm.setdefault(p, http)

    # HTTPS em portas SSL comuns
    for p in [245, 563, 591, 8140, 981, 1311, 2083, 2087, 7000,
              7443, 9443, 11371, 12443, 19080, 19081]:
        pm.setdefault(p, https)

    # SSH em portas alternativas
    for p in [2222, 2200]:
        pm.setdefault(p, ssh)

    # FTP em portas alternativas
    for p in [990, 2121]:
        pm.setdefault(p, ftp)

    # MySQL em portas alternativas
    for p in [3307, 3308]:
        pm.setdefault(p, mysql)

    # Telnet em portas alternativas
    for p in [992, 2323]:
        pm.setdefault(p, telnet)

    # SMTP em portas alternativas
    for p in [2525, 587]:
        pm.setdefault(p, smtp)

    # Banner generico para faixas suspeitas/obscuras
    for p in range(1, 65536):
        pm.setdefault(p, null)

    return pm


# =========================================================================
# POTEMKIN - Classe principal do honeypot
# =========================================================================
#
# Orquestra todos os componentes:
# - Detector (portscan)
# - RateLimiter (conexoes excessivas)
# - Firewall (iptables)
# - Syslog (Wazuh)
# - Responders (simulacao de servicos)
# - ThreadPool (conexao paralela)
# - Selector/epoll (escuta em massa)
# =========================================================================

class Potemkin:
    """Honeypot principal: detecta portscans e bloqueia atacantes via iptables."""

    def __init__(self, config_path=None):
        self.cfg = load_config(config_path)
        self._stop = threading.Event()
        self._servers = []    # Lista de listen sockets
        self._pool = None     # ThreadPoolExecutor

    def init(self):
        """
        Inicializacao completa:
        logging, syslog, detector, rate limiter, firewall, port map,
        thread pool, threads de background, PID file.
        """
        # --- Configura logging ---
        lf = self.cfg.get("log_file")
        self.log = logging.getLogger("potemkin")
        self.log.setLevel(logging.INFO)
        if lf:
            d = os.path.dirname(lf)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            fh = logging.FileHandler(lf)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            self.log.addHandler(fh)
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.log.addHandler(sh)

        # --- Syslog ---
        sl = self.cfg.get("syslog", {})
        self.syslog = Syslog(
            facility=sl.get("facility", "local6"),
            ident=sl.get("ident", "potemkin"),
        )

        # --- Mapa de portas ---
        self.port_map = build_port_map()

        # --- Whitelist (Trusted Hosts) ---
        self.whitelist = set(self.cfg.get("whitelist", []))

        # --- Detector de portscan ---
        det = self.cfg.get("detection", {})
        self.detector = Detector(
            threshold=det.get("threshold", 10),
            window=det.get("window", 60),
            ban_duration=det.get("ban_duration", 600),
            escalation=det.get("escalation", True),
            max_ban_duration=det.get("max_ban_duration", 86400),
            on_detect=self._on_scan,
            on_expire=self._on_ban_expire,
        )

        # --- Rate Limiter ---
        rl = self.cfg.get("rate_limit", {})
        self._rl_enabled = rl.get("enabled", True)
        self._rl_ban = rl.get("ban_on_exceed", True)
        self._rl_ban_dur = rl.get("ban_duration", 300)
        self.ratelimiter = RateLimiter(
            max_conn=rl.get("max_connections", 30),
            window=rl.get("window", 10),
            ban_on_exceed=rl.get("ban_on_exceed", True),
            ban_duration=rl.get("ban_duration", 300),
        )

        # --- Firewall (iptables) ---
        fw = self.cfg.get("firewall", {})
        self.fw = Firewall(
            helper=fw.get("helper", "/usr/local/bin/potemkin-firewall"),
            backend=fw.get("backend", "iptables"),  # Sempre iptables
        )
        self.fw.init()

        # --- Thread pool ---
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.cfg.get("max_threads", 512),
            thread_name_prefix="ptm",
        )

        # --- Threads de background (daemon) ---
        # Detector: expira bans antigos e limpa entries inuteis
        t_det = threading.Thread(
            target=self.detector.cleanup_loop,
            name="detector-cleanup", daemon=True,
        )
        t_det.start()

        # Rate Limiter: limpa buckets vazios
        t_rl = threading.Thread(
            target=self.ratelimiter.cleanup_loop,
            name="ratelimit-cleanup", daemon=True,
        )
        t_rl.start()

        # --- PID file ---
        pid_f = self.cfg.get("pid_file")
        if pid_f:
            d = os.path.dirname(pid_f)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            with open(pid_f, "w") as fh:
                fh.write(str(os.getpid()))

        self.log.info("Potemkin v%s inicializado (iptables-only)", __VERSION__)

    # ------------------------------------------------------------------
    # CALLBACKS - Chamados pelo Detector e RateLimiter
    # ------------------------------------------------------------------

    def _on_scan(self, ip, count, ports, ban_duration):
        """
        Callback: portscan detectado pelo Detector.
        Bloqueia IP no iptables e emite logs/syslog.
        """
        self.log.warning(
            "PORTSCAN %s | %d portas | ban=%ds", ip, count, ban_duration,
        )
        self.syslog.scan_detected(ip, count, ports, ban_duration)
        self.fw.block(ip, ban_duration)
        self.syslog.ip_blocked(ip, ban_duration, reason="portscan")

        # Registra no log de bloqueios
        bl = self.cfg.get("block_log")
        if bl:
            try:
                with open(bl, "a") as fh:
                    fh.write(
                        f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                        f"SCAN ip={ip} portas={count} ban={ban_duration}s\n"
                    )
            except OSError:
                pass

    def _on_ban_expire(self, ip):
        """
        Callback: ban expirou para o IP.
        Remove regra do iptables e emite syslog.
        Chamado pelo Detector.cleanup_loop() e Detector.record().
        """
        self.log.info("UNBAN %s | ban expirado, removendo regra do iptables", ip)
        self.fw.unblock(ip)
        self.syslog.ip_unblocked(ip)

    def _on_rate_exceed(self, ip):
        """
        Callback: rate limit excedido pelo IP.
        Bloqueia no iptables E registra no Detector.blocked para
        que o cleanup_loop faca o unban automatico apos ban_duration.
        """
        dur = self._rl_ban_dur
        self.log.warning("RATE_LIMIT %s | ban=%ds", ip, dur)
        self.fw.block(ip, dur)
        self.syslog.ip_blocked(ip, dur, reason="rate_limit")

        # Registra ban no Detector para unban automatico
        self.detector.add_rate_ban(ip, dur)

        # Log de bloqueios
        bl = self.cfg.get("block_log")
        if bl:
            try:
                with open(bl, "a") as fh:
                    fh.write(
                        f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                        f"RATE ip={ip} ban={dur}s\n"
                    )
            except OSError:
                pass

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _in_use(port):
        """Verifica se a porta ja esta em uso por outro processo."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                return False
            except OSError:
                return True

    def _conn(self, cs, ca, port, responder):
        """
        Lida com uma conexao individual no thread pool.
        1. Registra no detector (porta scan tracking)
        2. Emite syslog
        3. Executa o handler do servico simulado
        """
        ip = ca[0]
        try:
            timeout = self.cfg.get("socket_timeout", 3)
            cs.settimeout(timeout)

            # Registra no detector de portscan
            self.detector.record(ip, port)

            # Syslog da conexao
            svc = getattr(responder, "service", "unknown")
            self.syslog.connection(ip, port, svc)

            # Executa handler do servico
            responder.handle(cs)
        except Exception:
            pass
        finally:
            try:
                cs.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # MAIN LOOP - Event loop com selectors/epoll
    # ------------------------------------------------------------------

    def run(self):
        """
        Loop principal: usa selectors (epoll) para monitorar milhares
        de listen sockets em uma unica thread, e delega conexoes
        aceitas para o ThreadPoolExecutor.
        """
        ports = sorted(self.port_map.keys())
        addr = self.cfg.get("bind_address", "0.0.0.0")
        bk = self.cfg.get("backlog", 32)

        self.log.info(
            "Potemkin v%s | %d portas | %s | iptables",
            __VERSION__, len(ports), addr,
        )

        # Cria selector e registra todos os listen sockets
        sel = selectors.DefaultSelector()
        started = 0
        skipped = 0

        for p in ports:
            if self._stop.is_set():
                break
            if self._in_use(p):
                skipped += 1
                continue
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((addr, p))
                srv.listen(bk)
                srv.setblocking(False)
                sel.register(srv, selectors.EVENT_READ, data=p)
                self._servers.append(srv)
                started += 1
            except OSError as e:
                self.log.debug("Porta %d: %s", p, e)

        self.log.info("Ativas: %d portas, Puladas: %d (em uso)", started, skipped)

        # --- Event loop: uma thread, milhares de portas ---
        while not self._stop.is_set():
            try:
                events = sel.select(timeout=1.0)
            except (OSError, ValueError):
                break

            for key, _mask in events:
                srv = key.fileobj
                port = key.data
                try:
                    cs, ca = srv.accept()
                    ip = ca[0]

                    # Rejeita rapido: IPv6 (nao suportado pelo iptables nativo)
                    if ':' in ip:
                        cs.close()
                        continue

                    # Trusted Hosts (Whitelist)
                    if ip in self.whitelist:
                        cs.close()
                        continue

                    # Rejeita rapido: IPs bloqueados
                    if self.detector.is_blocked(ip):
                        cs.close()
                        continue

                    # Verifica rate limit
                    if self._rl_enabled and not self.ratelimiter.check(ip):
                        cs.close()
                        if self._rl_ban:
                            self._on_rate_exceed(ip)
                        continue

                    # Delega para thread pool
                    self._pool.submit(self._conn, cs, ca, port, self.port_map[port])
                except OSError:
                    pass

        # --- Shutdown limpo ---
        self.log.info("Desligando...")
        self._pool.shutdown(wait=False, cancel_futures=True)
        sel.close()
        for s in self._servers:
            try:
                s.close()
            except OSError:
                pass
        self.fw.cleanup()
        self.syslog.close()

        # Remove PID file
        pid_f = self.cfg.get("pid_file")
        if pid_f:
            try:
                os.unlink(pid_f)
            except OSError:
                pass

    def stop(self):
        """Sinaliza parada graciosa do event loop."""
        self._stop.set()


# =========================================================================
# CLI - Ponto de entrada
# =========================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="potemkin",
        description=f"Potemkin v{__VERSION__} - Sistema Defensivo Honeypot contra Portscan",
    )
    parser.add_argument(
        "-c", "--config",
        metavar="ARQUIVO",
        default=None,
        help="Caminho para arquivo de configuracao JSON",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__VERSION__}",
    )
    args = parser.parse_args()

    potemkin = Potemkin(config_path=args.config)

    # Captura sinais para shutdown gracioso
    def sig(signum, frame):
        potemkin.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig)
    signal.signal(signal.SIGINT, sig)
    signal.signal(signal.SIGHUP, sig)

    potemkin.init()
    potemkin.run()


if __name__ == "__main__":
    main()
