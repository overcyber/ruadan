#!/usr/bin/env python3
"""
Mock da defesa do lab — emula o mecanismo de proteção para testar a camada
de evasão SEM tocar na rede real (roda em 127.0.0.1).

Comportamento (por IP de origem):
  - Até --thresh requests: HTTP 200 {"ok":true}
  - Depois de --thresh: bloqueia por --blocktime segundos
    * --mode 403  : responde 403 {"blocked":true}
    * --mode drop : aceita o TCP e NUNCA responde (tarpit → curl vê 000)
    * --mode reset: fecha a conexão sem responder (RST-like → curl vê 000)
  - --mode emulated: responde SEMPRE o mesmo corpo 200 instantâneo para
    QUALQUER path (porta "fita" — sinal body-clone para o emulation_check)

Log de cada request em stdout (para validar rotação de IP nos testes):
  <epoch> <client_ip> <code> <path>

Uso:
  python3 mock_blocker.py --port 8899 --thresh 20 --blocktime 120 --mode 403
"""
import argparse
import sys
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

counts = defaultdict(int)
blocked_until = defaultdict(float)

ARGS = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_GET(self):
        ip = self.client_address[0]
        now = time.time()

        if ARGS.mode == "emulated":
            # porta "fita": mesmo corpo 200 instantâneo para qualquer path
            self._send(200, b'{"emulated":true,"path":"whatever"}')
            print(f"{now:.3f} {ip} 200 {self.path}", flush=True)
            return

        if blocked_until[ip] > now:
            code = 403
        else:
            counts[ip] += 1
            if counts[ip] > ARGS.thresh:
                blocked_until[ip] = now + ARGS.blocktime
                # ao expirar o bloqueio o contador zera (recomeça a contar)
                code = 403
            else:
                code = 200

        print(f"{now:.3f} {ip} {code} {self.path}", flush=True)

        if code == 200:
            # corpo VARIA por path — senão o emulation_check vê body-clone
            # (a "fita" real serve corpo idêntico para qualquer path)
            body = b'{"ok":true,"path":"' + self.path.encode() + b'"}'
            self._send(200, body)
            return

        # bloqueado:
        if ARGS.mode == "403":
            self._send(403, b'{"blocked":true}')
        elif ARGS.mode == "drop":
            # tarpit: segura a conexão até o curl estourar --max-time
            time.sleep(ARGS.blocktime + 10)
        elif ARGS.mode == "reset":
            # fecha sem responder → curl vê 000 (empty reply / reset)
            try:
                self.connection.close()
            except Exception:
                pass

    def do_POST(self):
        self.do_GET()

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, *a):
        pass  # log padrão fora; nós já logamos no stdout


def main():
    global ARGS
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8899)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--thresh", type=int, default=20)
    p.add_argument("--blocktime", type=int, default=120)
    p.add_argument("--mode", choices=["403", "drop", "reset", "emulated"], default="403")
    ARGS = p.parse_args()
    srv = ThreadingHTTPServer((ARGS.bind, ARGS.port), Handler)
    print(f"# mock_blocker listening on {ARGS.bind}:{ARGS.port} "
          f"thresh={ARGS.thresh} blocktime={ARGS.blocktime} mode={ARGS.mode}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
