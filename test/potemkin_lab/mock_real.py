#!/usr/bin/env python3
"""Mock de serviço REAL para o lab Potemkin: responde DIFERENTE por path
(como um app de verdade — corpo embute a rota pedida), em IPv4 (127.0.0.2)
e IPv6 (::1). O Potemkin pula esta porta (_in_use) → invisível à defesa."""
import http.server
import socket
import threading


class Real_handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"REAL SERVICE\npath={self.path}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve_v4():
    srv = http.server.ThreadingHTTPServer(("127.0.0.2", 7777), Real_handler)
    srv.serve_forever()


def serve_v6():
    try:
        # subclass própria p/ v6 — NÃO mutar a classe compartilhada (a thread
        # v6 mutando ThreadingHTTPServer.address_family derrubava o server v4)
        class V6Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6
        srv = V6Server(("::1", 7777), Real_handler)
        srv.serve_forever()
    except OSError:
        pass  # sem v6 no host


if __name__ == "__main__":
    threading.Thread(target=serve_v6, daemon=True).start()
    serve_v4()
