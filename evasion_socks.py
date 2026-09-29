#!/usr/bin/env python3
"""
Ruadan — SOCKS5 minimal com SOURCE-BINDING (substituto do 3proxy no Kali).

O pacote 3proxy não existe nos repos do Kali; este servidor fornece o mesmo
recurso essencial para o pool de evasão: um listener SOCKS5 cujas conexões
de SAÍDA são amarradas a um IP de origem fixo (socket.create_connection com
source_address) — assim o ffuf/gobuster (que não suportam --interface)
rotacionam o source-IP via -x socks5://127.0.0.1:108xx.

Protocolo: RFC 1928 — sem auth, apenas CONNECT (suficiente para curl -x
socks5:// e ffuf -x socks5://). Um processo = um listener = uma identidade.

Uso:
  python3 evasion_socks.py -l 127.0.0.1 -p 10800 -s 192.168.50.240
"""
import argparse
import socket
import sys
import threading


def _pump(src, dst):
    """Relay unidirecional com close gracioso."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            src.close()
        except Exception:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle(client, source_ip):
    try:
        # ---- greeting: VER NMETHODS METHODS... --------------------------------
        data = client.recv(262)
        if len(data) < 2 or data[0] != 0x05:
            return
        client.sendall(b"\x05\x00")  # NO AUTH REQUIRED

        # ---- request: VER CMD RSV ATYP DST.ADDR DST.PORT ----------------------
        data = b""
        while len(data) < 8:
            chunk = client.recv(8 - len(data))
            if not chunk:
                return
            data += chunk
        if data[1] != 0x01:  # só CONNECT
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        atyp = data[3]
        if atyp == 0x01:  # IPv4
            while len(data) < 10:
                data += client.recv(10 - len(data))
            dst = socket.inet_ntoa(data[4:8])
            port = int.from_bytes(data[8:10], "big")
        elif atyp == 0x03:  # domínio
            nlen = data[4]
            need = 5 + nlen + 2
            while len(data) < need:
                chunk = client.recv(need - len(data))
                if not chunk:
                    return
                data += chunk
            dst = data[5:5 + nlen].decode("idna", "replace")
            port = int.from_bytes(data[5 + nlen:7 + nlen], "big")
        elif atyp == 0x04:  # IPv6
            while len(data) < 22:
                chunk = client.recv(22 - len(data))
                if not chunk:
                    return
                data += chunk
            dst = socket.inet_ntop(socket.AF_INET6, data[4:20])
            port = int.from_bytes(data[20:22], "big")
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        # ---- conecta ao destino com SOURCE BINDING ----------------------------
        try:
            remote = socket.create_connection((dst, port), timeout=12,
                                               source_address=(source_ip, 0))
        except Exception:
            # host unreachable (05) — sem detalhe para não vazar stack
            client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        # ---- reply success (BND.ADDR = endereço local amarrado) -----------------
        baddr = remote.getsockname()
        try:
            bnd = socket.inet_aton(baddr[0])
        except Exception:
            bnd = b"\x00\x00\x00\x00"
        client.sendall(b"\x05\x00\x00\x01" + bnd + baddr[1].to_bytes(2, "big"))

        # ---- relay bidirecional -----------------------------------------------
        t = threading.Thread(target=_pump, args=(client, remote), daemon=True)
        t.start()
        _pump(remote, client)
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


def main():
    p = argparse.ArgumentParser(description="SOCKS5 com source-binding (pool de evasão Ruadan)")
    p.add_argument("-l", "--listen", default="127.0.0.1")
    p.add_argument("-p", "--port", type=int, required=True)
    p.add_argument("-s", "--source", required=True, help="IP de origem das conexões de saída")
    args = p.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.listen, args.port))
    except OSError as e:
        print(f"[evasion-socks][ERRO] bind {args.listen}:{args.port}: {e}", flush=True)
        sys.exit(1)
    srv.listen(128)
    print(f"[evasion-socks] listening {args.listen}:{args.port} source={args.source}", flush=True)
    while True:
        try:
            client, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(client, args.source), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
