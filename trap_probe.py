#!/usr/bin/env python3
"""
Ruadan — trap_probe.py: probe com SOURCE-BIND que devolve OBSERVAÇÕES BRUTAS.

NENHUMA assinatura de defesa hardcoded aqui. O probe não interpreta nada —
coleta fatos crus; a interpretação (clustering, variação, aprendizado de
threshold) fica no trap_census.sh com base no ESTADO aprendido por alvo.
Assim, qualquer mudança na defesa (novos banners, novo mapa de portas, novo
threshold) só muda o que o sistema APRENDE, não o que ele ESPERA.

Uso:
  trap_probe.py <src_ip> <dst> <port> [mode] [n]
  mode: banner (default) — conecta, recv puro (1ª resposta)
        http          — envia 2 requests (paths distintos) e compara
        stability      — conecta n vezes (default 3), mede Δt e hash

Saída (key=value, uma por linha, parseável):
  result=connect|refused|timeout
  hash=<md5 da 1ª resposta>          (vazio se nada recebido)
  bytes=<n recebidos>
  t_ms=<tempos de connect em ms, csv>
  hash2=<md5 da 2ª resposta>         (modo http: path B)
  reconnect_hash=<hash estável?>     (modo stability)
"""
import hashlib
import socket
import sys
import time


def _body(data):
    """Extrai o corpo (pós \r\n\r\n) — headers têm campos voláteis (Date,
    Server rotativo) que quebrariam o clustering. Body é o conteúdo estável;
    apps reais variam o corpo por rota; emuladores servem igual."""
    if b"\r\n\r\n" in data:
        return data.split(b"\r\n\r\n", 1)[1]
    return data


def _connect(src, dst, port, timeout):
    try:
        t0 = time.perf_counter()
        if src == "-":
            # sem source-bind (ex: IPv6, onde não há pool de origem)
            s = socket.create_connection((dst, port), timeout=timeout)
        else:
            s = socket.create_connection((dst, port), timeout=timeout,
                                         source_address=(src, 0))
        t_ms = int((time.perf_counter() - t0) * 1000)
        return s, t_ms
    except ConnectionRefusedError:
        return None, -1
    except (socket.timeout, OSError):
        return None, -2


def _recv(s, limit, timeout):
    s.settimeout(timeout)
    data = b""
    try:
        while len(data) < limit:
            chunk = s.recv(limit - len(data))
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    return data


def probe(src, dst, port, mode, n, timeout=2.5):
    out = []

    if mode == "http":
        s, t = _connect(src, dst, port, timeout)
        if s is None:
            print("result=" + ("refused" if t == -1 else "timeout"))
            return
        try:
            s.sendall(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
            d1 = _recv(s, 2048, timeout)
            s.close()
        except OSError:
            d1 = b""
        s2, t2 = _connect(src, dst, port, timeout)
        h2 = ""
        if s2 is not None:
            try:
                # path aleatório — resposta de app REAL varia; emulador serve igual
                s2.sendall(b"GET /probe-variant-%d HTTP/1.0\r\nHost: probe\r\n\r\n"
                           % int(time.time() * 1000 % 99991))
                d2 = _recv(s2, 2048, timeout)
                h2 = hashlib.md5(_body(d2)).hexdigest()
            except OSError:
                pass
            finally:
                try:
                    s2.close()
                except OSError:
                    pass
        print(f"result=connect t_ms={t} bytes={len(d1)} "
              f"hash={hashlib.md5(_body(d1)).hexdigest() if d1 else ''} hash2={h2}")
        return

    if mode == "stability":
        hs = []
        ts = []
        res = "connect"
        for _ in range(max(2, n)):
            s, t = _connect(src, dst, port, timeout)
            if s is None:
                res = "refused" if t == -1 else "timeout"
                break
            ts.append(t)
            d = _recv(s, 512, timeout)
            hs.append(hashlib.md5(d).hexdigest() if d else "")
            try:
                s.close()
            except OSError:
                pass
        stable = len(set(hs)) == 1 and hs and hs[0] != ""
        print(f"result={res} t_ms={','.join(str(x) for x in ts)} "
              f"reconnect_hash={'same' if stable else 'varies'} "
              f"hash={hs[0] if hs else ''}")
        return

    # banner (default): 1 conexão, 1ª resposta crua
    s, t = _connect(src, dst, port, timeout)
    if s is None:
        print("result=" + ("refused" if t == -1 else "timeout"))
        return
    d = _recv(s, 512, timeout)
    try:
        s.close()
    except OSError:
        pass
    print(f"result=connect t_ms={t} bytes={len(d)} "
          f"hash={hashlib.md5(d).hexdigest() if d else ''}")


def main():
    if len(sys.argv) < 4:
        print("uso: trap_probe.py <src_ip> <dst> <port> [banner|http|stability] [n]",
              file=sys.stderr)
        sys.exit(2)
    src, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    mode = sys.argv[4] if len(sys.argv) > 4 else "banner"
    n = int(sys.argv[5]) if len(sys.argv) > 5 else 3
    probe(src, dst, port, mode, n)


if __name__ == "__main__":
    sys.exit(main())
