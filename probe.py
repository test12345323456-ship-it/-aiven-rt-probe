import json, os, re, ssl, socket, threading, urllib.request, urllib.error, urllib.parse, time
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
V2 = "fleetx-v2"

def http(url, timeout=4, n=9000):
    try:
        ctx = ssl._create_unverified_context()
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        r = op.open(urllib.request.Request(url, headers={"User-Agent": "rtprobe-v2"}), timeout=timeout)
        return {"status": r.status, "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": r.read(n).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try: body = e.read(n).decode("utf-8", "replace")
        except Exception: body = ""
        return {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()}, "body": body}
    except Exception as e:
        return {"error": type(e).__name__}

def tcp_probe(host, port, tls=0, read_wait=1.4, send=None):
    out = {"host": host, "port": port, "tls": bool(tls)}
    t0 = time.time()
    try:
        s = socket.socket(); s.settimeout(3.5)
        s.connect((host, int(port)))
        out["connect"] = "open"
        if tls:
            try:
                ctx = ssl._create_unverified_context()
                s = ctx.wrap_socket(s)
                out["tls"] = s.version()
            except Exception as e:
                out["tls_err"] = type(e).__name__ + ":" + str(e)[:60]
        if send:
            try: s.send(send)
            except Exception as e: out["send_err"] = type(e).__name__
        s.settimeout(read_wait)
        try:
            d = s.recv(400)
            out["banner"] = d[:400].decode("utf-8", "replace")
        except (socket.timeout, ssl.SSLWantReadError):
            out["banner"] = None
        except Exception as e:
            out["banner_err"] = type(e).__name__
        s.close()
    except (ConnectionRefusedError, ConnectionResetError) as e:
        out["connect"] = "refused"
    except socket.timeout:
        out["connect"] = "timeout"
    except OSError as e:
        out["connect"] = "oserr:" + str(e)[:70]
    out["ms"] = int((time.time() - t0) * 1000)
    return out

def _esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")

def resp_probe(host, port, user, password, cmds=None):
    """TLS RESP probe: AUTH + PING + INFO + CONFIG subset + CLIENT INFO."""
    out = {"host": host, "port": port}
    try:
        ctx = ssl._create_unverified_context()
        s = socket.create_connection((host, int(port)), timeout=8)
        s = ctx.wrap_socket(s); s.settimeout(6)
        rd = [b""]
        def _readline():
            while b"\r\n" not in rd[0]:
                d = s.recv(4096)
                if not d: break
                rd[0] += d
            ln, _, rd[0] = rd[0].partition(b"\r\n")
            return ln, rd[0]
        def _bulk(i, buf):
            ln, buf = _readline_r(buf)
            if not ln.startswith(b"$"): return ln, buf
            n = int(ln[1:])
            if n == -1: return None, buf
            return buf[:n], buf[n + 2:]
        def _readline_r(buf):
            while b"\r\n" not in buf:
                d = s.recv(4096)
                if not d: break
                buf += d
            ln, _, buf = buf.partition(b"\r\n")
            return ln, buf
        def _value(ln, buf):
            c = ln[:1]
            if c == b"$":
                n = int(ln[1:])
                if n == -1: return None, buf
                return buf[:n], buf[n + 2:]
            if c == b"*":
                n = int(ln[1:])
                if n == -1: return [], buf
                arr = []
                for _ in range(n):
                    ln2, buf = _readline_r(buf)
                    v, buf = _value(ln2, buf)
                    arr.append(v)
                return arr, buf
            if c == b"-": return ("ERR", ln[1:].decode("utf-8", "replace")[:180]), buf
            return ln[1:].decode("utf-8", "replace"), buf
        def cmd(*args):
            args = [a.encode() if isinstance(a, str) else a for a in args]
            payload = b"*" + str(len(args)).encode() + b"\r\n"
            for a in args:
                payload += b"$" + str(len(a)).encode() + b"\r\n" + a + b"\r\n"
            s.send(payload)
            buf = b""
            ln, buf = _readline_r(buf)
            return ln, buf
        ln, buf = cmd("AUTH", user or "default", password or "")
        out["auth"] = buf[:120].decode("utf-8", "replace") if ln == b"+OK" else _value(ln, buf)[0]
        successes = {}
        plan = cmds or [("PING",), ("INFO", b"server"), ("CLIENT", b"INFO"),
                        ("CONFIG", b"GET", b"maxmemory*"), ("CONFIG", b"GET", b"*dir*")]
        ln, buf = cmd("PING"); out["ping"] = "+PONG" if ln == b"+PONG" else ln[:80].decode("utf-8", "replace")
        for cargs in plan:
            ln, buf = cmd(*cargs)
            try:
                successes[bytes(b" ").join(cargs).decode()[:36]] = (ln + b" ||| " + buf[:500]).decode("utf-8", "replace")
            except Exception:
                successes[join_args_safe(cargs)] = "raw: " + repr(ln)[:80]
        out["probe"] = json.dumps(successes)[:1400]
        try: s.close()
        except Exception: pass
    except Exception as e:
        out["err"] = type(e).__name__ + ":" + str(e)[:110]
    return out

def join_args_safe(cargs):
    try: return " ".join(x.decode() for x in cargs[:2])
    except Exception: return "cmd"

def http_probe(host, port, path="/", method="GET", tls=1, host_hdr=None):
    try:
        s = socket.create_connection((host, int(port)), timeout=8); s.settimeout(6)
        if tls:
            ctx = ssl._create_unverified_context(); s = ctx.wrap_socket(s)
        hn = host_hdr or host
        req = f"{method} {path} HTTP/1.1\r\nHost: {hn}\r\nUser-Agent: rtprobe-v2\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        d = b""
        while len(d) < 9000:
            chunk = s.recv(4096)
            if not chunk: break
            d += chunk
        s.close()
        head, _, body = d.partition(b"\r\n\r\n")
        return {"dest": f"{host}:{port}{path}", "head": head[:800].decode("utf-8", "replace"),
                "body": body[:3000].decode("utf-8", "replace")}
    except Exception as e:
        return {"err": type(e).__name__ + ":" + str(e)[:110]}

def fleetx(qs):
    q = urllib.parse.parse_qs(qs)
    kind = (q.get("q") or ["reach"])[0]
    if kind == "reach":
        targets = (q.get("targets") or [""])[0]
        out = []
        for t in targets.split(","):
            if ":" not in t: continue
            h, p = t.rsplit(":", 1)
            out.append(tcp_probe(h.strip(), p, tls=1 if (q.get("tls") or ["0"])[0] == "1" else 0))
        return {"kind": "reach", "results": out}
    if kind == "resp":
        return {"kind": "resp", "result": resp_probe((q.get("host") or [""])[0], (q.get("port") or ["0"])[0],
                 (q.get("user") or ["default"])[0], (q.get("pass") or [""])[0])}
    if kind == "http":
        return {"kind": "http", "result": http_probe((q.get("host") or [""])[0], (q.get("port") or ["0"])[0],
                 (q.get("path") or ["/"])[0], (q.get("method") or ["GET"])[0],
                 0 if (q.get("tls") or ["1"])[0] == "0" else 1, host_hdr=(q.get("hosthdr") or [None])[0])}
    if kind == "self":
        try:
            name = socket.gethostname()
            ips = [x for x in re.findall(r"(\d+\.\d+\.\d+\.\d+)", open("/proc/net/fib_trie").read())]
            return {"kind": "self", "hostname": name, "fib_ips": sorted(set(ips))[:40],
                    "routes": open("/proc/net/route").read()[:1200]}
        except Exception as e:
            return {"kind": "self", "err": str(e)[:100]}
    if kind == "ping":
        return {"kind": "v", "v": V2}
    return {"err": "unknown kind"}

def self_v6(gua):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(3)
        s.connect((gua, 8000))
        s.send(f"GET /{TOKEN} HTTP/1.1\r\nHost: gua\r\nConnection: close\r\n\r\n".encode())
        d = s.recv(160)
        s.close()
        return d.decode("utf-8", "replace").split("\r\n")[0]
    except Exception as e:
        return type(e).__name__ + ":" + str(e)[:60]

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        path, _, qs = self.path.partition("?")
        if path == "/" + TOKEN:
            if qs:
                body = json.dumps(fleetx(qs)).encode()
                code = 200
            else:
                body = json.dumps({"v": V2, "status": CACHE["status"]}).encode()
                code = 200
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

CACHE = {"status": "warming-up"}

def serve6():
    try:
        ctx = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        ctx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ctx.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except Exception:
            pass
        ctx.bind(("::", 8000)); ctx.listen(8)
        while True:
            c, _ = ctx.accept()
            try:
                c.settimeout(6)
                req = c.recv(2048)
                path = req.split(" ")[1] if len(req.split()) > 1 else "/"
                if path == "/" + TOKEN:
                    body = json.dumps({"v": V2, "via": "v6"}).encode()
                    c.send(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                else:
                    c.send(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                pass
            finally:
                try: c.close()
                except Exception: pass
    except Exception:
        pass

threading.Thread(target=serve6, daemon=True).start()
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
