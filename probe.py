import json, os, re, ssl, socket, threading, urllib.request, urllib.error, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
OSD = ["10.156.0.82","10.156.0.85","10.156.0.107","10.156.0.131","10.156.0.144",
       "10.156.0.151","10.156.0.170","10.156.0.184","10.156.0.237"]

def http(url, timeout=4, n=9000):
    try:
        ctx = ssl._create_unverified_context()
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        r = op.open(urllib.request.Request(url, headers={"User-Agent": "rtprobe-id"}), timeout=timeout)
        return {"status": r.status, "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": r.read(n).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try: body = e.read(n).decode("utf-8", "replace")
        except Exception: body = ""
        return {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()}, "body": body}
    except Exception as e:
        return {"error": type(e).__name__}

def tls_fp(ip, port=443):
    try:
        import hashlib
        ctx = ssl._create_unverified_context()
        s = socket.socket(); s.settimeout(3); s.connect((ip, port))
        c = ctx.wrap_socket(s)
        der = c.getpeercert(binary_form=True)
        ver = c.version(); cipher = c.cipher()
        c.close()
        return {"sha256": hashlib.sha256(der).hexdigest()[:24], "tls": ver,
                "cipher": cipher[0] if cipher else None}
    except Exception as e:
        return {"err": type(e).__name__}

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

def run_all():
    o = {}
    # self v6 listener test
    try:
        for ln in open("/proc/net/if_inet6").read().split("\n"):
            p = ln.split()
            if len(p) > 5 and p[5] == "eth0" and not p[0].startswith("fe80") and p[1] != "01":
                h = p[0]; groups = [h[i:i+4] for i in range(0, 32, 4)]
                gua = ":".join(groups).rstrip(":0") + "::" if groups[-1] == "0000" else ":".join(groups)
                # build canonical: drop trailing zero groups, no compression needed
                gua = ":".join(groups).replace(":0:0:", "::", 1)
                o["gua"] = ":".join(groups)
                o["v6_selftest"] = self_v6(gua)
                break
    except Exception as e:
        o["v6_selftest"] = "parse:" + type(e).__name__

    # OSD metadata: login page versions + headers + TLS fp
    o["osd_meta"] = {}
    for ip in OSD:
        r = http(f"https://{ip}/login", n=9000)
        meta = {"status": r.get("status"), "err": r.get("error")}
        if r.get("headers"):
            h = r["headers"]
            meta["headers"] = {k: str(v)[:200] for k, v in h.items() if k in
                               ("osd-name", "server", "x-content-type-options", "www-authenticate",
                                "location", "set-cookie", "content-type")}
        b = r.get("body") or ""
        vers = set(re.findall(r'"version"\s*:\s*"([0-9][0-9.]*)"', b))
        builds = set(re.findall(r'"buildNumber"\s*:\s*(\d+)', b))
        meta["versions"] = sorted(vers)[:6]
        meta["build"] = sorted(builds)[:3]
        meta["injected_meta"] = "kbn-injected-metadata" in b or "opensearchDashboards" in b
        o["osd_meta"][ip] = meta
    o["osd_tls"] = {ip: tls_fp(ip) for ip in OSD}

    # Grafana + connect metadata
    g = http("https://10.156.0.39/api/health", n=400)
    o["grafana_health"] = {"status": g.get("status"), "body": (g.get("body") or "")[:200]}
    o["grafana_tls"] = tls_fp("10.156.0.39")
    o["cnt_tls"] = {ip: tls_fp(ip) for ip in ("10.156.0.176","10.156.0.179","10.156.0.183")}
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__ + ": " + str(e)[:140]
        threading.Event().wait(120)

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
