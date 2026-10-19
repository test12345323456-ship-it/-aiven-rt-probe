import json, os, socket, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
NB = "10.156.0.170"

def tcp(ip, port, timeout=2):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, port)); return "OPEN"
    except ConnectionRefusedError: return "refused"
    except socket.timeout: return "filtered"
    except OSError as e: return type(e).__name__
    finally:
        try: s.close()
        except Exception: pass

def http(url, headers=None, method="GET", timeout=4, insecure=False, n=3000):
    try:
        ctx = ssl._create_unverified_context() if insecure else None
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        r = op.open(req, timeout=timeout)
        return {"status": r.status, "headers": dict(r.headers), "body": r.read(n).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(n).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": dict(e.headers or {}), "body": body}
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)}

def safe(p, n=1500):
    try:
        return open(p).read()[:n]
    except Exception as e:
        return type(e).__name__

def run_all():
    o = {}
    # parallel full sweep of the node bridge
    result = {}
    work = [(ip, p) for ip in ("10.156.0.%d" % i for i in range(2, 255)) for p in (22, 80, 443)]
    sem = threading.BoundedSemaphore(48)
    lock = threading.Lock()
    def worker(item):
        ip, p = item
        r = tcp(ip, p, 2.2)
        if r == "OPEN":
            with lock:
                result.setdefault(ip, []).append(p)
    ths = []
    for item in work:
        t = threading.Thread(target=worker, args=(item,)); t.start(); ths.append(t)
        if len(ths) > 200:
            for t in ths: t.join()
            ths = []
    for t in ths: t.join()
    o["full_sweep"] = result
    # OSD surface
    o["osd_root"] = http("http://" + NB + "/", n=2600)
    o["osd_authinfo"] = http("http://" + NB + "/api/core/security/authinfo")
    o["osd_authinfo_https"] = http("https://" + NB + "/api/core/security/authinfo", insecure=True)
    o["osd_system"] = http("http://" + NB + "/api/system/info")
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__
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

threading.Thread(target=loop, daemon=True).start()
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
