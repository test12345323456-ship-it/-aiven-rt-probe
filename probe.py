import json, os, socket, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
HTTPS_IPS = ["10.156.0.107", "10.156.0.131", "10.156.0.144"]

def http(url, headers=None, method="GET", timeout=4, insecure=False, n=4000):
    try:
        ctx = ssl._create_unverified_context() if insecure else None
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        r = op.open(req, timeout=timeout)
        return {"status": r.status, "hdr": {k: r.headers.get(k) for k in ("osd-name", "server", "content-type")},
                "body": r.read(n).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(n).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "hdr": {k: (e.headers or {}).get(k) for k in ("osd-name", "server", "content-type")}, "body": body}
    except Exception as e:
        return {"error": type(e).__name__}

def run_all():
    o = {}
    for ip in HTTPS_IPS:
        base = "https://" + ip
        o[ip + "_authinfo"] = http(base + "/api/core/security/authinfo", insecure=True)
        o[ip + "_status"] = http(base + "/api/usage_reporter/last_status", insecure=True)
        o[ip + "_osdconf"] = http(base + "/app/kibanaSettings", insecure=True)
        o[ip + "_root_title"] = http(base + "/", insecure=True, n=400)
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__
        threading.Event().wait(150)

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
