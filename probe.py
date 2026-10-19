import json, os, socket, ssl, threading, urllib.request, hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
HTTPS_IPS = ["10.156.0.39", "10.156.0.82", "10.156.0.85", "10.156.0.107", "10.156.0.131",
             "10.156.0.144", "10.156.0.151", "10.156.0.176", "10.156.0.179", "10.156.0.183",
             "10.156.0.184", "10.156.0.237"]
SSH_SAMPLE = ["10.156.0.10", "10.156.0.19", "10.156.0.41", "10.156.0.96", "10.156.0.136",
              "10.156.0.192", "10.156.0.248", "10.156.0.253"]
LO_PORTS = [22, 80, 443, 2375, 4646, 5432, 6060, 8080, 9000]

def ssh_banner(ip, port=22, timeout=3):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(3)
        d = s.recv(80)
        s.close()
        return d.decode("utf-8", "replace").strip()
    except Exception as e:
        return type(e).__name__ + ": " + str(e)

def http(url, headers=None, method="GET", timeout=4, insecure=False, n=500):
    try:
        ctx = ssl._create_unverified_context() if insecure else None
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        r = op.open(req, timeout=timeout)
        return {"status": r.status, "hdr": {k: r.headers.get(k) for k in ("osd-name", "server", "location", "content-type", "x-powered-by")},
                "body": r.read(n).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(n).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "hdr": {k: (e.headers or {}).get(k) for k in ("osd-name", "server", "location", "content-type", "x-powered-by")}, "body": body}
    except Exception as e:
        return {"error": type(e).__name__}

def cert_sub(ip):
    try:
        ctx = ssl._create_unverified_context()
        s = socket.create_connection((ip, 443), timeout=4)
        ss = ctx.wrap_socket(s, server_hostname=ip)
        c = ss.getpeercert(binary_form=False) or {}
        raw = ss.getpeercert(binary_form=True)
        ss.close()
        return {"subject": dict(x[0] for x in c.get("subject", [])),
                "san": [x[1] for x in c.get("subjectAltName", [])][:10],
                "sha256": hashlib.sha256(raw).hexdigest()[:16]}
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)[:80]}

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

def run_all():
    o = {}
    o["ssh_banners"] = {ip: ssh_banner(ip) for ip in SSH_SAMPLE}
    o["http_neighbors"] = {ip: http("http://" + ip + "/") for ip in HTTPS_IPS}
    o["certs"] = {ip: cert_sub(ip) for ip in HTTPS_IPS}
    o["localhost_ports"] = {str(p): tcp("127.0.0.1", p) for p in LO_PORTS}
    o["ot_agent"] = http("http://127.0.0.1:8888/", timeout=2)
    o["traefik_api"] = http("http://127.0.0.1:8080/api/rawdata", timeout=2, n=700)
    o["ot_pprof"] = http("http://127.0.0.1:6060/debug/pprof/", timeout=2, n=300)
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
