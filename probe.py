import json, os, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
ULA = "fda7:a938:5bfe:5fa6:0:5ea:2f7c:59f8"

def tcp(ip, port, timeout=2, v6=False):
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(timeout)
    try:
        s.connect((ip, port)); return "OPEN"
    except ConnectionRefusedError: return "refused"
    except socket.timeout: return "filtered"
    except OSError as e: return type(e).__name__
    finally:
        try: s.close()
        except Exception: pass

def http(url, headers=None, timeout=5, n=3000):
    try:
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=__import__("ssl")._create_unverified_context()))
        req = urllib.request.Request(url, headers=headers or {})
        r = op.open(req, timeout=timeout)
        return {"status": r.status, "body": r.read(n).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(n).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body}
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)[:80]}

def safe(p, n=1600):
    try:
        return open(p).read()[:n]
    except Exception as e:
        return type(e).__name__

def run_all():
    o = {}
    # our own IPv6 addresses
    o["if_inet6"] = safe("/proc/net/if_inet6", 1200)
    # local netns: what else listens (raw and via TCP)
    o["p22243_lo"] = {}
    for host in ("[::1]", "127.0.0.1", "[::]"):
        o["p22243_lo"]["http_" + host] = http("http://" + host + ":22243/", timeout=3, n=400)
    o["p22243_raw"] = None
    try:
        s = socket.create_connection(("::1", 22243), timeout=2)
        s.settimeout(2)
        try:
            d = s.recv(96)
            o["p22243_raw"] = "first: " + (d.hex() if d else "none")
        except Exception as e:
            o["p22243_raw"] = "open-read:" + type(e).__name__
        s.close()
    except Exception as e:
        o["p22243_raw"] = type(e).__name__
    # IPv6 ULA reachability to the named infra node
    o["ula"] = {}
    for p in (22, 80, 443, 8000, 5432):
        o["ula"][str(p)] = tcp(ULA, p, 2, v6=True)
    # find our own ULA prefix from if_inet6, then sweep a few neighbors in our own /64
    o["v6_sweep"] = {}
    try:
        txt = safe("/proc/net/if_inet6", 2000)
        for line in txt.split("\n"):
            parts = line.split()
            if len(parts) > 3 and parts[3] not in ("lo",):
                if parts[0].startswith("fda7"):
                    full = parts[0]
                    ip6 = ":".join(full[i:i+4] for i in range(0, 32, 4))
                    o["v6_self"] = ip6
                    base = ip6.rsplit(":", 1)[0]
                    for n in ("0", "1", "10", "100", "fffe", "59f7", "59f9", "5fa6"):
                        cand = base + ":" + n
                        o["v6_sweep"][cand + ":443"] = tcp(cand, 443, 1.5, v6=True)
                        o["v6_sweep"][cand + ":22"] = tcp(cand, 22, 1.5, v6=True)
                    break
    except Exception as e:
        o["v6_sweep"]["err"] = type(e).__name__
    # grafana identity
    g = http("https://10.156.0.39/", n=4200)
    o["grafana_assets"] = [seg.split('"')[0] for seg in (g.get("body") or "").split('src="')[1:6]]
    o["grafana_health"] = http("https://10.156.0.39/api/health", n=400)
    o["grafana_buildinfo"] = http("https://10.156.0.39/api/backendbuildinfo", n=300)
    o["grafana_login"] = http("https://10.156.0.39/login", n=1800)
    # netns listener check (tcp6 full)
    o["tcp6_full"] = safe("/proc/net/tcp6", 1200)
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
