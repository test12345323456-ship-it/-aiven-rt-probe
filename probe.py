import json, os, socket, ssl, struct, hashlib, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
OSD_IPS = ["10.156.0.82", "10.156.0.85", "10.156.0.107", "10.156.0.131",
           "10.156.0.144", "10.156.0.151", "10.156.0.170", "10.156.0.184",
           "10.156.0.237", "10.156.0.39"]

def http(url, headers=None, method="GET", timeout=5, insecure=True, n=2500):
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

def cert_of(ip, port=443, timeout=4):
    try:
        ctx = ssl._create_unverified_context()
        s = socket.create_connection((ip, port), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=ip)
        c = ss.getpeercert(binary_form=False) or {}
        raw = ss.getpeercert(binary_form=True)
        ss.close()
        return {"cn": (dict(x[0] for x in c.get("subject", [])).get("commonName", "")),
                "san": [x[1] for x in c.get("subjectAltName", [])][:12],
                "sha256": hashlib.sha256(raw).hexdigest()[:20],
                "notBefore": c.get("notBefore", "")[:20]}
    except Exception as e:
        return {"error": type(e).__name__}

def ping(ip, timeout=2, seq=7):
    tid = os.getpid() & 0xFFFF
    chk = 0
    hdr = struct.pack(">BBHHH", 8, 0, 0, tid, seq)
    data = struct.pack(">d", 1750000000.0)
    tot = hdr + data
    tot = struct.pack(">BBHHH", 8, 0, 0, tid, seq) + data
    # checksum
    s = 0
    for i in range(0, len(tot), 2):
        w = (tot[i] << 8) + (tot[i+1] if i+1 < len(tot) else 0)
        s = (s + w) & 0xFFFF
    s = ~s & 0xFFFF
    icmp = struct.pack(">BBHHH", 8, 0, s, tid, seq) + data
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sk.settimeout(timeout)
        sk.sendto(icmp, (ip, 0))
        rep, _ = sk.recvfrom(1024); sk.close()
        typ = rep[20]
        return {8: "echo", 0: "pinreply", 3: "unreachable", 11: "ttl"}.get(typ, "type" + str(typ))
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return type(e).__name__ + ": " + str(e)[:40]

def safe(p, n=2200):
    try:
        return open(p).read()[:n]
    except Exception as e:
        return type(e).__name__

def run_all():
    o = {}
    o["osd_status"] = {ip: http("https://" + ip + "/api/status", n=900) for ip in OSD_IPS}
    o["n39"] = http("https://10.156.0.39/")
    o["n39p"] = {p: http("https://10.156.0.39" + p, n=300) for p in ("/login", "/healthz", "/api", "/about")}
    o["certs"] = {ip: cert_of(ip) for ip in OSD_IPS}
    o["ipfs_icmp"] = {}
    for ip in ["10.156.0.1", "10.156.0.2", "10.156.0.3", "10.156.0.39", "10.156.0.82",
               "10.156.0.107", "10.156.0.144", "10.156.0.170", "10.156.0.235", "10.156.0.236",
               "10.156.0.174"]:
        o["ipfs_icmp"][ip] = ping(ip)
    o["netcs"] = {"tcp": safe("/proc/net/tcp", 1500), "tcp6": safe("/proc/net/tcp6", 900),
                  "udp": safe("/proc/net/udp", 700), "icmp_raw": safe("/proc/net/raw", 500)}
    o["hosts_file"] = safe("/etc/hosts", 400)
    o["logs_sidecar"] = safe("/alloc/logs/sidecar.stdout.0", 2600)
    o["logs_pod"] = safe("/alloc/logs/pod.stdout.0", 700)
    o["alloc_tmp"] = {p: os.listdir(p) for p in ("/alloc/tmp", "/alloc/data")}
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
