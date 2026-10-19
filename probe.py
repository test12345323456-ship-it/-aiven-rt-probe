import json, os, socket, ssl, struct, threading, urllib.request, random
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}
IPS = ["10.156.0.%d" % i for i in range(2, 255)]
SP = [5432, 26247, 26249, 33046, 9092, 9200, 4317, 8500, 4646, 8080, 9100, 5500, 6379, 26379]

def tcp(ip, port, timeout=1.5):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, port)); return "OPEN"
    except ConnectionRefusedError: return "refused"
    except socket.timeout: return "filtered"
    except OSError: return "err"
    finally:
        try: s.close()
        except Exception: pass

def dns_query(name, server="169.254.1.1", port=53):
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
        s.sendto(q, (server, port))
        data, _ = s.recvfrom(1024); s.close()
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)}
    rc = data[3] & 0xF  # rcode
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    txt = data.decode("latin1")
    answers = []
    # crude A-record scan in answer section
    off = None
    i = len(data)
    # simple scan: find 4-byte A in tail
    pos = 12
    # skip question
    while data[pos:pos+1] != b"\x00":
        pos += 1 + data[pos]; 
        if pos >= len(data): break
    pos += 5
    while pos + 10 <= len(data) and an and len(answers) < 8:
        rr = data[pos:pos+10]
        typ, cls, ttl, rdlen = struct.unpack(">HHIH", rr[0:10])
        pos2 = pos + 10
        if typ == 1 and rdlen == 4:
            answers.append(".".join(str(b) for b in data[pos2:pos2+4]))
        elif typ in (5, 12):
            # CNAME/PTR: skip
            pass
        pos = pos2 + rdlen
        an -= 1
    return {"rcode": rc, "answers": answers}

NAMES = [
 "falcon-bug-bounty-flag-pgsql-dev-sandbox.service.consul",
 "falcon.service.consul", "falcon.nomad", "postgres.service.consul",
 "nomad.service.consul", "consul.service.consul",
 "traefik.http.service.consul", "http.service.consul",
 "falcon-bug-bounty-flag-pgsql-dev-sandbox.nomad",
 "dev-sandbox.nomad", "dev-sandbox.service.consul",
 "pg-30e460ba.nomad", "os-30e460ba.nomad",
 "falcon-bug-bounty-flag-pgsql-dev-sandbox.aiven.local",
 "nomad", "consul", "consul.consul", "nomad.nomad",
]

def run_all():
    o = {}
    result = {}
    work = [(ip, p) for ip in IPS for p in SP]
    lock = threading.Lock()
    ths = []
    def worker(item):
        ip, p = item
        r = tcp(ip, p)
        if r == "OPEN":
            with lock:
                result.setdefault(ip, []).append(p)
    for item in work:
        t = threading.Thread(target=worker, args=(item,)); t.start(); ths.append(t)
        if len(ths) > 220:
            for t in ths: t.join()
            ths = []
    for t in ths: t.join()
    o["svc_port_sweep"] = result
    o["dns_nomad_consul"] = {}
    for n in NAMES:
        o["dns_nomad_consul"][n] = dns_query(n)
        o["dns_nomad_consul"][n + "@gw"] = dns_query(n, "10.156.0.1")
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__
        threading.Event().wait(200)

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
