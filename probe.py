import json, os, ssl, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}

def v6_tls_probe(ip, host, port=443, timeout=4):
    try:
        ctx = ssl._create_unverified_context()
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((ip, port, 0, 0))
        c = ctx.wrap_socket(s, server_hostname=host)
        peer = c.getpeername()
        c.close()
        return {"connected": True, "local": str(peer and peer[:4]), "msg": "v6 TLS connect OK"}
    except Exception as e:
        return {"connected": False, "err": type(e).__name__ + " " + str(e)[:70]}

def run_all():
    o = {}
    # correct self-GUA parse (columns: hexaddr idx prefix scope flags iface)
    try:
        for ln in open("/proc/net/if_inet6").read().split("\n"):
            p = ln.split()
            if len(p) > 5 and p[5] == "eth0" and not p[0].startswith("fe80") and p[1] != "01":
                h = p[0]
                groups = [h[i:i+4] for i in range(0, 32, 4)]
                o["self_gua"] = ":".join(int(g, 16) and format(int(g, 16), "x").lstrip("0") or "0" for g in groups).replace(":", "::")
                o["self_gua_full"] = ":".join(groups)
                o["self_prefix_len"] = int(p[2], 16)
    except Exception as e:
        o["gua_err"] = type(e).__name__ + str(e)[:60]

    # v6 egress proof A: ipv6.google.com 443 TLS with SNI
    try:
        o["v6egress_google"] = None
        for ai in socket.getaddrinfo("ipv6.google.com", 443, socket.AF_INET6):
            ip = ai[4][0]
            o["v6egress_google"] = {"target": ip, **v6_tls_probe(ip, "ipv6.google.com")}
            break
    except Exception as e:
        o["v6egress_google"] = {"err": type(e).__name__ + " " + str(e)[:60]}

    # v6 egress proof B: globo/microsoft dual-stack without forcing (urllib default may pick v6)
    o["v6_route_default"] = None
    try:
        for ln in open("/proc/net/ipv6_route").read().split("\n"):
            p = ln.split()
            if len(p) > 4 and p[0].startswith("00000000000000000000000000000000") and p[1] == "00":
                o["v6_route_default"] = ln[:180]
    except Exception as e:
        o["v6_route_default"] = type(e).__name__

    # infra-node ULA: confirm again + probe 8000 (probe port pattern) identification-only
    ula = "fda7:a938:5bfe:5fa6:0:5ea:2f7c:59f8"
    o["ula_banner"] = None
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(2)
        s.connect((ula, 22))
        o["ula_banner"] = s.recv(80).decode("utf-8", "replace").strip()
        s.close()
    except Exception as e:
        o["ula_banner"] = type(e).__name__
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__ + ": " + str(e)[:120]
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
