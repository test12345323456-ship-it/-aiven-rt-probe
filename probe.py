import json, os, re, ssl, socket, threading, urllib.request, urllib.error, urllib.parse, time, base64, hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
V2 = "fleetx-v3"

def http(url, timeout=4, n=9000):
    try:
        ctx = ssl._create_unverified_context()
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        r = op.open(urllib.request.Request(url, headers={"User-Agent": "rtprobe-v2"}), timeout=timeout)
        return {"status": r.status, "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": r.read(n).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try: body = e.read(n).decode("utf-8", "replace")
        except Exception: body = ""
        return {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()}, "body": body}
    except Exception as e:
        return {"error": type(e).__name__}

def tcp_probe(host, port, tls=0, read_wait=1.4, send=None, sni=None):
    out = {"host": host, "port": port, "tls": bool(tls)}
    t0 = time.time()
    try:
        s = socket.socket(); s.settimeout(3.5)
        s.connect((host, int(port)))
        out["connect"] = "open"
        if tls:
            try:
                ctx = ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=sni or host)
                out["tls"] = s.version()
            except Exception as e:
                out["tls_err"] = type(e).__name__ + ":" + str(e)[:60]
        if send:
            try: s.send(send)
            except Exception as e: out["send_err"] = type(e).__name__
        s.settimeout(read_wait)
        try:
            d = s.recv(400)
            out["banner"] = d[:400].decode("utf-8", "replace")
        except (socket.timeout, ssl.SSLWantReadError):
            out["banner"] = None
        except Exception as e:
            out["banner_err"] = type(e).__name__
        s.close()
    except (ConnectionRefusedError, ConnectionResetError) as e:
        out["connect"] = "refused"
    except socket.timeout:
        out["connect"] = "timeout"
    except OSError as e:
        out["connect"] = "oserr:" + str(e)[:70]
    out["ms"] = int((time.time() - t0) * 1000)
    return out

def _esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")

def resp_probe(host, port, user, password, cmds=None):
    """TLS RESP probe: AUTH + PING + INFO + CONFIG subset + CLIENT INFO."""
    out = {"host": host, "port": port}
    try:
        ctx = ssl._create_unverified_context()
        s = socket.create_connection((host, int(port)), timeout=8)
        s = ctx.wrap_socket(s); s.settimeout(6)
        def _readline_r(buf):
            while b"\r\n" not in buf:
                d = s.recv(4096)
                if not d: break
                buf += d
            ln, _, buf = buf.partition(b"\r\n")
            return ln, buf
        def _value(ln, buf):
            c = ln[:1]
            if c == b"$":
                n = int(ln[1:])
                if n == -1: return None, buf
                return buf[:n], buf[n + 2:]
            if c == b"*":
                n = int(ln[1:])
                if n == -1: return [], buf
                arr = []
                for _ in range(n):
                    ln2, buf = _readline_r(buf)
                    v, buf = _value(ln2, buf)
                    arr.append(v)
                return arr, buf
            if c == b"-": return ("ERR", ln[1:].decode("utf-8", "replace")[:180]), buf
            return ln[1:].decode("utf-8", "replace"), buf
        def cmd(*args):
            args = [a.encode() if isinstance(a, str) else a for a in args]
            payload = b"*" + str(len(args)).encode() + b"\r\n"
            for a in args:
                payload += b"$" + str(len(a)).encode() + b"\r\n" + a + b"\r\n"
            s.send(payload)
            buf = b""
            ln, buf = _readline_r(buf)
            return ln, buf
        ln, buf = cmd("AUTH", user or "default", password or "")
        out["auth"] = buf[:120].decode("utf-8", "replace") if ln == b"+OK" else _value(ln, buf)[0]
        successes = {}
        plan = cmds or [(b"PING",), (b"INFO", b"server"), (b"CLIENT", b"INFO"),
                        (b"CONFIG", b"GET", b"maxmemory*"), (b"CONFIG", b"GET", b"*dir*")]
        ln, buf = cmd("PING"); out["ping"] = "+PONG" if ln == b"+PONG" else ln[:80].decode("utf-8", "replace")
        for cargs in plan:
            ln, buf = cmd(*cargs)
            try:
                successes[cargs[0].decode() + (" " + cargs[1].decode() if len(cargs) > 1 and isinstance(cargs[1], bytes) else "")[:28]] = (ln + b" ||| " + buf[:500]).decode("utf-8", "replace")
            except Exception:
                successes[join_args_safe(cargs)] = "raw: " + repr(ln)[:80]
        out["probe"] = json.dumps(successes)[:1400]
        try: s.close()
        except Exception: pass
    except Exception as e:
        out["err"] = type(e).__name__ + ":" + str(e)[:110]
    return out

def join_args_safe(cargs):
    try: return " ".join(x.decode() for x in cargs[:2])
    except Exception: return "cmd"

def http_probe(host, port, path="/", method="GET", tls=1, host_hdr=None,
               sni=None, basic=None, body=None, hdrs=None, n_read=12000):
    try:
        s = socket.create_connection((host, int(port)), timeout=8); s.settimeout(8)
        if tls:
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(s, server_hostname=(sni or host))
        hn = host_hdr or host
        req = f"{method} {path} HTTP/1.1\r\nHost: {hn}\r\nUser-Agent: rtprobe-v2\r\nConnection: close\r\n"
        if basic:
            req += "Authorization: Basic " + base64.b64encode(basic.encode()).decode() + "\r\n"
        for h in (hdrs or []):
            if ":" in h: req += h + "\r\n"
        req += "Content-Length: " + str(len((body or "").encode())) + "\r\n\r\n"
        req += (body or "")
        s.send(req.encode())
        d = b""
        while len(d) < n_read:
            chunk = s.recv(4096)
            if not chunk: break
            d += chunk
        s.close()
        head, _, bd = d.partition(b"\r\n\r\n")
        return {"dest": f"{host}:{port}{path}", "head": head[:800].decode("utf-8", "replace"),
                "body": bd[:3000].decode("utf-8", "replace")}
    except Exception as e:
        return {"err": type(e).__name__ + ":" + str(e)[:110]}

def dns_one(host):
    addrs, err = [], None
    try:
        for fam, _t, _p, _cn, sa in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            a = sa[0]
            if a not in addrs: addrs.append(a)
    except Exception as e:
        err = type(e).__name__ + ":" + str(e)[:80]
    return {"host": host, "addrs": addrs[:8], "err": err}

def mysql_probe(host, port, user, password):
    out = {"kind": "mysql", "host": host, "port": port}
    def token_native(pw, salt):
        if not pw: return b""
        p1 = hashlib.sha1(pw.encode()).digest()
        p2 = hashlib.sha1(p1).digest()
        sb = hashlib.sha1(salt + p2).digest()
        return bytes(a ^ b for a, b in zip(sb, p1))
    def token_sha2(pw, nonce):
        if not pw: return b""
        s1 = hashlib.sha256(pw.encode()).digest()
        s2 = hashlib.sha256(s1).digest()
        s3 = hashlib.sha256(s2 + nonce).digest()
        return bytes(a ^ b for a, b in zip(s3, s1))
    try:
        s = socket.create_connection((host, int(port)), timeout=8)
        s.settimeout(10)
        def rpkt():
            h = b""
            while len(h) < 4:
                c = s.recv(4 - len(h))
                if not c: raise EOFError("hdr")
                h += c
            ln = h[0] | (h[1] << 8) | (h[2] << 16)
            body = b""
            while len(body) < ln:
                c = s.recv(ln - len(body))
                if not c: raise EOFError("body")
                body += c
            return h[3], body
        def wpkt(body, seq):
            s.sendall(bytes([len(body) & 0xFF, (len(body) >> 8) & 0xFF, (len(body) >> 16) & 0xFF, seq & 0xFF]) + body)
        seq, hs = rpkt()
        i = 1
        j = hs.index(b"\x00", i); ver = hs[i:j].decode("utf-8", "replace"); i = j + 1
        i += 4
        salt = hs[i:i + 8]; i += 8 + 1
        capl = hs[i] | (hs[i + 1] << 8); i += 2
        i += 1 + 2
        caphi = hs[i] | (hs[i + 1] << 8); i += 2
        caps = capl | (caphi << 16); i += 1
        try: salt2 = hs[i:i + 13].split(b"\x00")[0][:12]
        except Exception: salt2 = b""
        salt = (salt + salt2)[:20]
        i += 13
        els = hs[i:].split(b"\x00")
        plugin = els[0].decode("utf-8", "replace") if els and els[0] else "unknown"
        out["handshake"] = {"ver": ver, "caps": hex(caps), "plugin": plugin}
        token = token_native(password, salt) if "native" in plugin else b""
        caps_cli = 0x00000001 | 0x00000200 | 0x00002000 | 0x00008000 | 0x00080000
        body = caps_cli.to_bytes(4, "little") + (1 << 24).to_bytes(4, "little") + bytes([255]) + b"\x00" * 23
        body += user.encode() + b"\x00" + bytes([len(token)]) + token
        body += plugin.encode() + b"\x00"
        wpkt(body, seq + 1)
        seq, rep = rpkt()
        if rep[:1] == b"\x00":
            out["auth"] = "ok"
        elif rep[:1] == b"\xff":
            out["auth"] = "err " + rep[3:9].decode("latin1") + " " + rep[9:170].decode("utf-8", "replace")
            return out
        elif rep[:1] == b"\xfe":
            j2 = rep.index(b"\x00", 1)
            sw_plugin = rep[1:j2].decode("utf-8", "replace")
            sw_salt = rep[j2 + 1:j2 + 21]
            out["auth"] = "switch:" + sw_plugin
            t2 = token_native(password, sw_salt) if "native" in sw_plugin else (token_sha2(password, sw_salt) if "sha2" in sw_plugin else b"")
            wpkt(bytes([len(t2)]) + t2, 3)
            for _ in range(3):
                seq, rep = rpkt()
                if rep[:1] == b"\x00": out["auth"] += " -> ok"; break
                if rep[:2] == b"\x01\x03": continue
                if rep[:2] == b"\x01\x04":
                    out["auth"] += " -> full-auth(cleartext)"
                    wpkt(password.encode() + b"\x00", 5)
                    continue
                if rep[:1] == b"\xff":
                    out["auth"] += " -> err " + rep[3:120].decode("utf-8", "replace"); break
                out["auth"] += " -> ?" + repr(rep[:40]); break
        else:
            out["auth"] = "unexpected " + str(rep[:70])
        if out["auth"] != "ok":
            return out
        def parse_row(body):
            vals, p = [], 0
            while p < len(body) and len(vals) <= 6:
                b0 = body[p]
                if b0 == 0xFB: vals.append(None); p += 1
                elif b0 == 0xFC:
                    ln = body[p + 1] | (body[p + 2] << 8); vals.append(body[p + 3:p + 3 + ln].decode("utf-8", "replace")); p += 3 + ln
                elif b0 == 0xFD:
                    ln = body[p + 1] | (body[p + 2] << 8) | (body[p + 3] << 16); vals.append(body[p + 4:p + 4 + ln].decode("utf-8", "replace")); p += 4 + ln
                elif b0 == 0xFE:
                    ln = int.from_bytes(body[p + 1:p + 9], "little"); vals.append(body[p + 9:p + 9 + ln].decode("utf-8", "replace")); p += 9 + ln
                else:
                    vals.append(body[p:p + b0].decode("utf-8", "replace")); p += b0 + 1
            return vals
        plan = [
            "SELECT @@version, @@version_comment, @@hostname, @@port, @@datadir",
            "SELECT user(), current_user()",
            "SHOW VARIABLES LIKE 'local_infile'",
            "SHOW VARIABLES LIKE 'secure_file_priv'",
            "SHOW VARIABLES LIKE 'have_ssl'",
            "SHOW VARIABLES LIKE 'have_openssl'",
            "SHOW VARIABLES LIKE 'max_allowed_packet'",
            "SHOW GRANTS",
            "SELECT plugin_name, plugin_type, plugin_status FROM information_schema.PLUGINS ORDER BY plugin_name LIMIT 12",
        ]
        rows, total = [], 0
        for sql in plan:
            try:
                wpkt(b"\x03" + sql.encode(), 0)
                seq, po = rpkt()
                if po[:1] == b"\xff":
                    rows.append(["ERR", po[3:110].decode("utf-8", "replace")]); continue
                if po[:1] == b"\x00":
                    rows.append(["OK", po[1:70].decode("utf-8", "replace")]); continue
                cc = int(po[0])
                for _ in range(cc): seq, _c = rpkt()
                seq, e = rpkt()
                if not (e[:1] == b"\xfe" and len(e) <= 5):
                    rows.append(parse_row(e))
                while total < 1200:
                    seq, rp = rpkt()
                    if rp[:1] == b"\xfe" and len(rp) <= 5: break
                    if rp[:1] == b"\xff":
                        rows.append(["ERR", rp[3:110].decode("utf-8", "replace")]); break
                    rows.append(parse_row(rp))
            except Exception as ex:
                rows.append(["EXC", type(ex).__name__ + ":" + str(ex)[:80]])
                break
        out["rows"] = [[str(v)[:110] if v is not None else "<NULL>" for v in r] for r in rows][:26]
        try: s.close()
        except Exception: pass
    except Exception as e:
        out["err"] = type(e).__name__ + ":" + str(e)[:110]
    return out

def fleetx(qs):
    q = urllib.parse.parse_qs(qs)
    kind = (q.get("q") or ["reach"])[0]
    if kind == "reach":
        targets = (q.get("targets") or [""])[0]
        sni_map = dict(t.split("=") for t in (q.get("sni") or [""])[0].split(",") if "=" in t)
        out = []
        for t in targets.split(","):
            if ":" not in t: continue
            h, p = t.rsplit(":", 1)
            out.append(tcp_probe(h.strip(), p, tls=1 if (q.get("tls") or ["0"])[0] == "1" else 0,
                                 sni=sni_map.get(h.strip())))
        return {"kind": "reach", "results": out}
    if kind == "dns":
        hosts = (q.get("hosts") or [""])[0].split(",")
        return {"kind": "dns", "results": [dns_one(h.strip()) for h in hosts if h.strip()]}
    if kind == "mysql":
        return {"kind": "mysql", "result": mysql_probe((q.get("host") or [""])[0], (q.get("port") or ["26247"])[0],
                 (q.get("user") or ["avnadmin"])[0], (q.get("pass") or [""])[0])}
    if kind == "resp":
        return {"kind": "resp", "result": resp_probe((q.get("host") or [""])[0], (q.get("port") or ["0"])[0],
                 (q.get("user") or ["default"])[0], (q.get("pass") or [""])[0])}
    if kind == "http":
        extra = [x for x in ((q.get("hdrs") or [""])[0].split("|")) if ":" in x]
        return {"kind": "http", "result": http_probe(
            (q.get("host") or [""])[0], (q.get("port") or ["0"])[0],
            (q.get("path") or ["/"])[0], (q.get("method") or ["GET"])[0],
            0 if (q.get("tls") or ["1"])[0] == "0" else 1,
            host_hdr=(q.get("hosthdr") or [None])[0],
            sni=(q.get("sni") or [None])[0],
            basic=(q.get("basic") or [None])[0],
            body=(q.get("body") or [None])[0],
            hdrs=extra)}
    if kind == "self":
        try:
            name = socket.gethostname()
            ips = [x for x in re.findall(r"(\d+\.\d+\.\d+\.\d+)", open("/proc/net/fib_trie").read())]
            v6 = re.findall(r"([0-9a-f]{4}(?::[0-9a-fx]{1,4}){2,8})", open("/proc/net/if_inet6").read()) if os.path.exists("/proc/net/if_inet6") else []
            return {"kind": "self", "hostname": name, "fib_ips": sorted(set(ips))[:40], "v6": v6[:6],
                    "routes": open("/proc/net/route").read()[:600]}
        except Exception as e:
            return {"kind": "self", "err": str(e)[:100]}
    if kind == "ping":
        return {"kind": "v", "v": V2}
    return {"err": "unknown kind"}

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        path, _, qs = self.path.partition("?")
        if path == "/" + TOKEN:
            if qs:
                body = json.dumps(fleetx(qs)).encode()
                code = 200
            else:
                body = json.dumps({"v": V2, "status": CACHE["status"]}).encode()
                code = 200
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

CACHE = {"status": "warming-up"}

def serve6():
    try:
        ctx = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        ctx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ctx.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except Exception:
            pass
        ctx.bind(("::", 8000)); ctx.listen(8)
        while True:
            c, _ = ctx.accept()
            try:
                c.settimeout(6)
                req = c.recv(2048)
                path = req.split(" ")[1] if len(req.split()) > 1 else "/"
                if path.startswith("/" + TOKEN):
                    qs = path.partition("?")[2]
                    body = json.dumps({"v": V2, "via": "v6", "r": fleetx(qs) if qs else {"ping": 1}}).encode()
                    c.send(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                else:
                    c.send(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                pass
            finally:
                try: c.close()
                except Exception: pass
    except Exception:
        pass

threading.Thread(target=serve6, daemon=True).start()
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
