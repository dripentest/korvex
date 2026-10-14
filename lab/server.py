#!/usr/bin/env python3
"""Stack-Fingerprinter test lab. One persona per container, selected by $PERSONA.

Pure stdlib (runs on the imported lab-base image). Each persona is crafted to
exercise a specific detection path or a known weak point (see
docs/arch-review-and-lab.md).
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PERSONA = os.environ.get("PERSONA", "flask")
PORT = int(os.environ.get("PORT", "80"))

# A random, high-entropy base64 session value — must NOT be flagged as a
# serialized object (weak point A8).
RANDOM_SESSION = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG0="

APP_JS = (
    b"const API='/api/internal/users';\n"
    b"fetch('/api/v2/orders?id=1');\n"
    b"// decoy: not a real secret password = short\n"
    b"const AWS='AKIAIOSFODNN7EXAMPLE';\n"
    b"const tok='eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abcdefghijklmnop';\n"
    b"const slack='xoxb-1234567890-ABCDEFGHIJKLMNOPQRSTUVWX';\n"
    b"var endpoint='/admin/dashboard';\n"
)

def robots(host):
    return (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /backup/secret.sql\n"
        "Disallow: /api/internal\n"
        f"Sitemap: http://{host}/sitemap.xml\n"
    ).encode()


def sitemap(host):
    return (
        '<?xml version="1.0"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <sitemap><loc>http://{host}/sitemap-extra.xml</loc></sitemap>\n"
        "</sitemapindex>\n"
    ).encode()


def sitemap_extra(host):
    return (
        '<?xml version="1.0"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>http://{host}/hidden/panel</loc></url>\n"
        f"  <url><loc>http://{host}/reports/2024</loc></url>\n"
        "</urlset>\n"
    ).encode()

HOME_HTML = b'<html><body><h1>lab</h1><script src="/static/app.js"></script></body></html>'


def _resp(status, headers=None, body=b""):
    return status, list(headers or []), body if isinstance(body, bytes) else body.encode()


def handle(persona, path, req_headers):
    """Return (status, [(header, value), ...], body_bytes)."""
    origin = req_headers.get("Origin")

    if persona == "flask":
        if path == "/console":
            return _resp(200, [("Server", "Werkzeug/2.0.2 Python/3.10.12")], b"console")
        if path == "/debug":
            return _resp(200, [("Server", "Werkzeug/2.0.2 Python/3.10.12")], b"debug")
        if path == "/":
            return _resp(200, [
                ("Server", "Werkzeug/2.0.2 Python/3.10.12"),
                ("Set-Cookie", f"session={RANDOM_SESSION}; Path=/"),
            ], HOME_HTML)
        return _resp(404, [("Server", "Werkzeug/2.0.2 Python/3.10.12")], b"nf")

    if persona == "php":
        base = [("X-Powered-By", "PHP/7.4.3"),
                ("Set-Cookie", f"PHPSESSID={RANDOM_SESSION}; path=/")]
        if path == "/composer.json":
            return _resp(200, base, b'{"require":{"monolog/monolog":"1.0"}}')
        if path == "/.env":
            return _resp(200, base, b"APP_KEY=base64:deadbeef\nDB_PASSWORD=hunter2\n")
        if path == "/phpmyadmin/":
            return _resp(403, base, b"forbidden")
        if path == "/":
            return _resp(200, base, HOME_HTML)
        return _resp(404, base, b"nf")

    if persona in ("cors-reflect", "cors-null", "cors-wildcard"):
        h = []
        if persona == "cors-reflect" and origin:
            h += [("Access-Control-Allow-Origin", origin),
                  ("Access-Control-Allow-Credentials", "true")]
        elif persona == "cors-null":
            h += [("Access-Control-Allow-Origin", "null"),
                  ("Access-Control-Allow-Credentials", "true")]
        elif persona == "cors-wildcard":
            h += [("Access-Control-Allow-Origin", "*")]
        if path == "/":
            return _resp(200, h + [("Content-Type", "application/json")], b'{"ok":true}')
        return _resp(404, h, b"nf")  # realistic: API 404s unknown paths

    if persona == "deser":
        # Java serialized stream, base64 → starts with rO0AB
        java_cookie = "rO0ABXQABGphdmE"
        if path == "/":
            body = b'<html><form><input type="hidden" name="__VIEWSTATE" value="/wEPDwUK"/></form></html>'
            return _resp(200, [("Set-Cookie", f"SESS={java_cookie}; path=/")], body)
        return _resp(404, [], b"nf")

    if persona == "origin403":
        # Weak point A1/A3: reject any cross-origin request wholesale.
        if origin:
            return _resp(403, [("Server", "nginx")], b"cross-origin denied")
        return _resp(200, [("Server", "nginx")], HOME_HTML)

    if persona == "login-redirect":
        sec = [("Strict-Transport-Security", "max-age=63072000"),
               ("Content-Security-Policy", "default-src 'self'"),
               ("X-Frame-Options", "DENY"),
               ("X-Content-Type-Options", "nosniff")]
        if path == "/":
            return _resp(302, sec + [("Location", "/login")], b"")
        if path == "/login":
            return _resp(200, sec + [("Set-Cookie", f"sessionid={RANDOM_SESSION}; HttpOnly; Secure; SameSite=Lax")], b"login")
        return _resp(404, sec, b"nf")

    if persona == "deep-headers":
        # Weak point A2: root reveals nothing; stack only on /api/.
        if path == "/api/":
            return _resp(200, [("X-Powered-By", "Express"),
                               ("Set-Cookie", f"connect.sid={RANDOM_SESSION}; path=/")], b'{"users":[]}')
        if path == "/":
            return _resp(200, [("Content-Type", "text/html")], b"<html>home</html>")
        return _resp(404, [], b"nf")

    if persona == "passive":
        host = req_headers.get("Host", "127.0.0.1")
        if path == "/robots.txt":
            return _resp(200, [("Content-Type", "text/plain")], robots(host))
        if path == "/sitemap.xml":
            return _resp(200, [("Content-Type", "application/xml")], sitemap(host))
        if path == "/sitemap-extra.xml":
            return _resp(200, [("Content-Type", "application/xml")], sitemap_extra(host))
        if path == "/static/app.js":
            return _resp(200, [("Content-Type", "application/javascript")], APP_JS)
        if path == "/":
            return _resp(200, [("Content-Type", "text/html")], HOME_HTML)
        return _resp(404, [], b"nf")

    if persona == "spa":
        # React/Vue SPA behind nginx: a catch-all route serves index.html for
        # every path (classic soft-404). Extremely common in production.
        return _resp(200, [("Content-Type", "text/html"), ("Cache-Control", "no-cache")],
                     b'<!doctype html><html><head><title>App</title></head>'
                     b'<body><div id="root"></div><script src="/static/main.js"></script></body></html>')

    if persona == "hostile":
        # Weak point A9: hostile value in a header that DOES match a signature,
        # so the attacker string lands in a graph node's `source` metadata.
        xss_server = 'Werkzeug/2.0.1</script><img src=x onerror=alert(1)>'
        if path == "/":
            return _resp(200, [("Server", xss_server),
                               ("Set-Cookie", f"s={RANDOM_SESSION}; Path=/")], HOME_HTML)
        return _resp(404, [("Server", xss_server)], b"nf")

    return _resp(200, [("Server", "lab")], b"default")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self):
        status, headers, body = handle(PERSONA, self.path.split("#")[0], self.headers)
        sent = {k.lower() for k, _ in headers}
        # Realistic single Server header (no Python BaseHTTP default leaking in).
        self.send_response_only(status)
        self.send_header("Date", self.date_time_string())
        if "server" not in sent:
            self.send_header("Server", "nginx/1.24.0")
        if "content-type" not in sent:
            self.send_header("Content-Type", "text/html")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def version_string(self):
        return "nginx/1.24.0"

    do_GET = _send
    do_HEAD = _send

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"persona={PERSONA} port={PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
