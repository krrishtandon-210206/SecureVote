"""Zero-dependency server:  python server.py [port]   ->  http://localhost:8000"""
import json, os, sys, mimetypes
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import service

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

class Handler(BaseHTTPRequestHandler):
    def _send(self, status, data, ctype="application/json"):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(status); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw))); self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(raw)
    def _api(self, method):
        body = {}
        if method == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000: return self._send(413, {"error": "too large"})
            try: body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError: return self._send(400, {"error": "invalid JSON"})
        st, obj = service.handle(method, self.path.split("?")[0], body, dict(self.headers))
        self._send(st, obj)
    def do_POST(self): self._api("POST")
    def do_GET(self):
        p = self.path.split("?")[0]
        if p.startswith("/api/"): return self._api("GET")
        p = "/index.html" if p == "/" else p
        f = os.path.normpath(os.path.join(WEB, p.lstrip("/")))
        if not f.startswith(WEB) or not os.path.isfile(f): return self._send(404, b"not found", "text/plain")
        self._send(200, open(f, "rb").read(), mimetypes.guess_type(f)[0] or "application/octet-stream")
    def log_message(self, *a): pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 8000))
    print(f"SecureVote running at http://localhost:{port}   (admin password: {service.ADMIN_PASSWORD})")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
