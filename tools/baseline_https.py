"""最小对照: 用标准库 http.server + ssl.wrap_socket(不是我的 MemoryBIO 实现) 起个 HTTPS 服务,
看 Chrome 能不能正常握手。用来判断问题在 Chrome 参数还是在探针实现。"""
import http.server
import ssl
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
cert = ROOT / "capture" / "chrome154" / "certs" / "probe.crt"
key = ROOT / "capture" / "chrome154" / "certs" / "probe.key"

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(str(cert), str(key))
ctx.set_alpn_protocols(["h2", "http/1.1"])


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        body = b"<html><body>ok-baseline</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # noqa: A002
        print("[baseline]", *a, flush=True)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("[baseline] serving https://127.0.0.1:8443/ for 60s", flush=True)
t = threading.Timer(60, srv.shutdown)
t.start()
try:
    srv.serve_forever()
except KeyboardInterrupt:
    pass
print("[baseline] done", flush=True)
