"""requests 语法兼容性测试 —— 不需要网络, 自带一个本地明文 HTTP 服务器。

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import gzip
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import chrome_fp                              # noqa: E402
from chrome_fp import Session, structures     # noqa: E402
from chrome_fp.exceptions import HTTPError, TooManyRedirects   # noqa: E402


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received: list[dict] = []

    def log_message(self, *args):      # 静音
        pass

    def _body(self) -> bytes:
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code: int, body: bytes, ctype="text/html; charset=utf-8", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _record(self, body: bytes):
        Handler.received.append({
            "method": self.command,
            "path": self.path,
            "headers": [(k, v) for k, v in self.headers.items()],
            "body": body.decode("utf-8", "replace"),
        })

    def do_GET(self):
        path = self.path.split("?")[0]
        self._record(b"")
        if path == "/":
            self._send(200, "hello 世界".encode())
        elif path == "/json":
            self._send(200, json.dumps({"ok": True}).encode(), "application/json")
        elif path == "/gzip":
            self._send(200, gzip.compress("压缩内容".encode()), "text/plain",
                       [("Content-Encoding", "gzip")])
        elif path == "/redirect":
            self._send(302, b"", extra=[("Location", "/final")])
        elif path == "/final":
            self._send(200, b"final")
        elif path == "/set-cookie":
            self._send(200, b"ok", extra=[("Set-Cookie", "sid=abc123; Path=/")])
        elif path == "/missing":
            self._send(404, b"nope")
        else:
            self._send(200, b"ok")

    def do_POST(self):
        body = self._body()
        self._record(body)
        if self.path == "/echo":
            self._send(200, json.dumps({
                "method": self.command,
                "body": body.decode("utf-8", "replace"),
                "header_names": [k.lower() for k, _ in self.headers.items()],
                "content_type": self.headers.get("content-type", ""),
            }).encode(), "application/json")
        else:
            self._send(200, b"posted")


class LocalServer:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        Handler.received.clear()
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"


# ====================================================================== 结构

class TestStructures(unittest.TestCase):
    def test_case_insensitive_dict(self):
        d = structures.CaseInsensitiveDict({"Content-Type": "text/html"})
        self.assertEqual(d["content-type"], "text/html")
        self.assertEqual(d["CONTENT-TYPE"], "text/html")
        d["X-Test"] = "1"
        self.assertIn("x-test", d)
        self.assertEqual(d.get("X-TEST"), "1")
        self.assertEqual(len(d), 2)
        self.assertEqual(dict(d.lower_items())["x-test"], "1")

    def test_cookie_jar(self):
        jar = structures.RequestsCookieJar()
        jar.set("a", "1", domain="example.com")
        jar.set("b", "2", domain="other.com")
        self.assertEqual(jar.get("a"), "1")
        self.assertEqual(jar.get_dict(), {"a": "1", "b": "2"})
        self.assertEqual(jar.get_cookie_header("example.com"), "a=1")
        self.assertIsNone(jar.get_cookie_header("nothing.com"))
        jar["c"] = "3"
        self.assertEqual(jar["c"], "3")
        del jar["c"]
        self.assertNotIn("c", jar)

    def test_cookie_jar_from_set_cookie(self):
        jar = structures.RequestsCookieJar()
        jar.extract_cookies_from_headers("example.com", [
            ("set-cookie", "sid=xyz; Path=/; HttpOnly"),
            ("set-cookie", "theme=dark; Path=/app"),
        ])
        self.assertEqual(jar.get("sid"), "xyz")
        self.assertEqual(jar.get("theme"), "dark")
        self.assertEqual(jar.get_cookie_header("example.com", "/"), "sid=xyz")
        self.assertIn("theme=dark", jar.get_cookie_header("example.com", "/app/x") or "")
        # host-only(Set-Cookie 没带 Domain)不发子域
        self.assertIsNone(jar.get_cookie_header("sub.example.com", "/other"))


# ====================================================================== 请求

class TestRequestsSyntax(unittest.TestCase):
    def test_get_and_response_attributes(self):
        with LocalServer() as srv:
            r = chrome_fp.get(srv.base + "/")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.reason, "OK")
            self.assertTrue(r.ok)
            self.assertEqual(r.headers["content-type"], "text/html; charset=utf-8")
            self.assertEqual(r.headers["CONTENT-TYPE"], "text/html; charset=utf-8")
            self.assertIn("世界", r.text)
            self.assertEqual(r.encoding.lower(), "utf-8")
            self.assertIsInstance(r.elapsed.total_seconds(), float)
            self.assertEqual(r.url, srv.base + "/")
            self.assertTrue(bool(r))
            self.assertEqual(r.request.method, "GET")
            self.assertIn("User-Agent", r.request.headers)

    def test_params_forms(self):
        with LocalServer() as srv:
            for params, want in (
                ({"a": "1", "b": "2"}, "a=1&b=2"),
                ([("a", "1"), ("a", "2")], "a=1&a=2"),
                ("x=9", "x=9"),
            ):
                r = chrome_fp.get(srv.base + "/query", params=params)
                self.assertEqual(r.status_code, 200)
                self.assertIn(want, Handler.received[-1]["path"])

    def test_existing_query_is_preserved(self):
        """回归: URL 里原有的 ?n=0 不能被 params 处理丢掉"""
        with LocalServer() as srv:
            chrome_fp.get(srv.base + "/query?n=0")
            self.assertEqual(Handler.received[-1]["path"], "/query?n=0")
            chrome_fp.get(srv.base + "/query?n=0", params={"a": 1})
            self.assertEqual(Handler.received[-1]["path"], "/query?n=0&a=1")

    def test_session_params(self):
        with Session() as s:
            s.params = {"token": "t1"}
            with LocalServer() as srv:
                chrome_fp_sess_get(s, srv.base + "/query")
                self.assertIn("token=t1", Handler.received[-1]["path"])
                chrome_fp_sess_get(s, srv.base + "/query", params={"a": "1"})
                self.assertEqual(Handler.received[-1]["path"], "/query?token=t1&a=1")

    def test_post_json(self):
        with LocalServer() as srv:
            r = chrome_fp.post(srv.base + "/echo", json={"a": 1, "b": "中文"})
            data = r.json()
            self.assertEqual(data["method"], "POST")
            self.assertEqual(data["body"], '{"a":1,"b":"中文"}')
            self.assertEqual(data["content_type"], "application/json")

    def test_post_form_data(self):
        with LocalServer() as srv:
            r = chrome_fp.post(srv.base + "/echo", data={"a": "1", "b": "中文"})
            data = r.json()
            self.assertEqual(data["content_type"], "application/x-www-form-urlencoded")
            self.assertEqual(data["body"], "a=1&b=%E4%B8%AD%E6%96%87")

    def test_post_raw_bytes(self):
        with LocalServer() as srv:
            r = chrome_fp.post(srv.base + "/echo", data=b"\x00\x01raw")
            self.assertEqual(r.json()["body"], "\x00\x01raw")

    def test_headers_merge_and_order(self):
        """会话头 + 单次请求头: 请求头覆盖会话头, 且 Chrome 顺序被保留"""
        with Session(mode="cors", dest="empty") as s:
            s.headers.update({"X-Token": "abc", "User-Agent": "custom-ua"})
            with LocalServer() as srv:
                chrome_fp_sess_get(s, srv.base + "/", headers={"x-token": "override"})
                hdrs = dict(Handler.received[-1]["headers"])
                self.assertEqual(hdrs["User-Agent"], "custom-ua")
                self.assertEqual(hdrs["X-Token"], "override")
                names = [k.lower() for k, _ in Handler.received[-1]["headers"]]
                # 子资源 profile: sec-ch-ua-platform 在 user-agent 之前, accept 之后才是 sec-fetch-*
                self.assertLess(names.index("sec-ch-ua-platform"), names.index("user-agent"))
                self.assertLess(names.index("accept"), names.index("sec-fetch-site"))
                self.assertIn("priority", names)

    def test_cookies_round_trip(self):
        with Session() as s:
            with LocalServer() as srv:
                chrome_fp_sess_get(s, srv.base + "/set-cookie")
                self.assertEqual(s.cookies.get("sid"), "abc123")
                chrome_fp_sess_get(s, srv.base + "/")
                hdrs = dict(Handler.received[-1]["headers"])
                self.assertEqual(hdrs.get("Cookie"), "sid=abc123")
                self.assertEqual(s.cookies.get("sid"), "abc123")

    def test_request_level_cookies(self):
        with LocalServer() as srv:
            chrome_fp.get(srv.base + "/", cookies={"k": "v"})
            self.assertEqual(dict(Handler.received[-1]["headers"]).get("Cookie"), "k=v")

    def test_redirects(self):
        with LocalServer() as srv:
            r = chrome_fp.get(srv.base + "/redirect")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.text, "final")
            self.assertEqual(len(r.history), 1)
            self.assertEqual(r.history[0].status_code, 302)
            self.assertTrue(r.history[0].is_redirect)
            self.assertEqual(r.url, srv.base + "/final")

            r2 = chrome_fp.get(srv.base + "/redirect", allow_redirects=False)
            self.assertEqual(r2.status_code, 302)
            self.assertEqual(r2.headers["Location"], "/final")

    def test_too_many_redirects(self):
        with LocalServer() as srv:
            with self.assertRaises(TooManyRedirects):
                chrome_fp.get(srv.base + "/redirect", max_redirects=0)

    def test_raise_for_status(self):
        with LocalServer() as srv:
            r = chrome_fp.get(srv.base + "/missing")
            self.assertEqual(r.status_code, 404)
            self.assertFalse(r.ok)
            with self.assertRaises(HTTPError) as ctx:
                r.raise_for_status()
            self.assertEqual(ctx.exception.response.status_code, 404)

    def test_auth_basic(self):
        with LocalServer() as srv:
            chrome_fp.get(srv.base + "/", auth=("user", "pass"))
            hdrs = dict(Handler.received[-1]["headers"])
            self.assertEqual(hdrs["Authorization"], "Basic dXNlcjpwYXNz")

    def test_gzip_decoding(self):
        with LocalServer() as srv:
            r = chrome_fp.get(srv.base + "/gzip")
            # requests 语义: text/plain 没写 charset 时 encoding 默认 ISO-8859-1
            self.assertEqual(r.encoding, "ISO-8859-1")
            self.assertEqual(r.content.decode("utf-8"), "压缩内容")
            # 想要正确文本就显式用 apparent_encoding(和 requests 一样)
            r.encoding = r.apparent_encoding
            self.assertEqual(r.text, "压缩内容")
            self.assertEqual(r.headers["Content-Encoding"], "gzip")
            self.assertNotEqual(r.raw, r.content)

    def test_iter_content_and_lines(self):
        with LocalServer() as srv:
            r = chrome_fp.get(srv.base + "/")
            self.assertEqual(b"".join(r.iter_content(4)), r.content)
            # decode_unicode=False 时 iter_lines 给 bytes(和 requests 一致)
            self.assertEqual(list(r.iter_lines()), [r.content])
            self.assertEqual(list(r.iter_lines(decode_unicode=True)), [r.text])

    def test_session_context_manager_and_close(self):
        with Session() as s:
            with LocalServer() as srv:
                chrome_fp_sess_get(s, srv.base + "/")
        self.assertEqual(len(s._pool), 0)

    def test_json_decode_error(self):
        with LocalServer() as srv:
            r = chrome_fp.get(srv.base + "/")
            with self.assertRaises(chrome_fp.exceptions.JSONDecodeError):
                r.json()

    def test_missing_schema(self):
        with self.assertRaises(chrome_fp.exceptions.MissingSchema):
            chrome_fp.get("example.com")
        with self.assertRaises(chrome_fp.exceptions.InvalidSchema):
            chrome_fp.get("ftp://example.com/")

    def test_hooks(self):
        seen = []
        with LocalServer() as srv:
            chrome_fp.get(srv.base + "/", hooks={"response": [lambda r: seen.append(r.status_code)]})
        self.assertEqual(seen, [200])

    def test_prepare_request_offline(self):
        s = Session(mode="navigate", dest="document")
        p = s.prepare_request("GET", "https://example.com/a?b=1", params={"c": "2"})
        self.assertEqual(p.method, "GET")
        self.assertIn("b=1&c=2", p.url)
        names = [k for k, _ in p._h2_headers]
        # 伪头由 HTTP/2 层加, 这里只有普通头, 且顺序是 Chrome 的导航顺序
        self.assertEqual(names[:3], ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"])
        self.assertIn("upgrade-insecure-requests", names)
        self.assertLess(names.index("user-agent"), names.index("accept"))
        self.assertEqual(p.headers["sec-fetch-dest"], "document")
        self.assertEqual(p.headers["sec-fetch-user"], "?1")
        self.assertEqual(p.headers["sec-fetch-site"], "none")

    def test_bad_client_cert_path_is_explicit(self):
        """cert= 现在实现了: 文件不存在要明确报错, 而不是静默忽略"""
        from chrome_fp.exceptions import RequestException

        with self.assertRaises(RequestException) as ctx:
            chrome_fp.get("https://example.com/", cert=("no-such-cert.pem", "no-such-key.pem"))
        self.assertIn("no-such-cert.pem", str(ctx.exception))

    def test_client_cert_loaded_from_files(self):
        """cert= 支持 (cert, key) 和合并的单个 PEM, 加载后挂在 PreparedRequest 上"""
        import tempfile

        from test_tls_features import make_client_cert
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            ccert, ckey = make_client_cert(tmp)
            combined = os.path.join(tmp, "combined.pem")
            with open(combined, "wb") as out:
                for p in (ccert, ckey):
                    with open(p, "rb") as f:
                        out.write(f.read())

            s = Session()
            p = s.prepare_request("GET", "https://example.com/", cert=(ccert, ckey))
            self.assertIsNotNone(p._client_cert)
            self.assertEqual(len(p._client_cert.chain_der), 1)

            # 会话级 cert, 以及证书+私钥写在同一个 PEM 里的用法
            self.assertIsNotNone(
                Session(cert=(ccert, ckey)).prepare_request("GET", "https://x/")._client_cert)
            self.assertIsNotNone(
                Session(cert=combined).prepare_request("GET", "https://x/")._client_cert)

            # 明文 http 不需要客户端证书
            self.assertIsNone(Session().prepare_request("GET", "http://example.com/")._client_cert)

    def test_verify_and_timeout_signature(self):
        with LocalServer() as srv:
            r = chrome_fp.get(srv.base + "/", verify=False, timeout=(5, 10))
            self.assertEqual(r.status_code, 200)


def chrome_fp_sess_get(session, url, **kwargs):
    return session.get(url, **kwargs)


class TestConnectAny(unittest.TestCase):
    """连接逻辑: DNS 把黑洞 IPv6 排在前面时不能把整个超时预算烧光"""

    def test_ipv4_preferred_over_blackholed_ipv6(self):
        import socket as _socket
        import time as _time
        from unittest import mock

        from chrome_fp.session import _connect_any

        with LocalServer() as srv:
            real_gai = _socket.getaddrinfo

            def fake_gai(host, port, **kw):
                # 故意把"IPv6 黑洞"排在前面(真实 DNS 就是这么返回的)
                return [
                    (_socket.AF_INET6, _socket.SOCK_STREAM, 6, "", ("2001:db8::dead", port, 0, 0)),
                    (_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("127.0.0.1", srv.port)),
                ]

            with mock.patch.object(_socket, "getaddrinfo", fake_gai):
                t0 = _time.monotonic()
                sock = _connect_any("dual.test", srv.port, 10)
                dt = _time.monotonic() - t0
            self.assertEqual(sock.getpeername()[0], "127.0.0.1")
            sock.close()
            self.assertLess(dt, 1.0, f"IPv4 应该立刻连上, 实际 {dt:.2f}s")

    def test_total_timeout_is_bounded(self):
        import socket as _socket
        import time as _time
        from unittest import mock

        from chrome_fp.exceptions import ConnectionError as CfpConnectionError
        from chrome_fp.session import _connect_any

        def fake_gai(host, port, **kw):
            # 一个不可路由地址: connect 会一直等到我们给的时限
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("192.0.2.1", port))]

        with mock.patch.object(_socket, "getaddrinfo", fake_gai):
            t0 = _time.monotonic()
            with self.assertRaises((CfpConnectionError, TimeoutError, OSError)):
                _connect_any("blackhole.test", 443, 2)
            dt = _time.monotonic() - t0
        self.assertLess(dt, 6.0, f"整体不该超过 timeout 太多, 实际 {dt:.2f}s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
