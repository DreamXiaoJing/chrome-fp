"""Accept-CH / 高熵 client hints 与 cookie 位置的测试。

背景: 不少 CDN 会下发 `Accept-CH: sec-ch-ua-full-version, ...`, 真 Chrome 会在**后续**
请求里带上这些高熵 hint。完全不发的话, 一眼就能看出不是浏览器 —— 这是比 JA3 更硬的
信号。这里自带一个会下发 Accept-CH 的 TLS+h2 服务器做端到端验证。
"""

from __future__ import annotations

import os
import socket
import ssl
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from test_tls_features import make_cert  # noqa: E402

ACCEPT_CH = ("sec-ch-ua-full-version-list, sec-ch-ua-full-version, sec-ch-ua-arch, "
             "sec-ch-ua-bitness, sec-ch-ua-model, sec-ch-ua-platform-version, "
             "sec-ch-ua-wow64, device-memory, dpr, viewport-width, "
             "viewport-height, rtt, downlink, ect")


class HintServer:
    """TLS+h2 服务器: 第一个响应下发 Accept-CH, 并记录收到的请求头顺序"""

    def __init__(self, cert: str, key: str, accept_ch: str | None = ACCEPT_CH):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.ctx.set_alpn_protocols(["h2"])
        self.accept_ch = accept_ch
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.requests: list[list[tuple[str, str]]] = []
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=5)

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, raw: socket.socket):
        import h2.config
        import h2.connection
        import h2.events

        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except Exception:  # noqa: BLE001
            return
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        h2c = h2.connection.H2Connection(config=cfg)
        h2c.initiate_connection()
        conn.sendall(h2c.data_to_send())
        sent_accept_ch = False
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                for ev in h2c.receive_data(data):
                    if isinstance(ev, h2.events.RequestReceived):
                        self.requests.append(list(ev.headers))
                        body = b"ok"
                        headers = [(":status", "200"), ("content-type", "text/plain"),
                                   ("content-length", str(len(body)))]
                        if self.accept_ch and not sent_accept_ch:
                            headers.append(("accept-ch", self.accept_ch))
                            sent_accept_ch = True
                        h2c.send_headers(ev.stream_id, headers)
                        h2c.send_data(ev.stream_id, body, end_stream=True)
                out = h2c.data_to_send()
                if out:
                    conn.sendall(out)
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class TestAcceptCh(unittest.TestCase):
    def test_hints_sent_only_after_accept_ch(self):
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with HintServer(cert, key) as srv:
                with Session(verify=False, timeout=20) as s:
                    base = f"https://127.0.0.1:{srv.port}"
                    s.get(base + "/first")          # 这次还没有 Accept-CH 生效
                    s.get(base + "/second")         # 这次应该带上
            first, second = self._by_path(srv, "/first"), self._by_path(srv, "/second")
            self.assertFalse([k for k in first if k in _HIGH], "第一次不该有高熵 hint")
            got = [k for k, _ in second if k in _HIGH]
            self.assertTrue(got, "第二次应该带上高熵 hint")
            self.assertEqual(got, [h for h in _ORDER if h in _HIGH])

    def test_hint_header_order_matches_chrome(self):
        """带 hint 的头顺序必须和探针抓包里 Chrome 的一致"""
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with HintServer(cert, key) as srv:
                with Session(verify=False, timeout=20) as s:
                    base = f"https://127.0.0.1:{srv.port}"
                    s.get(base + "/a")
                    s.get(base + "/b", headers={"referer": base + "/a"})
            names = [k for k, _ in self._by_path(srv, "/b")]
            # 探针抓包实测的顺序(带 hint 的子资源请求)
            self.assertEqual(names[:20], [
                ":method", ":authority", ":scheme", ":path",
                "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "viewport-width",
                "device-memory", "sec-ch-ua", "sec-ch-ua-model", "sec-ch-ua-mobile",
                "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch",
                "sec-ch-ua-full-version", "downlink", "ect", "dpr", "user-agent", "rtt",
            ], f"实际顺序: {names}")

    def test_hint_values(self):
        from chrome_fp import Session, spec

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with HintServer(cert, key) as srv:
                with Session(verify=False, timeout=20) as s:
                    base = f"https://127.0.0.1:{srv.port}"
                    s.get(base + "/a")
                    s.get(base + "/b")
            h = dict(self._by_path(srv, "/b"))
            self.assertEqual(h["sec-ch-ua-full-version"],
                             f'"{spec.CHROME_VERSION}"')
            self.assertEqual(h["sec-ch-ua-bitness"], '"64"')
            self.assertEqual(h["sec-ch-ua-wow64"], "?0")
            self.assertEqual(h["device-memory"], "8")
            self.assertEqual(h["ect"], "4g")

    def test_values_can_be_overridden(self):
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with HintServer(cert, key) as srv:
                with Session(verify=False, timeout=20,
                             client_hint_values={"device-memory": "4"}) as s:
                    base = f"https://127.0.0.1:{srv.port}"
                    s.get(base + "/a")
                    s.get(base + "/b")
            self.assertEqual(dict(self._by_path(srv, "/b"))["device-memory"], "4")

    def test_disabled_never_sends_hints(self):
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with HintServer(cert, key) as srv:
                with Session(verify=False, timeout=20, client_hints=False) as s:
                    base = f"https://127.0.0.1:{srv.port}"
                    s.get(base + "/a")
                    s.get(base + "/b")
            self.assertEqual([k for k, _ in self._by_path(srv, "/b") if k in _HIGH], [])

    def test_no_hints_when_server_does_not_ask(self):
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with HintServer(cert, key, accept_ch=None) as srv:
                with Session(verify=False, timeout=20) as s:
                    base = f"https://127.0.0.1:{srv.port}"
                    s.get(base + "/a")
                    s.get(base + "/b")
            self.assertEqual([k for k, _ in self._by_path(srv, "/b") if k in _HIGH], [])

    def test_unknown_tokens_ignored(self):
        """Accept-CH 里的未知/乱造 token 不能变成头发出去"""
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with HintServer(cert, key, accept_ch="x-not-a-hint, device-memory") as srv:
                with Session(verify=False, timeout=20) as s:
                    base = f"https://127.0.0.1:{srv.port}"
                    s.get(base + "/a")
                    s.get(base + "/b")
            names = [k for k, _ in self._by_path(srv, "/b")]
            self.assertIn("device-memory", names)
            self.assertNotIn("x-not-a-hint", names)

    @staticmethod
    def _by_path(srv: HintServer, path: str):
        for headers in srv.requests:
            if any(k == ":path" and v == path for k, v in headers):
                return headers
        raise AssertionError(f"服务器没收到 {path}")


class TestCookiePlacement(unittest.TestCase):
    def test_cookie_sits_between_accept_language_and_priority(self):
        """探针抓包实测: cookie 在 accept-language 之后、priority 之前。

        注意断言的是**本库发出去的**头列表(r.request_headers), 不是服务端 h2 事件里的:
        h2 库按 RFC 9113 §8.1.2.5 会把 cookie 字段重组并挪到末尾, 直接看服务端事件
        会误判成"顺序错了"(这个坑踩过一次)。
        """
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with HintServer(cert, key, accept_ch=None) as srv:
                with Session(verify=False, timeout=20) as s:
                    base = f"https://127.0.0.1:{srv.port}"
                    r = s.get(base + "/a", cookies={"sid": "x"})
            names = [k for k, _ in r.request_headers]
            self.assertIn("cookie", names)
            self.assertLess(names.index("accept-language"), names.index("cookie"))
            self.assertLess(names.index("cookie"), names.index("priority"))
            # 服务端确实收到了 cookie(只是 h2 库把它挪到末尾了)
            self.assertEqual(dict(TestAcceptCh._by_path(srv, "/a")).get("cookie"), "sid=x")


_HIGH = {
    "sec-ch-ua-full-version-list", "sec-ch-ua-full-version", "sec-ch-ua-arch",
    "sec-ch-ua-bitness", "sec-ch-ua-model", "sec-ch-ua-platform-version",
    "sec-ch-ua-wow64", "device-memory", "dpr", "viewport-width", "viewport-height",
    "rtt", "downlink", "ect",
}
_ORDER = [
    "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "viewport-width",
    "device-memory", "sec-ch-ua", "sec-ch-ua-model", "sec-ch-ua-mobile",
    "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch",
    "sec-ch-ua-full-version", "downlink", "ect", "dpr", "user-agent", "rtt",
    "sec-ch-ua-platform-version", "viewport-height",
]


if __name__ == "__main__":
    unittest.main(verbosity=2)
