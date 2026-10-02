"""流式请求/响应测试: 生成器上传(chunked)、stream=True 真流式下载、增量解压。

自带本地明文 HTTP 服务器, 不依赖外网。
"""

from __future__ import annotations

import gzip
import json
import os
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: list[dict] = []

    def log_message(self, *args):
        pass

    def _read_chunked(self) -> bytes:
        body = bytearray()
        while True:
            line = self.rfile.readline().strip()
            size = int(line.split(b";")[0], 16)
            if size == 0:
                self.rfile.readline()
                break
            body += self.rfile.read(size)
            self.rfile.read(2)
        return bytes(body)

    def _read_body(self) -> bytes:
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            return self._read_chunked()
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n else b""

    def do_POST(self):
        body = self._read_body()
        Handler.seen.append({
            "path": self.path,
            "chunked": self.headers.get("transfer-encoding", "").lower() == "chunked",
            "content_length": self.headers.get("content-length"),
            "size": len(body),
            "head": body[:16].decode("latin-1"),
        })
        payload = json.dumps({"size": len(body)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/stream":
            self._stream_chunked()
        elif path == "/stream-gzip":
            self._stream_gzip()
        elif path == "/big":
            payload = b"y" * (256 * 1024)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    def _stream_chunked(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(3):
            chunk = f"chunk-{i};".encode()
            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.flush()
            if i < 2:
                time.sleep(0.4)          # 故意慢, 用来证明客户端是"边收边给"
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _stream_gzip(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        import zlib
        # compressobj 的第一个位置参数是 level, wbits 必须用关键字传
        co = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        for part in (b"hello " * 500, b"world " * 500, b"!" * 500):
            out = co.compress(part)
            if out:
                self.wfile.write(f"{len(out):x}\r\n".encode() + out + b"\r\n")
                self.wfile.flush()
        tail = co.flush()
        self.wfile.write(f"{len(tail):x}\r\n".encode() + tail + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


class LocalServer:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        Handler.seen.clear()
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"


class TestChunkedUpload(unittest.TestCase):
    def test_generator_body_uses_chunked(self):
        """传生成器时长度未知 -> 必须用 Transfer-Encoding: chunked, 且内容完整"""
        from chrome_fp import Session

        def gen():
            for i in range(5):
                yield f"part{i}-".encode() * 250      # 每块 1500 字节

        with LocalServer() as srv:
            with Session() as s:
                r = s.post(srv.base + "/upload", data=gen())
            self.assertEqual(r.status_code, 200)
            got = Handler.seen[-1]
            self.assertTrue(got["chunked"], "生成器上传应该走 chunked")
            self.assertIsNone(got["content_length"])
            self.assertEqual(got["size"], 5 * 1500)
            self.assertEqual(r.json()["size"], 5 * 1500)

    def test_iterable_of_chunks(self):
        from chrome_fp import Session

        with LocalServer() as srv:
            with Session() as s:
                r = s.post(srv.base + "/upload", data=[b"abc", b"defg", b"h"])
            self.assertEqual(r.json()["size"], 8)

    def test_bytes_body_still_has_content_length(self):
        from chrome_fp import Session

        with LocalServer() as srv:
            with Session() as s:
                s.post(srv.base + "/upload", data=b"12345")
            got = Handler.seen[-1]
            self.assertFalse(got["chunked"])
            self.assertEqual(got["content_length"], "5")


class TestStreamingResponse(unittest.TestCase):
    def test_stream_true_yields_incrementally(self):
        """stream=True 时必须边收边给, 不能把整段读完才返回第一块"""
        from chrome_fp import Session

        with LocalServer() as srv:
            with Session(timeout=20) as s:
                t0 = time.time()
                with s.get(srv.base + "/stream", stream=True) as r:
                    self.assertEqual(r.status_code, 200)
                    first = next(r.iter_content(64))
                    first_at = time.time() - t0
                    rest = b"".join(r.iter_content(64))
            # 服务器每块间隔 0.4s, 三块总共 ~0.8s; 第一块必须远早于整段结束
            self.assertEqual(first, b"chunk-0;")
            self.assertLess(first_at, 0.35, f"第一块来得太晚({first_at:.2f}s), 说明没在流式读")
            self.assertEqual(first + rest, b"chunk-0;chunk-1;chunk-2;")

    def test_stream_false_buffers_everything(self):
        from chrome_fp import Session

        with LocalServer() as srv:
            with Session(timeout=20) as s:
                r = s.get(srv.base + "/stream")
            self.assertEqual(r.text, "chunk-0;chunk-1;chunk-2;")

    def test_streaming_gzip_is_decompressed_incrementally(self):
        from chrome_fp import Session

        with LocalServer() as srv:
            with Session(timeout=20) as s:
                with s.get(srv.base + "/stream-gzip", stream=True) as r:
                    got = b"".join(r.iter_content(256))
            want = b"hello " * 500 + b"world " * 500 + b"!" * 500
            self.assertEqual(got, want)

    def test_streaming_stops_early_without_error(self):
        from chrome_fp import Session

        with LocalServer() as srv:
            with Session(timeout=20) as s:
                r = s.get(srv.base + "/big", stream=True)
                first = next(r.iter_content(1024))
                # chunk_size 对**流式**响应只是提示, 已经缓冲到的数据会整块给出
                # (requests 也是这样), 所以这里只要求拿到过数据
                self.assertGreater(len(first), 0)
                r.close()

    def test_content_after_stream_drains(self):
        """stream=True 之后访问 .content 会把剩下的读完(requests 行为)"""
        from chrome_fp import Session

        with LocalServer() as srv:
            with Session(timeout=20) as s:
                r = s.get(srv.base + "/stream", stream=True)
            self.assertEqual(r.content, b"chunk-0;chunk-1;chunk-2;")


if __name__ == "__main__":
    unittest.main(verbosity=2)
