"""HTTP/1.1 客户端 (ALPN = http/1.1 时使用)。头顺序同样按 Chrome 习惯。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HTTP1Response:
    status: int = 0
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    version: str = "HTTP/1.1"
    body_iter = None      # stream=True 时给的是"按需读"的生成器


REASONS = {
    200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 408: "Request Timeout", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
    504: "Gateway Timeout",
}


class HTTP1Connection:
    def __init__(self, tls_conn):
        self.tls = tls_conn
        self.buf = b""

    # ------------------------------------------------------------ 读

    def _read_until(self, sep: bytes, limit: int = 1 << 20) -> bytes:
        while sep not in self.buf:
            chunk = self.tls.recv_app(65536)
            if not chunk:
                raise ConnectionError("连接关闭")
            self.buf += chunk
            if len(self.buf) > limit:
                raise ConnectionError("响应头过大")
        idx = self.buf.index(sep) + len(sep)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def _read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.tls.recv_app(65536)
            if not chunk:
                raise ConnectionError("连接关闭")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read_chunked(self) -> bytes:
        body = bytearray()
        for chunk in self.iter_chunked():
            body += chunk
        return bytes(body)

    def iter_chunked(self):
        """逐块读 chunked 响应体(真流式, 不整段缓冲)"""
        while True:
            line = self._read_until(b"\r\n").strip()
            size = int(line.split(b";")[0], 16)
            if size == 0:
                # 读 trailer 直到空行
                while True:
                    line = self._read_until(b"\r\n")
                    if line in (b"\r\n", b"\n"):
                        break
                break
            yield self._read_exact(size)
            self._read_exact(2)   # CRLF

    # ------------------------------------------------------------ 请求

    def _send_chunked_body(self, chunks) -> None:
        """按 Transfer-Encoding: chunked 发请求体(RFC 9112 §7.1)"""
        for chunk in chunks:
            if not chunk:
                continue
            if isinstance(chunk, str):
                chunk = chunk.encode()
            self.tls.send_app(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        self.tls.send_app(b"0\r\n\r\n")

    def request(self, method: str, target: str, headers: list[tuple[str, str]],
                body: bytes | None = None, host: str = "",
                body_stream=None, stream: bool = False) -> HTTP1Response:
        lines = [f"{method} {target} HTTP/1.1"]
        has_host = any(k.lower() == "host" for k, _ in headers)
        if not has_host and host:
            lines.append(f"Host: {host}")
        lines += [f"{k}: {v}" for k, v in headers]
        chunked = body_stream is not None
        if chunked and not any(k.lower() == "transfer-encoding" for k, _ in headers):
            lines.append("Transfer-Encoding: chunked")
        if body is not None and not chunked and \
                not any(k.lower() == "content-length" for k, _ in headers):
            lines.append(f"Content-Length: {len(body)}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
        self.tls.send_app(raw)
        if chunked:
            self._send_chunked_body(body_stream)
        elif body:
            self.tls.send_app(body)

        while True:
            head = self._read_until(b"\r\n\r\n")
            first_line = head.split(b"\r\n", 1)[0]
            # 跳过 1xx 信息响应(如 100 Continue), 继续等终响应
            try:
                code = int(first_line.split(b" ")[1])
            except (IndexError, ValueError):
                break
            if not (100 <= code < 200):
                break
        text = head.decode("iso-8859-1")
        parts = text.split("\r\n")
        status_line = parts[0].split(" ", 2)
        resp = HTTP1Response()
        resp.version = status_line[0]
        resp.status = int(status_line[1])
        resp.reason = status_line[2] if len(status_line) > 2 else REASONS.get(resp.status, "")
        for line in parts[1:]:
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            resp.headers.append((k.strip(), v.strip()))

        lower = {k.lower(): v for k, v in resp.headers}
        if stream:
            resp.body_iter = self._iter_body(method, resp.status, lower)
            return resp
        if lower.get("transfer-encoding", "").lower() == "chunked":
            resp.body = self._read_chunked()
        elif "content-length" in lower:
            resp.body = self._read_exact(int(lower["content-length"]))
        elif method == "HEAD" or resp.status in (204, 304):
            resp.body = b""
        else:
            chunks = [self.buf]
            self.buf = b""
            while True:
                try:
                    c = self.tls.recv_app(65536)
                except Exception:  # noqa: BLE001
                    break
                if not c:
                    break
                chunks.append(c)
            resp.body = b"".join(chunks)
        return resp

    def _iter_body(self, method: str, status: int, lower: dict):
        """流式读响应体: 按 chunked / content-length / 读到连接关闭三种情况"""
        if method == "HEAD" or status in (204, 304):
            return
        te = lower.get("transfer-encoding", "").lower()
        if te == "chunked":
            yield from self.iter_chunked()
            return
        if "content-length" in lower:
            left = int(lower["content-length"])
            while left > 0:
                if self.buf:
                    chunk, self.buf = self.buf[:left], self.buf[left:]
                else:
                    chunk = self.tls.recv_app(min(65536, left))
                    if not chunk:
                        return
                left -= len(chunk)
                yield chunk
            return
        if self.buf:
            yield self.buf
            self.buf = b""
        while True:
            try:
                chunk = self.tls.recv_app(65536)
            except Exception:  # noqa: BLE001
                return
            if not chunk:
                return
            yield chunk
