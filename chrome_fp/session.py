"""Session / Response —— **语法与 requests 一致**, 但底层指纹与真 Chrome 153 逐字节相同。

    import chrome_fp as requests          # 当成 requests 用
    s = requests.Session()
    s.headers.update({"x-token": "abc"})
    r = s.get("https://example.com/", params={"a": 1}, timeout=10)
    r.status_code, r.headers["Content-Type"], r.text, r.json(), r.elapsed

与 requests 的对应关系:
    请求侧: get/post/put/patch/delete/head/options, request(), Session.request(),
            params/data/json/headers/cookies/auth/files/timeout/allow_redirects/
            proxies/verify/cert/stream/hooks/max_redirects
    响应侧: status_code headers text content json() url encoding apparent_encoding
            ok reason elapsed history cookies request raw_headers
            raise_for_status() is_redirect is_permanent_redirect links next
            iter_content() iter_lines() close() 以及 `with session:` 上下文
    异常:   chrome_fp.exceptions 下的完整层次(RequestException/HTTPError/...)

**请求头不再是写死一份顺序**: 真 Chrome 对导航请求和子资源请求用的头集合与顺序是不同的
(本轮抓包实测), 所以默认按 `dest`/`mode` 选一份 profile, 详见 spec.header_order。
"""

from __future__ import annotations

import binascii
import gzip
import json as _json
import os
import socket
import ssl
import time
import zlib
from collections.abc import Mapping
from datetime import timedelta
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from . import client, hello, http1, http2, spec, tls12, tls13
from .exceptions import (
    ConnectionError as _ConnectionError,
    ConnectTimeout,
    ContentDecodingError,
    HTTPError,
    InvalidSchema,
    InvalidURL,
    MissingSchema,
    NotImplementedRequestError,
    ProxyError,
    ReadTimeout,
    RequestException,
    SSLError,
    TooManyRedirects,
    URLRequired,
)
from .structures import CaseInsensitiveDict, RequestsCookieJar

try:
    import brotli
except ImportError:  # pragma: no cover
    brotli = None
try:
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None
try:
    import charset_normalizer
except ImportError:  # pragma: no cover
    charset_normalizer = None

DEFAULT_TIMEOUT = 30.0
DEFAULT_REDIRECT_LIMIT = 30
UA = spec.DEFAULT_USER_AGENT

REDIRECT_CODES = (301, 302, 303, 307, 308)
PERMANENT_REDIRECT_CODES = (301, 308)


# ====================================================================== Response


class Response:
    """requests.models.Response 的兼容实现"""

    __attrs__ = ["status_code", "headers", "url", "history", "encoding",
                 "reason", "cookies", "elapsed", "request"]

    def __init__(self):
        self.status_code: int = 0
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
        self.raw_headers: list[tuple[str, str]] = []
        self._content: bytes | None = b""
        self._raw: bytes = b""              # 解压前的原始字节
        self._raw_iter = None               # stream=True 时: 按需吐原始字节的生成器
        self._reader = None                 # stream=True 时: _StreamReader(含增量解压)
        self._close_conn = None             # 流式响应占用的连接
        self.url: str = ""
        self.http_version: str = ""
        self.reason: str = ""
        self.encoding: str | None = None
        self.history: list["Response"] = []
        self.cookies: RequestsCookieJar = RequestsCookieJar()
        self.elapsed: timedelta = timedelta(0)
        self.duration: float = 0.0
        self.request = None
        self.request_headers: list[tuple[str, str]] = []
        self.tls: dict = {}

    # ------------------------------------------------------------ 基本属性

    @property
    def ok(self) -> bool:
        try:
            self.raise_for_status()
        except HTTPError:
            return False
        return True

    @property
    def content(self) -> bytes:
        if self._content is None:
            # 流式响应: 真正读完才缓存(和 requests 一样, 访问 .content 会把流读完)
            reader = self._reader
            raw = reader.read_all() if reader is not None else b""
            self._content = _decompress(raw, (self.headers.get("content-encoding") or ""))
            self._reader = None
        return self._content

    @content.setter
    def content(self, value: bytes) -> None:
        self._content = value

    @property
    def raw(self) -> bytes:
        """解压前的响应体(requests 的 raw 是 urllib3 对象, 这里给字节更实用)"""
        if self._reader is not None:
            self._raw = self._reader.read_all()
            self._reader = None
        return self._raw

    @property
    def text(self) -> str:
        if not self._content:
            return ""
        encoding = self.encoding or self.apparent_encoding
        try:
            return str(self._content, encoding, errors="replace")
        except (LookupError, TypeError):
            return str(self._content, errors="replace")

    @property
    def apparent_encoding(self) -> str:
        if charset_normalizer is not None:
            best = charset_normalizer.from_bytes(self._content).best()
            if best and best.encoding:
                return best.encoding
        return "utf-8"

    def json(self, **kwargs):
        try:
            return _json.loads(self.text, **kwargs)
        except _json.JSONDecodeError as e:
            from .exceptions import JSONDecodeError
            raise JSONDecodeError(f"{e}", e.doc, e.pos) from None

    @property
    def is_redirect(self) -> bool:
        return self.status_code in REDIRECT_CODES and "location" in self.headers

    @property
    def is_permanent_redirect(self) -> bool:
        return self.status_code in PERMANENT_REDIRECT_CODES and "location" in self.headers

    @property
    def links(self) -> dict:
        out: dict = {}
        header = self.headers.get("link")
        if not header:
            return out
        for part in header.split(","):
            segs = [s.strip() for s in part.split(";")]
            if not segs or not segs[0].startswith("<"):
                continue
            url = segs[0].strip("<>")
            params = {}
            for seg in segs[1:]:
                if "=" in seg:
                    k, _, v = seg.partition("=")
                    params[k.strip()] = v.strip().strip('"')
            if "rel" in params:
                out[params["rel"]] = {"url": url, **params}
        return out

    @property
    def next(self):
        if self.is_redirect:
            return self.links.get("next", {}).get("url")
        return None

    # ------------------------------------------------------------ 兼容旧 API

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)

    # ------------------------------------------------------------ 方法与协议

    def raise_for_status(self) -> None:
        reason = self.reason or ""
        msg = None
        if 400 <= self.status_code < 500:
            msg = f"{self.status_code} Client Error: {reason} for url: {self.url}"
        elif 500 <= self.status_code < 600:
            msg = f"{self.status_code} Server Error: {reason} for url: {self.url}"
        if msg:
            raise HTTPError(msg, response=self)

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        if chunk_size is None or chunk_size <= 0:
            chunk_size = 1
        if self._reader is not None:
            # 真流式: 边收边解压, 不整段缓冲。
            # 这里是循环拉取而不是 yield from —— 调用方提前丢掉这个迭代器时, 不能连累
            # 底层的 _StreamReader(否则后面的块就读不出来了)。
            while True:
                try:
                    chunk = next(self._reader)
                except StopIteration:
                    return
                if decode_unicode:
                    yield chunk.decode(self.encoding or "utf-8", "replace")
                else:
                    yield chunk
        data = self.content
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            yield chunk.decode(self.encoding or "utf-8", "replace") if decode_unicode else chunk

    def iter_lines(self, chunk_size: int = 512, decode_unicode: bool = False, delimiter=None):
        pending = None
        for chunk in self.iter_content(chunk_size=chunk_size, decode_unicode=decode_unicode):
            if pending is not None:
                chunk = pending + chunk
            lines = chunk.split(delimiter) if delimiter else chunk.splitlines()
            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None
            yield from lines
        if pending is not None:
            yield pending

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        conn = getattr(self, "_close_conn", None)
        if conn is not None:
            try:
                conn.sock.close()
            except OSError:
                pass
            conn.alive = False
            self._close_conn = None
        self._content = b""

    def __bool__(self) -> bool:
        return self.ok

    def __iter__(self):
        return self.iter_content(128)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"


class PreparedRequest:
    """requests.PreparedRequest 的轻量版(供 r.request / auth 钩子使用)"""

    def __init__(self):
        self.method: str = ""
        self.url: str = ""
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
        self.body = None
        self.hooks: dict = {}
        self._client_cert = None

    def __repr__(self) -> str:
        return f"<PreparedRequest [{self.method}]>"


# ====================================================================== Session


class _Connection:
    """一条已建好的连接 + 其上的 HTTP 引擎"""

    def __init__(self, sock, tls, engine, key: tuple, host: str):
        self.sock = sock
        self.tls = tls
        self.engine = engine
        self.key = key
        self.host = host
        self.created = time.time()
        self.alive = True
        self.requests = 0


class Session:
    """requests.Session 风格的会话, 底层用真 Chrome 指纹发请求。"""

    def __init__(
        self,
        *,
        # ---- 指纹相关 ----
        proxy: str | None = None,
        mode: str = "cors",              # navigate | cors | no-cors | none
        dest: str | None = None,         # document|iframe|empty|script|style|image|font|preflight
        user_agent: str | None = None,
        origin: str | None = None,
        referer: str | None = None,
        sec_fetch_site: str | None = None,   # none|same-origin|same-site|cross-site
        priority: str | None = None,         # 覆盖 RFC 9218 priority 头, 如 "u=0, i" / "i"
        send_priority_tree: bool = False,    # Chrome 153 默认不发(见 spec)
        allow_tls12: bool = True,
        ca_file: str | None = None,
        check_certificate_transparency: bool = False,
        # ---- requests 风格 ----
        headers=None,
        cookies=None,
        auth=None,
        proxies=None,
        verify: bool = True,
        cert=None,
        timeout=DEFAULT_TIMEOUT,
        max_redirects: int = DEFAULT_REDIRECT_LIMIT,
        trust_env: bool = True,
        params=None,
        http2_enabled: bool = True,
        keylog_file: str | None = None,
        client_hints: bool = True,
        client_hint_values: dict | None = None,
        # ---- 版本 ----
        chrome_version: str = spec.DEFAULT_VERSION,      # "154"(默认) / "153"
    ):
        if mode not in ("navigate", "cors", "no-cors", "none"):
            raise ValueError(f"mode 必须是 navigate/cors/no-cors/none, 收到 {mode!r}")
        # 选定版本 profile: 之后所有 spec.* 读取都指向这一版(见 spec.__getattr__)
        self.profile = spec.get_profile(chrome_version)
        self._profile_token = spec.activate(self.profile)
        if dest is not None and dest not in spec.SUPPORTED_DESTS:
            raise ValueError(f"dest 必须是 {spec.SUPPORTED_DESTS} 之一, 收到 {dest!r}")

        self.mode = mode
        self.dest = dest
        self._user_agent = user_agent
        self.origin = origin
        self.referer = referer
        self.sec_fetch_site = sec_fetch_site
        self.priority = priority
        self.send_priority_tree = send_priority_tree
        self.allow_tls12 = allow_tls12
        self.ca_file = ca_file
        self.check_certificate_transparency = check_certificate_transparency
        self.http2_enabled = http2_enabled

        self.headers = CaseInsensitiveDict(headers or {})
        self.params: dict = dict(params or {})
        self.cookies = RequestsCookieJar(cookies or {})
        self.auth = auth
        self.proxies: dict = dict(proxies or {})
        self._proxy = proxy
        self.verify = verify
        self.cert = cert
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.trust_env = trust_env
        # 给出路径就把 TLS 会话密钥按 NSS key log 格式写进去, Wireshark 可直接解密本库流量
        self.keylog_file = keylog_file
        # 高熵 client hints: 网站用 Accept-CH 点单, 后续请求要按 Chrome 的顺序带上。
        # 不实现的话, 凡是下发过 Accept-CH 的站(不少 CDN 都发)一眼就能看出不是浏览器。
        self.client_hints = client_hints
        self.client_hint_values = dict(spec.CLIENT_HINT_VALUES)
        if client_hint_values:
            self.client_hint_values.update(client_hint_values)
        self._accept_ch: dict[tuple, list[str]] = {}   # origin -> 已开启的 hint 列表

        self._pool: dict[tuple, _Connection] = {}
        self.last_client_hello: bytes | None = None
        self.last_handshake: dict = {}
        self.adapters: dict = {}

    # ================================================================ 代理

    @staticmethod
    def _parse_proxy(proxy: str | None):
        if not proxy:
            return None
        if not isinstance(proxy, str):
            # 允许 {"http": "...", "https": "..."}
            proxy = proxy.get("https") or proxy.get("http") or proxy.get("all")
            if not proxy:
                return None
        u = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        if u.scheme not in ("http", "https", ""):
            raise InvalidSchema(f"只支持 http(s) 代理, 收到 {u.scheme!r}")
        return (u.hostname, u.port or 8080)

    def _env_proxies(self) -> dict:
        if not self.trust_env:
            return {}
        out = {}
        for scheme, names in (("http", ("http_proxy", "HTTP_PROXY")),
                              ("https", ("https_proxy", "HTTPS_PROXY")),
                              ("all", ("all_proxy", "ALL_PROXY"))):
            for name in names:
                if os.environ.get(name):
                    out[scheme] = os.environ[name]
                    break
        return out

    def _resolve_proxy(self, scheme: str, host: str, proxies: dict | None):
        """优先级: 单次请求 proxies > Session.proxies > Session(proxy=) > 环境变量"""
        no_proxy = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
        if self.trust_env and no_proxy:
            entries = [e.strip().lstrip(".") for e in no_proxy.split(",") if e.strip()]
            if any(host == e or host.endswith("." + e) for e in entries) or "*" in entries:
                return None
        table = {}
        table.update(self._env_proxies())
        if self._proxy:
            table["http"] = table["https"] = self._proxy
            table["all"] = self._proxy
        table.update({k.lower(): v for k, v in self.proxies.items()})
        if proxies:
            table.update({k.lower(): v for k, v in proxies.items()})
        chosen = table.get(scheme) or table.get("all")
        return self._parse_proxy(chosen)

    # ================================================================ 头

    @property
    def user_agent(self) -> str:
        # 动态取当前 profile 的 UA, 不能用模块级快照(否则 153 Session 会发 154 的 UA)
        return self._user_agent or spec.DEFAULT_USER_AGENT

    def _slot_values(self, method: str, parts, dest: str, mode: str,
                     body: bytes | None, origin: str | None) -> dict:
        d: dict[str, str] = {
            "sec-ch-ua": spec.DEFAULT_HEADERS["sec-ch-ua"],
            "sec-ch-ua-mobile": spec.DEFAULT_HEADERS["sec-ch-ua-mobile"],
            "sec-ch-ua-platform": spec.DEFAULT_HEADERS["sec-ch-ua-platform"],
            "user-agent": self.user_agent,
            "accept": spec.ACCEPT_BY_DEST.get(dest, spec.ACCEPT_XHR),
            "sec-fetch-dest": spec.SEC_FETCH_DEST_BY_DEST.get(dest, "empty"),
            "sec-fetch-mode": "navigate" if mode == "navigate" else mode,
            "accept-encoding": spec.DEFAULT_HEADERS["accept-encoding"],
            "accept-language": spec.DEFAULT_HEADERS["accept-language"],
            "priority": self.priority or spec.PRIORITY_BY_DEST.get(dest, "u=1, i"),
        }
        if mode == "navigate" and dest in ("document", "iframe"):
            d["upgrade-insecure-requests"] = "1"
        if dest == "document":
            d["sec-fetch-user"] = "?1"
        if self.sec_fetch_site:
            d["sec-fetch-site"] = self.sec_fetch_site
        elif mode == "navigate" and dest == "document":
            d["sec-fetch-site"] = "none"
        else:
            d["sec-fetch-site"] = "same-origin"
        if body is not None:
            d["content-length"] = str(len(body))
        if origin:
            d["origin"] = origin
        if self.referer:
            d["referer"] = self.referer
        for name in self._wanted_hints(parts, mode):
            if name in spec.CLIENT_HINT_VALUES:
                d[name] = self.client_hint_values.get(name, spec.CLIENT_HINT_VALUES[name])
        return d

    # ---- Accept-CH ----

    @staticmethod
    def _origin_key(parts, mode: str) -> tuple:
        return (parts.scheme, (parts.hostname or "").lower(), parts.port
                or (443 if parts.scheme == "https" else 80))

    def _wanted_hints(self, parts, mode: str) -> list[str]:
        """要发的高熵 hint: 只有 https + 该源明确用 Accept-CH 点过单才发"""
        if not self.client_hints or parts.scheme != "https":
            return []
        wanted = self._accept_ch.get(self._origin_key(parts, mode))
        return list(wanted) if wanted else []

    def _remember_accept_ch(self, url: str, headers) -> None:
        """记下响应里的 Accept-CH(RFC 8942)。只在安全上下文生效, 且要整个头一起看。"""
        if not self.client_hints:
            return
        parts = urlsplit(url)
        if parts.scheme != "https":
            return
        tokens: list[str] = []
        for k, v in headers:
            if k.lower() != "accept-ch":
                continue
            for tok in v.split(","):
                tok = tok.strip().lower()
                # 只认高熵的已知 hint; 带参数的 token(如 "sec-ch-ua-full-version;v=1")取名字
                name = tok.split(";")[0].strip()
                if name in spec.HIGH_ENTROPY_HINTS:
                    tokens.append(name)
        # Chrome 的发送顺序是内部固定表, 不是 Accept-CH 里的顺序
        ordered = [h for h in spec.CLIENT_HINT_ORDER if h in set(tokens)]
        key = self._origin_key(parts, "cors")
        if ordered:
            self._accept_ch[key] = ordered

    def _build_headers(self, method: str, parts, dest: str, mode: str,
                       user_headers: list[tuple[str, str]] | Mapping | None,
                       body: bytes | None,
                       origin: str | None,
                       has_body: bool | None = None,
                       hints: bool = False) -> list[tuple[str, str]]:
        """按 Chrome 的头顺序排布; 用户提供的同名头就地替换取值, 其余追加到末尾。

        has_body 与 body 分开: 流式请求体没有长度(content-length 不该出现), 但要占住
        带 body 的那套头顺序。
        """
        if has_body is None:
            has_body = body is not None
        order = spec.header_order(dest, mode, method, has_body=has_body, hints=hints)
        defaults = self._slot_values(method, parts, dest, mode, body, origin)

        if isinstance(user_headers, Mapping):
            user = [(str(k), str(v)) for k, v in user_headers.items()]
        else:
            user = [(str(k), str(v)) for k, v in (user_headers or [])]
        user_by_lower = {k.lower(): (k, v) for k, v in user}

        out: list[tuple[str, str]] = []
        emitted: set[str] = set()
        for slot in order:
            if slot in user_by_lower:
                out.append((slot, user_by_lower[slot][1]))
                emitted.add(slot)
            elif slot in defaults:
                out.append((slot, defaults[slot]))
                emitted.add(slot)
            # 否则该槽位本次不适用(例如没 body 就没有 content-length)
        for k, v in user:
            key = k.lower()
            if key in emitted or key in order:
                continue
            out.append((key, v))
            emitted.add(key)
        return out

    # ================================================================ 连接

    def _tcp_connect(self, host: str, port: int, timeout, proxy):
        try:
            if proxy:
                sock = _connect_any(proxy[0], proxy[1], timeout)
                req = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
                       f"Host: {host}:{port}\r\n\r\n").encode()
                sock.sendall(req)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise ProxyError("代理关闭了连接")
                    buf += chunk
                if b" 200" not in buf.split(b"\r\n")[0]:
                    raise ProxyError(f"代理拒绝 CONNECT: {buf[:120]!r}")
                return sock
            return _connect_any(host, port, timeout)
        except socket.timeout as e:
            raise ConnectTimeout(f"连接 {host}:{port} 超时") from e

    def _get_connection(self, scheme: str, host: str, port: int, connect_timeout,
                        read_timeout, proxy, verify: bool, client_cert=None):
        key = _pool_key(scheme, host, port, proxy, client_cert)
        conn = self._pool.get(key)
        if conn is not None and conn.alive:
            return conn
        sock = self._tcp_connect(host, port, connect_timeout, proxy)
        tls = None
        engine = None
        if scheme == "https":
            ch = hello.build_client_hello(host)
            self.last_client_hello = ch.record
            try:
                tls = client.open_connection(
                    sock, ch, verify_certs=verify, ca_file=self.ca_file,
                    timeout=read_timeout, allow_tls12=self.allow_tls12,
                    keylog_file=self.keylog_file, client_cert=client_cert,
                )
            except tls13.TLSException as e:
                raise SSLError(str(e)) from e
            alpn = tls.alpn
            self.last_handshake = {
                "tls_version": getattr(tls, "tls_version", "1.3"),
                "alpn": alpn,
                "cipher_suite": f"0x{tls.cipher_suite:04x}",
                "duration": tls.handshake_time,
                "cert": tls.peer_certificate_chain[0].subject.rfc4514_string()
                if tls.peer_certificate_chain else None,
            }
            if alpn == "h2" and self.http2_enabled:
                engine = http2.H2Connection(tls, send_priority_tree=self.send_priority_tree)
                engine.start()
            else:
                engine = http1.HTTP1Connection(tls)
        else:
            engine = http1.HTTP1Connection(_PlainSock(sock))
        conn = _Connection(sock, tls, engine, key, host)
        self._pool[key] = conn
        return conn

    def _drop_connection(self, key: tuple) -> None:
        dead = self._pool.pop(key, None)
        if dead:
            dead.alive = False
            try:
                dead.sock.close()
            except OSError:
                pass

    # ================================================================ 准备请求

    @staticmethod
    def _split_timeout(timeout):
        if timeout is None:
            return DEFAULT_TIMEOUT, DEFAULT_TIMEOUT
        if isinstance(timeout, (tuple, list)):
            if len(timeout) == 1:
                return timeout[0], timeout[0]
            return timeout[0], timeout[1]
        return timeout, timeout

    @staticmethod
    def _encode_params(params) -> str:
        if params is None:
            return ""
        if isinstance(params, (str, bytes)):
            return params.decode() if isinstance(params, bytes) else params
        items: list[tuple[str, str]] = []
        if isinstance(params, Mapping):
            src = params.items()
        else:
            src = params
        for k, v in src:
            if isinstance(v, (list, tuple)):
                for item in v:
                    items.append((k, "" if item is None else str(item)))
            else:
                items.append((k, "" if v is None else str(v)))
        return urlencode(items, doseq=True)

    @staticmethod
    def _encode_data(data, files):
        """返回 (body, content_type)。files 非空时走 multipart/form-data。

        body 可能是 bytes, 也可能是**流式对象**(生成器/文件对象) —— 后者的长度未知,
        调用方要走 chunked(HTTP/1.1)或裸 DATA(HTTP/2)。
        """
        if files:
            boundary = binascii.hexlify(os.urandom(16)).decode()
            out = bytearray()
            fields = []
            if isinstance(data, Mapping):
                fields = [(k, "" if v is None else str(v)) for k, v in data.items()]
            elif data:
                fields = list(data)
            for k, v in fields:
                out += f"--{boundary}\r\n".encode()
                out += f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode()
                out += str(v).encode() + b"\r\n"
            for field, value in files.items():
                filename, fileobj, ctype = None, value, "application/octet-stream"
                if isinstance(value, tuple):
                    if len(value) == 2:
                        filename, fileobj = value
                    elif len(value) == 3:
                        filename, fileobj, ctype = value
                    else:
                        filename, fileobj, ctype = value[0], value[1], value[2]
                if hasattr(fileobj, "read"):
                    content = fileobj.read()
                else:
                    content = str(fileobj).encode()
                if filename is None:
                    filename = getattr(fileobj, "name", field)
                out += f"--{boundary}\r\n".encode()
                out += (f'Content-Disposition: form-data; name="{field}"; '
                        f'filename="{os.path.basename(str(filename))}"\r\n').encode()
                out += f"Content-Type: {ctype}\r\n\r\n".encode()
                out += content + b"\r\n"
            out += f"--{boundary}--\r\n".encode()
            return bytes(out), f"multipart/form-data; boundary={boundary}"

        if data is None:
            return None, None
        if isinstance(data, (bytes, bytearray)):
            return bytes(data), None
        if isinstance(data, str):
            return data.encode("utf-8"), None
        if isinstance(data, Mapping) or (isinstance(data, (list, tuple))
                                         and _is_form_pairs(data)):
            items = data.items() if hasattr(data, "items") else data
            pairs = []
            for k, v in items:
                if isinstance(v, (list, tuple)):
                    for item in v:
                        pairs.append((k, "" if item is None else str(item)))
                else:
                    pairs.append((k, "" if v is None else str(v)))
            return urlencode(pairs, doseq=True).encode(), "application/x-www-form-urlencoded"
        # 文件对象 / 生成器: 直接当流交给上层, 不整段读进内存
        if hasattr(data, "read") or hasattr(data, "__iter__"):
            return data, None
        return str(data).encode(), None

    @staticmethod
    def _basic_auth_header(user: str, password) -> str:
        import base64
        if isinstance(password, str):
            password = password.encode()
        token = base64.b64encode(f"{user}:{password.decode() if isinstance(password, bytes) else password}"
                                 .encode()).decode()
        return f"Basic {token}"

    def _apply_auth(self, headers: dict, auth, prepared: PreparedRequest) -> None:
        if auth is None:
            return
        if isinstance(auth, (tuple, list)) and len(auth) == 2:
            headers["authorization"] = self._basic_auth_header(auth[0], auth[1])
        elif isinstance(auth, str):
            headers["authorization"] = self._basic_auth_header(auth, "")
        elif callable(auth):
            prepared.headers = CaseInsensitiveDict(headers)
            result = auth(prepared)
            if isinstance(result, PreparedRequest):
                for k, v in result.headers.items():
                    headers[k.lower()] = v
            elif isinstance(result, Mapping):
                for k, v in result.items():
                    headers[str(k).lower()] = v
        else:
            raise RequestException(f"不支持的 auth 类型: {type(auth)!r}")

    # ================================================================ 请求主流程

    def request(
        self,
        method: str,
        url: str,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects: bool = True,
        proxies=None,
        hooks=None,
        stream: bool = False,
        verify=None,
        cert=None,
        json=None,
        *,
        dest: str | None = None,
        mode: str | None = None,
        origin: str | None = None,
        referer: str | None = None,
        priority: str | None = None,
        max_redirects: int | None = None,
    ) -> Response:
        """与 requests.Session.request 同签名; 额外多了 dest/mode/origin/referer/priority 用于控制指纹头。"""
        # 跨线程使用时也保证读到的是本 Session 的版本 profile(Session 不是线程安全的)
        spec.activate(self.profile)
        if not url:
            raise URLRequired("没有提供 URL")
        method = method.upper()

        prepared = self.prepare_request(
            method, url, params=params, data=data, headers=headers, cookies=cookies,
            files=files, auth=auth, json=json, hooks=hooks, dest=dest, mode=mode,
            origin=origin, referer=referer, priority=priority,
            verify=verify, proxies=proxies, cert=cert,
        )

        history: list[Response] = []
        current = prepared
        redirect_limit = self.max_redirects if max_redirects is None else max_redirects
        limit = redirect_limit if allow_redirects else 0
        for _ in range(limit + 1):
            resp = self.send(current, timeout=timeout, stream=stream,
                             allow_redirects=False, verify=verify, proxies=proxies)
            resp.history = list(history)
            if not allow_redirects or resp.status_code not in REDIRECT_CODES:
                self._run_hooks(hooks, resp)
                return resp
            location = resp.headers.get("location")
            if not location:
                self._run_hooks(hooks, resp)
                return resp

            history.append(resp)
            next_url = urljoin(current.url, location)
            next_method, next_body = current.method, current.body
            if resp.status_code == 303 or (resp.status_code in (301, 302)
                                           and current.method not in ("GET", "HEAD")):
                next_method, next_body = "GET", None
            drop = {"content-type", "content-length"} if next_body is None else set()
            if urlsplit(next_url).netloc != urlsplit(current.url).netloc:
                drop |= {"authorization", "cookie"}
            new_headers = {k: v for k, v in current.headers.items()
                           if k.lower() not in drop}
            current = self.prepare_request(
                next_method, next_url, headers=new_headers, data=next_body,
                dest=dest, mode=mode, origin=origin, referer=referer, priority=priority,
                verify=verify, proxies=proxies, cert=cert,
            )
        raise TooManyRedirects(f"重定向超过 {redirect_limit} 次", response=resp)

    def prepare_request(
        self,
        method: str,
        url: str,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        json=None,
        hooks=None,
        *,
        dest: str | None = None,
        mode: str | None = None,
        origin: str | None = None,
        referer: str | None = None,
        priority: str | None = None,
        verify=None,
        proxies=None,
        cert=None,
    ) -> PreparedRequest:
        parts = urlsplit(url)
        if not parts.scheme:
            raise MissingSchema(f"URL 缺少 scheme: {url!r} (试试 https://...)")
        if parts.scheme not in ("http", "https"):
            raise InvalidSchema(f"不支持的 scheme: {parts.scheme!r}")
        if not parts.hostname:
            raise InvalidURL(f"URL 里没有主机名: {url!r}")

        # ---- 查询串: 原有 query 必须保留, params 追加在后面(和 requests 一致);
        #      params 可以是 dict / (k,v) 列表 / 现成的查询串 ----
        query_parts: list[str] = []
        if parts.query:
            query_parts.append(parts.query)
        if params is None:
            if self.params:
                query_parts.append(self._encode_params(self.params))
        elif isinstance(params, (str, bytes)):
            if self.params:
                query_parts.append(self._encode_params(self.params))
            raw = params.decode() if isinstance(params, bytes) else params
            if raw:
                query_parts.append(raw.lstrip("?&"))
        elif isinstance(params, Mapping):
            merged = dict(self.params)
            merged.update(params)
            query_parts.append(self._encode_params(merged))
        else:
            if self.params:
                query_parts.append(self._encode_params(self.params))
            query_parts.append(self._encode_params(list(params)))
        query = "&".join(q for q in query_parts if q)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, parts.fragment))
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        authority = parts.hostname if parts.port in (None, 443, 80) else f"{parts.hostname}:{parts.port}"

        # ---- body ----
        content_type = None
        if json is not None:
            body = _json.dumps(json, separators=(",", ":"), ensure_ascii=False).encode()
            content_type = "application/json"
        else:
            body, content_type = self._encode_data(data, files)
        body_stream = None
        if body is not None and not isinstance(body, (bytes, bytearray)):
            body_stream, body = body, None       # 长度未知 -> 走流式
        if files is not None and body_stream is None and body is not None:
            pass
        if (body is not None or body_stream is not None) and method in ("GET", "HEAD") \
                and files is None:
            method = "POST"

        # ---- 指纹 profile ----
        use_mode = mode or self.mode
        use_dest = dest or self.dest or ("document" if use_mode == "navigate" else "empty")
        if use_mode == "none":
            use_mode = "no-cors"

        # ---- 头: 会话头 + 请求头按**大小写不敏感**合并(后者覆盖), 避免
        #      "X-Token" 和 "x-token" 同时存在导致覆盖失效 ----
        merged: dict[str, tuple[str, str]] = {}

        def put(key, value) -> None:
            merged[str(key).lower()] = (str(key), str(value))

        for k, v in self.headers.items():
            put(k, v)
        if content_type:
            merged.setdefault("content-type", ("content-type", content_type))
        if priority:
            put("priority", priority)
        for k, v in (headers or {}).items():
            put(k, v)

        # origin: 用户显式给的优先; 否则按 Chrome 规则自动补
        final_origin = origin or self.origin
        if final_origin is None:
            if use_dest == "preflight" or (use_mode == "cors" and method not in ("GET", "HEAD")):
                final_origin = f"{parts.scheme}://{authority}"
        if referer or self.referer:
            merged.setdefault("referer", ("referer", referer or self.referer))

        # cookie
        jar_cookie = self.cookies.get_cookie_header(parts.hostname or "", path)
        if jar_cookie:
            merged.setdefault("cookie", ("cookie", jar_cookie))
        if cookies:
            extra = RequestsCookieJar(cookies).get_dict()
            if extra:
                existing = merged.get("cookie", ("cookie", ""))[1]
                joined = "; ".join(f"{k}={v}" for k, v in extra.items())
                merged["cookie"] = ("cookie", f"{existing}; {joined}" if existing else joined)

        user_headers: list[tuple[str, str]] = list(merged.values())

        wanted = self._wanted_hints(parts, use_mode)
        h2_headers = self._build_headers(method, parts, use_dest, use_mode,
                                        user_headers, body, final_origin,
                                        has_body=(body is not None or body_stream is not None),
                                        hints=bool(wanted))

        prepared = PreparedRequest()
        prepared.method = method
        prepared.url = url
        prepared.body = body
        prepared._body_stream = body_stream
        prepared.headers = CaseInsensitiveDict(h2_headers)
        prepared.hooks = hooks or {}
        prepared._h2_headers = h2_headers           # 保序(HTTP/2 需要)
        prepared._host = parts.hostname or ""
        prepared._port = parts.port or (443 if parts.scheme == "https" else 80)
        prepared._scheme = parts.scheme
        prepared._path = path
        prepared._authority = authority
        prepared._verify = self.verify if verify is None else verify
        prepared._proxies = proxies
        cert_to_use = cert if cert is not None else self.cert
        if cert_to_use is not None and prepared._scheme == "https":
            from .clientcert import ClientCertError, load_client_certificate

            try:
                prepared._client_cert = load_client_certificate(cert_to_use)
            except ClientCertError as e:
                raise RequestException(str(e)) from e
        else:
            prepared._client_cert = None

        auth_to_use = auth if auth is not None else self.auth
        if auth_to_use is not None:
            hdrs = {k: v for k, v in h2_headers}
            self._apply_auth(hdrs, auth_to_use, prepared)
            # authorization 不在 Chrome 默认顺序里, 放末尾
            h2_headers = h2_headers + [(k, v) for k, v in hdrs.items()
                                       if k not in {n for n, _ in h2_headers}]
            prepared._h2_headers = h2_headers
            prepared.headers = CaseInsensitiveDict(h2_headers)
        return prepared

    # ---------------------------------------------------------------- 发送

    def send(self, prepared: PreparedRequest, timeout=None, stream: bool = False,
             allow_redirects: bool = False, verify=None, proxies=None) -> Response:
        connect_timeout, read_timeout = self._split_timeout(
            timeout if timeout is not None else self.timeout)
        use_verify = prepared._verify if verify is None else verify
        use_proxies = proxies if proxies is not None else prepared._proxies
        proxy = self._resolve_proxy(prepared._scheme, prepared._host, use_proxies)

        t0 = time.time()
        last_err: Exception | None = None
        client_cert = getattr(prepared, "_client_cert", None)
        conn_key = _pool_key(prepared._scheme, prepared._host, prepared._port, proxy, client_cert)
        for attempt in range(2):
            try:
                conn = self._get_connection(prepared._scheme, prepared._host, prepared._port,
                                            connect_timeout, read_timeout, proxy, use_verify,
                                            client_cert)
                resp = self._dispatch(conn, prepared, stream)
                if stream and resp._raw_iter is not None:
                    # 流式响应还没读完: 这条连接不能再借给别人, 但**不能马上关**,
                    # 否则调用方 iter_content() 时套接字已经没了。读完/close 时再释放。
                    conn.alive = False
                    self._pool.pop(conn_key, None)
                    resp._close_conn = conn
                    resp._raw_iter = _close_when_done(resp._raw_iter, conn)
                    resp._reader = _StreamReader(
                        resp._raw_iter, resp.headers.get("content-encoding") or "")
                break
            except (OSError, tls13.TLSException, ssl.SSLError) as e:
                last_err = e
                self._drop_connection(conn_key)
                if attempt == 1:
                    # 本库自己的异常(SSLError/ProxyError/ConnectTimeout... 都是 OSError 子类)
                    # 必须原样透出, 不能被下面的兜底包成裸 ConnectionError
                    if isinstance(e, RequestException):
                        raise
                    # TLS 层抛的异常(握手后的 alert / 解密失败 / 被关闭)统一算 SSLError
                    if isinstance(e, tls13.TLSException):
                        raise SSLError(str(e)) from e
                    if isinstance(e, socket.timeout):
                        raise ReadTimeout(f"读取 {prepared.url} 超时") from e
                    raise _ConnectionError(str(e)) from e
        else:  # pragma: no cover
            raise last_err or _ConnectionError("请求失败")

        resp.url = prepared.url
        resp.duration = time.time() - t0
        resp.elapsed = timedelta(seconds=resp.duration)
        resp.request = prepared
        resp.request_headers = prepared._h2_headers
        resp.tls = dict(self.last_handshake)
        self.cookies.extract_cookies_from_headers(prepared._host, resp.raw_headers)
        self._remember_accept_ch(prepared.url, resp.raw_headers)
        resp.cookies = RequestsCookieJar()
        resp.cookies.extract_cookies_from_headers(prepared._host, resp.raw_headers)
        return resp

    def _dispatch(self, conn: _Connection, prepared: PreparedRequest,
                  stream: bool = False) -> Response:
        scheme, authority, host, path = (prepared._scheme, prepared._authority,
                                        prepared._host, prepared._path)
        body = prepared.body
        body_stream = getattr(prepared, "_body_stream", None)
        headers = prepared._h2_headers
        proxy = conn.key[3] if len(conn.key) > 3 else None

        if isinstance(conn.engine, http2.H2Connection):
            h2r = conn.engine.request(prepared.method, scheme, authority, path, headers,
                                      body_stream if body_stream is not None else body,
                                      stream=stream)
            resp = Response()
            resp.status_code = h2r.status
            resp.raw_headers = list(h2r.headers)
            resp.headers = CaseInsensitiveDict(h2r.headers)
            resp._raw = h2r.body
            resp._raw_iter = h2r.body_iter
            resp.http_version = "HTTP/2"
        else:
            target = path if not proxy else f"{scheme}://{authority}{path}"
            h1_headers = [(spec.h1_header_name(k), v) for k, v in headers]
            h1r = conn.engine.request(prepared.method, target, h1_headers, body,
                                      host=authority, body_stream=body_stream, stream=stream)
            resp = Response()
            resp.status_code = h1r.status
            resp.reason = h1r.reason
            resp.raw_headers = list(h1r.headers)
            resp.headers = CaseInsensitiveDict(h1r.headers)
            resp._raw = h1r.body
            resp._raw_iter = h1r.body_iter
            resp.http_version = h1r.version
        if not resp.reason:
            resp.reason = http1.REASONS.get(resp.status_code, "")
        resp.encoding = _encoding_from_headers(resp.headers)
        if resp._raw_iter is None:
            self._decode(resp)
        else:
            # 流式: content 留空, 等调用方 iter_content()/content 时才解压
            resp._content = None
        return resp

    @staticmethod
    def _decode(resp: Response) -> None:
        resp.content = _decompress(resp._raw,
                                   (resp.headers.get("content-encoding") or ""))

    @staticmethod
    def _run_hooks(hooks, resp: Response) -> None:
        if not hooks:
            return
        for fn in hooks.get("response", []) or []:
            fn(resp)

    # ================================================================ 便捷方法

    def get(self, url, params=None, **kwargs) -> Response:
        return self.request("GET", url, params=params, **kwargs)

    def options(self, url, **kwargs) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url, **kwargs) -> Response:
        return self.request("HEAD", url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs) -> Response:
        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url, data=None, json=None, **kwargs) -> Response:
        return self.request("PUT", url, data=data, json=json, **kwargs)

    def patch(self, url, data=None, json=None, **kwargs) -> Response:
        return self.request("PATCH", url, data=data, json=json, **kwargs)

    def delete(self, url, **kwargs) -> Response:
        return self.request("DELETE", url, **kwargs)

    # ---- requests 兼容的小接口 ----

    def mount(self, prefix: str, adapter) -> None:
        """requests 兼容: 本库只有一个内置传输层, 这里仅记录, 不参与调度。"""
        self.adapters[prefix] = adapter

    def get_adapter(self, url: str):
        return self.adapters.get(url) or self.adapters.get(url[:5]) or None

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        return {
            "proxies": proxies if proxies is not None else self.proxies,
            "stream": stream,
            "verify": verify if verify is not None else self.verify,
            "cert": cert if cert is not None else self.cert,
        }

    def set_cookie(self, name: str, value: str, *, domain: str = "", path: str = "/") -> None:
        self.cookies.set(name, value, domain=domain, path=path)

    def get_cookie(self, name: str, *, domain: str = "", default=None):
        if domain:
            return self.cookies.get(name, default, domain=domain)
        return self.cookies.get(name, default)

    def close(self) -> None:
        for conn in self._pool.values():
            conn.alive = False
            try:
                conn.sock.close()
            except OSError:
                pass
        self._pool.clear()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<chrome_fp.Session mode={self.mode} dest={self.dest}>"


def _close_when_done(chunks, conn):
    """流式响应**读完之后**释放连接。

    注意不能写在 finally 里无条件关: 调用方 `next(iter_content())` 拿到一块就把生成器
    丢掉是很正常的写法, 那时 GeneratorExit 会一路传到 finally —— 直接把套接字关了,
    后面的块就再也读不到了(踩过)。
    """
    completed = False
    try:
        for chunk in chunks:
            yield chunk
        completed = True
    finally:
        if completed:
            try:
                conn.sock.close()
            except OSError:
                pass
            conn.alive = False


PER_ADDRESS_TIMEOUT = 5.0     # 单个地址最多等这么久(黑洞地址不能吃掉整个预算)


def _connect_any(host: str, port: int, timeout) -> socket.socket:
    """连到 host:port —— 自己遍历 getaddrinfo 的结果, 而不是用 socket.create_connection。

    为什么: `socket.create_connection` 按 DNS 返回顺序**逐个**尝试, 每个都用完整 timeout。
    DNS 常把 IPv6 排在前面, 而本机/不少网络里 IPv6 到境外站点是黑洞 —— 两个 IPv6 地址
    各烧掉一整个 timeout, 请求直接超时。实测 example.com: 要 12s 才连上, timeout 给小
    一点就彻底失败; 同一时刻 requests 只要 0.6s(它走的是 IPv4)。
    这里改成: IPv4 优先 + 每地址限时 PER_ADDRESS_TIMEOUT + 整体不超过 timeout。
    """
    total = timeout if timeout else DEFAULT_TIMEOUT
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise _ConnectionError(f"域名解析失败 {host}: {e}") from e
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)

    deadline = time.monotonic() + total
    last_err: Exception | None = None
    seen: set = set()
    for fam, socktype, proto, _canon, sa in infos:
        if sa[:2] in seen:
            continue
        seen.add(sa[:2])
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock = None
        try:
            sock = socket.socket(fam, socktype, proto)
            sock.settimeout(min(left, PER_ADDRESS_TIMEOUT))
            sock.connect(sa)
            sock.settimeout(total)
            return sock
        except OSError as e:
            last_err = e
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    if isinstance(last_err, socket.timeout):
        raise last_err
    raise _ConnectionError(f"无法连接 {host}:{port}: {last_err}")


def _is_form_pairs(data) -> bool:
    """判断是不是 [(k, v), ...] 这种表单数据(而不是一串 bytes 分块)"""
    if not data:
        return True
    return all(isinstance(i, (tuple, list)) and len(i) == 2 for i in data)


def _decompress(raw: bytes, encoding: str) -> bytes:
    """一次性解压(非流式响应)"""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip":
            return gzip.decompress(raw)
        if enc == "deflate":
            return zlib.decompress(raw, -zlib.MAX_WBITS)
        if enc == "br" and brotli:
            return brotli.decompress(raw)
        if enc == "zstd" and zstandard:
            return zstandard.ZstdDecompressor().decompress(raw)
    except Exception as e:  # noqa: BLE001
        raise ContentDecodingError(f"{enc} 解压失败: {e}") from e
    return raw


def _make_decompressor(encoding: str):
    enc = (encoding or "").lower().strip()
    if enc == "gzip":
        return "gzip", zlib.decompressobj(16 + zlib.MAX_WBITS)
    if enc == "deflate":
        return "deflate", zlib.decompressobj(-zlib.MAX_WBITS)
    if enc == "br" and brotli:
        return "br", brotli.Decompressor()
    if enc == "zstd" and zstandard:
        return "zstd", zstandard.ZstdDecompressor().decompressobj()
    return None, None


class _StreamReader:
    """流式响应体的读取器: 底层原始流 + 增量解压。

    特意用类实现而不是生成器 —— 调用方 `next(iter_content())` 拿到一块就把迭代器丢掉
    是常见写法, 生成器会收到 GeneratorExit 并把**底层的体迭代器一起关掉**, 后面的块就
    再也读不出来(踩过)。类实现的 __next__ 只是往下拉一块, 放弃外层不影响它。
    """

    def __init__(self, raw_iter, encoding: str):
        self._raw = raw_iter
        self._kind, self._obj = _make_decompressor(encoding)
        self._pending = b""
        self._done = False

    def __iter__(self):
        return self

    def _feed(self, chunk: bytes) -> bytes:
        if self._obj is None:
            return chunk
        try:
            return self._obj.process(chunk) if self._kind in ("br", "zstd") \
                else self._obj.decompress(chunk)
        except Exception as e:  # noqa: BLE001
            raise ContentDecodingError(f"{self._kind} 流式解压失败: {e}") from e

    def _flush(self) -> bytes:
        if self._obj is None or not hasattr(self._obj, "flush"):
            return b""
        try:
            return self._obj.flush()
        except Exception:  # noqa: BLE001
            return b""

    def __next__(self) -> bytes:
        while True:
            if self._pending:
                out, self._pending = self._pending, b""
                return out
            if self._done:
                raise StopIteration
            try:
                chunk = next(self._raw)
            except StopIteration:
                self._done = True
                self._pending = self._flush()
                if self._pending:
                    continue
                raise
            out = self._feed(chunk)
            if out:
                return out

    def read_all(self) -> bytes:
        return b"".join(self)

    def close(self) -> None:
        self._done = True
        try:
            self._raw.close()
        except AttributeError:
            pass


def _pool_key(scheme: str, host: str, port: int, proxy, client_cert=None) -> tuple:
    """连接池键 —— 客户端证书不同不能复用同一条连接(证书是握手期协商的)"""
    cert_key = None
    if client_cert is not None:
        from hashlib import sha256 as _sha256

        cert_key = _sha256(client_cert.chain_der[0]).hexdigest()
    return (scheme, host, port, proxy, cert_key)


def _encoding_from_headers(headers) -> str | None:
    """对齐 requests.utils.get_encoding_from_headers"""
    content_type = headers.get("content-type")
    if content_type is None:
        return None
    if "text" in content_type:
        ctype, _, params = content_type.partition(";")
        for part in params.split(";"):
            k, _, v = part.partition("=")
            if k.strip().lower() == "charset":
                return v.strip().strip("'\"") or None
        return "ISO-8859-1"
    if "application/json" in content_type:
        return "utf-8"
    return None


class _PlainSock:
    """把裸 TCP socket 包装成 TLS13Connection 的接口(供 http:// 明文使用)"""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send_app(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_app(self, n: int = 65536) -> bytes:
        try:
            return self.sock.recv(n)
        except socket.timeout:
            return b""
