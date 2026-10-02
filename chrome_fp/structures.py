"""requests 兼容的数据结构: CaseInsensitiveDict / RequestsCookieJar / Cookie。"""

from __future__ import annotations

import time
from collections.abc import MutableMapping


class CaseInsensitiveDict(MutableMapping):
    """大小写不敏感的字典 —— 行为对齐 requests.structures.CaseInsensitiveDict。

        h = CaseInsensitiveDict({"Content-Type": "text/html"})
        h["content-type"]      # 'text/html'
        h["CONTENT-TYPE"]      # 'text/html'
    """

    def __init__(self, data=None, **kwargs):
        self._store: dict[str, tuple[str, str]] = {}
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value) -> None:
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key) -> None:
        del self._store[key.lower()]

    def __iter__(self):
        return (cased for cased, _ in self._store.values())

    def __len__(self) -> int:
        return len(self._store)

    def lower_items(self):
        return ((lower, cased[1]) for lower, cased in self._store.items())

    def __eq__(self, other) -> bool:
        if isinstance(other, MutableMapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        return dict(self.lower_items()) == dict(other.lower_items())

    def copy(self) -> "CaseInsensitiveDict":
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self) -> str:
        return str(dict(self.items()))


class Cookie:
    """最简 cookie 记录(域/路径/过期/host-only)"""

    def __init__(self, name: str, value: str, domain: str = "", path: str = "/",
                 expires: int | None = None, secure: bool = False, http_only: bool = False,
                 host_only: bool = False):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.expires = expires
        self.secure = secure
        self.http_only = http_only
        # host-only(Set-Cookie 没带 Domain)只发给完全同名的主机, 不发子域
        self.host_only = host_only
        self._rest: dict[str, str] = {}

    @property
    def expired(self) -> bool:
        return self.expires is not None and self.expires <= time.time()

    def to_header(self) -> str:
        return f"{self.name}={self.value}"

    def __repr__(self) -> str:
        return f"<Cookie {self.name}={self.value} for {self.domain or '*'}{self.path}>"


class RequestsCookieJar(MutableMapping):
    """requests.cookies.RequestsCookieJar 的可用子集。

    支持:
        jar["k"] = "v"; jar.set("k", "v", domain="example.com", path="/")
        jar.get("k"); jar.get_dict(); jar.items(); jar.update({...})
        "k" in jar; len(jar); del jar["k"]; jar.clear(); jar.copy()
    按域/路径匹配: match(host, path) 返回应该发送的 cookie 列表。
    """

    def __init__(self, cookies=None):
        self._cookies: dict[tuple[str, str, str], Cookie] = {}
        if cookies:
            self.update(cookies)

    # ---- 基础映射接口 ----
    def __setitem__(self, name, value) -> None:
        self.set(name, value)

    def __getitem__(self, name) -> str:
        cookie = self._find(name)
        if cookie is None:
            raise KeyError(name)
        return cookie.value

    def __delitem__(self, name) -> None:
        for key, cookie in list(self._cookies.items()):
            if cookie.name == name:
                del self._cookies[key]
                return
        raise KeyError(name)

    def __contains__(self, name) -> bool:
        return self._find(name) is not None

    def __iter__(self):
        return iter(self.get_dict())

    def __len__(self) -> int:
        return len(self.get_dict())

    def _find(self, name: str) -> Cookie | None:
        for cookie in self._cookies.values():
            if cookie.name == name and not cookie.expired:
                return cookie
        return None

    def set(self, name: str, value: str, domain: str = "", path: str = "/",
            expires: int | None = None, secure: bool = False,
            http_only: bool = False, host_only: bool = False) -> Cookie:
        if value is None:
            value = ""
        cookie = Cookie(name, str(value), domain.lstrip(".").lower(), path or "/",
                        expires, secure, http_only, host_only)
        self._cookies[(cookie.domain, cookie.path, cookie.name)] = cookie
        return cookie

    def get(self, name, default=None, domain=None, path=None):
        if domain is None and path is None:
            cookie = self._find(name)
            return cookie.value if cookie else default
        cookie = self._cookies.get(((domain or "").lstrip(".").lower(), path or "/", name))
        if cookie and not cookie.expired:
            return cookie.value
        return default

    def get_dict(self, domain=None, path=None) -> dict[str, str]:
        out: dict[str, str] = {}
        for cookie in self._cookies.values():
            if cookie.expired:
                continue
            if domain is not None and cookie.domain and not _domain_match(domain, cookie.domain):
                continue
            out[cookie.name] = cookie.value
        return out

    dict = get_dict

    def items(self):
        return self.get_dict().items()

    def keys(self):
        return self.get_dict().keys()

    def values(self):
        return self.get_dict().values()

    def update(self, other) -> None:
        if other is None:
            return
        if isinstance(other, RequestsCookieJar):
            for cookie in other._cookies.values():
                self.set(cookie.name, cookie.value, cookie.domain, cookie.path,
                         cookie.expires, cookie.secure, cookie.http_only)
        elif isinstance(other, dict):
            for k, v in other.items():
                self.set(k, v)
        else:
            for k, v in dict(other).items():
                self.set(k, v)

    def clear(self, domain=None, path=None) -> None:
        self._cookies.clear()

    def copy(self) -> "RequestsCookieJar":
        return RequestsCookieJar(self)

    def set_cookie(self, cookie: Cookie) -> None:
        self._cookies[(cookie.domain, cookie.path, cookie.name)] = cookie

    def set_cookie_if_ok(self, cookie: Cookie, request=None) -> None:
        self.set_cookie(cookie)

    def list_domains(self) -> list[str]:
        return sorted({c.domain for c in self._cookies.values() if c.domain})

    def list_paths(self) -> list[str]:
        return sorted({c.path for c in self._cookies.values()})

    def get_cookie_header(self, host: str, path: str = "/") -> str | None:
        """按域/路径匹配出 Cookie 请求头的值"""
        host_l = host.lower().split(":")[0]
        parts = []
        for cookie in self._cookies.values():
            if cookie.expired:
                continue
            if cookie.host_only:
                if host_l != cookie.domain:      # host-only 不发子域
                    continue
            elif cookie.domain and not _domain_match(host, cookie.domain):
                continue
            if not _path_match(path, cookie.path):
                continue
            parts.append(cookie.to_header())
        return "; ".join(parts) if parts else None

    def extract_cookies_from_headers(self, host: str, headers) -> None:
        """从 Set-Cookie 头里吸收 cookie(简化解析)"""
        for k, v in headers:
            if k.lower() != "set-cookie":
                continue
            self._parse_set_cookie(host, v)

    def _parse_set_cookie(self, host: str, value: str) -> None:
        segs = [s.strip() for s in value.split(";")]
        if not segs or "=" not in segs[0]:
            return
        name, _, val = segs[0].partition("=")
        domain, path = host, "/"
        expires = None
        secure = http_only = False
        has_domain = False
        for seg in segs[1:]:
            key, _, v = seg.partition("=")
            key = key.strip().lower()
            v = v.strip()
            if key == "domain":
                domain = v.lstrip(".").lower()
                has_domain = True
            elif key == "path":
                path = v or "/"
            elif key == "max-age":
                try:
                    expires = int(time.time()) + int(v)
                except ValueError:
                    pass
            elif key == "expires" and expires is None:
                from email.utils import parsedate_to_datetime
                try:
                    expires = int(parsedate_to_datetime(v).timestamp())
                except (TypeError, ValueError):
                    pass
            elif key == "secure":
                secure = True
            elif key == "httponly":
                http_only = True
        if expires is not None and expires <= time.time():
            self._cookies.pop((domain.lower(), path, name.strip()), None)
            return
        self.set(name.strip(), val, domain, path, expires, secure, http_only,
                 host_only=not has_domain)

    def __repr__(self) -> str:
        return f"<RequestsCookieJar{list(self.get_dict().items())}>"


def _domain_match(host: str, domain: str) -> bool:
    host = host.lower().split(":")[0]
    domain = domain.lower().lstrip(".")
    return host == domain or host.endswith("." + domain)


def _path_match(request_path: str, cookie_path: str) -> bool:
    if not request_path.startswith("/"):
        request_path = "/" + request_path
    if request_path == cookie_path:
        return True
    if request_path.startswith(cookie_path.rstrip("/") + "/"):
        return True
    return cookie_path == "/"
