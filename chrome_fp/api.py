"""模块级 API —— 和 requests 一样: `chrome_fp.get(...)` 直接可用。

    import chrome_fp as requests
    r = requests.get("https://example.com/", params={"q": 1}, timeout=5)
    r = requests.post("https://example.com/api", json={"a": 1})

和 requests 一样, 每次调用会新建一个 Session 并关闭它(所以不会复用连接)。
需要连接复用/Cookie 保持时自己建 `Session()` 用。

多出来的几个关键字(不属于 requests, 用于控制指纹): proxy / mode / dest / user_agent /
origin / referer / sec_fetch_site / send_priority_tree / allow_tls12 / ca_file。
"""

from __future__ import annotations

from .session import Session

# 这些只属于 Session(构造期), 不会透传给 Session.request
_SESSION_KEYS = frozenset({
    "proxy", "mode", "dest", "user_agent", "origin", "referer", "sec_fetch_site",
    "send_priority_tree", "allow_tls12", "ca_file", "check_certificate_transparency",
    "http2_enabled", "trust_env",
})


def request(method: str, url: str, **kwargs):
    session_kwargs = {k: kwargs.pop(k) for k in list(kwargs) if k in _SESSION_KEYS}
    with Session(**session_kwargs) as session:
        return session.request(method=method, url=url, **kwargs)


def get(url: str, params=None, **kwargs):
    return request("get", url, params=params, **kwargs)


def options(url: str, **kwargs):
    return request("options", url, **kwargs)


def head(url: str, **kwargs):
    return request("head", url, **kwargs)


def post(url: str, data=None, json=None, **kwargs):
    return request("post", url, data=data, json=json, **kwargs)


def put(url: str, data=None, json=None, **kwargs):
    return request("put", url, data=data, json=json, **kwargs)


def patch(url: str, data=None, json=None, **kwargs):
    return request("patch", url, data=data, json=json, **kwargs)


def delete(url: str, **kwargs):
    return request("delete", url, **kwargs)
