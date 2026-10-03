"""chrome_fp —— 与真 Chrome 同指纹的纯 Python HTTP 库, 用法和 requests 一样。

支持多版本 profile: 默认跟随 **Chrome 154**(本机 Stable 154.0.8037.98 实抓校对),
``Session(chrome_version="153")`` 可切到上一版(153.0.8010.48)。

    import chrome_fp as requests
    r = requests.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.json()["tls"]["ja4"], r.elapsed)

    from chrome_fp import Session
    s = Session(proxy="http://127.0.0.1:7892", mode="navigate")
    r = s.get("https://example.com/", params={"a": 1}, headers={"referer": "..."})
    s153 = Session(chrome_version="153")        # 用 Chrome 153 的指纹
    with Session() as s2:
        r = s2.post("https://httpbin.org/post", json={"a": 1})

底层构造单条 ClientHello(不含网络):

    from chrome_fp import build_client_hello, ja4_from_hello
    ch = build_client_hello("example.com")
    print(ja4_from_hello(ch.record), len(ch.record))
"""

from . import exceptions, spec, structures
from .api import delete, get, head, options, patch, post, put, request
from .exceptions import (
    ConnectionError,
    HTTPError,
    RequestException,
    Timeout,
    TooManyRedirects,
)
from .fingerprint import ja3_from_hello, ja4_from_hello, parse_client_hello
from .hello import ClientHello, build_client_hello
from .session import PreparedRequest, Response, Session
from .spec import (
    CHROME_MAJOR,
    CHROME_PLATFORM,
    CHROME_VERSION,
    DEFAULT_VERSION,
    PROFILES,
    Profile,
    get_profile,
)
from .structures import CaseInsensitiveDict, RequestsCookieJar

__all__ = [
    # 高层 API(与 requests 同名同签名)
    "Session", "Response", "PreparedRequest",
    "request", "get", "post", "put", "patch", "delete", "head", "options",
    "CaseInsensitiveDict", "RequestsCookieJar",
    "RequestException", "HTTPError", "ConnectionError", "Timeout", "TooManyRedirects",
    "exceptions", "structures", "spec",
    # 低层 ClientHello 工具
    "ClientHello", "build_client_hello",
    "ja3_from_hello", "ja4_from_hello", "parse_client_hello",
    "CHROME_MAJOR", "CHROME_PLATFORM", "CHROME_VERSION",
    # 版本 profile
    "PROFILES", "Profile", "get_profile", "DEFAULT_VERSION",
]

__version__ = "0.6.0"
