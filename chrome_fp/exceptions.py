"""异常层次 —— 名字与语义都对齐 requests.exceptions。

    from chrome_fp.exceptions import RequestException, HTTPError, TooManyRedirects
    try:
        r = s.get(url); r.raise_for_status()
    except HTTPError as e:
        print(e.response.status_code)
"""

from __future__ import annotations

import json as _json


class RequestException(IOError):
    """所有本库异常的基类(和 requests 一样继承 IOError)"""

    def __init__(self, *args, **kwargs):
        self.response = kwargs.pop("response", None)
        self.request = kwargs.pop("request", None)
        super().__init__(*args, **kwargs)


class InvalidJSONError(RequestException):
    """JSON 解码失败"""


class JSONDecodeError(InvalidJSONError, _json.JSONDecodeError):
    """r.json() 解析失败时抛出(同时是 json.JSONDecodeError)"""

    def __init__(self, *args, **kwargs):
        _json.JSONDecodeError.__init__(self, *args)
        InvalidJSONError.__init__(self, *self.args, **kwargs)

    def __reduce__(self):
        return _json.JSONDecodeError.__reduce__(self)


class HTTPError(RequestException):
    """raise_for_status() 抛出的 4xx/5xx"""


class ConnectionError(RequestException):
    """连接层面的失败"""


class ProxyError(ConnectionError):
    """代理握手失败"""


class SSLError(ConnectionError):
    """证书/握手校验失败"""


class Timeout(RequestException):
    """超时基类"""


class ConnectTimeout(ConnectionError, Timeout):
    """建连超时"""


class ReadTimeout(Timeout):
    """读写超时"""


class TooManyRedirects(RequestException):
    """重定向次数超过 max_redirects"""


class MissingSchema(RequestException, ValueError):
    """URL 没有 scheme"""


class InvalidSchema(RequestException, ValueError):
    """不支持的 scheme"""


class InvalidURL(RequestException, ValueError):
    """URL 不合法"""


class URLRequired(RequestException, ValueError):
    """没有给 URL"""


class ContentDecodingError(RequestException):
    """响应体解压失败"""


class ChunkedEncodingError(RequestException):
    """分块传输编码损坏"""


class StreamConsumedError(RequestException, TypeError):
    """流已被消费"""


class UnrewindableBodyError(RequestException):
    """body 无法重放"""


class NotImplementedRequestError(RequestException, NotImplementedError):
    """本库尚未实现的能力(客户端证书 / HTTP3 等)"""
