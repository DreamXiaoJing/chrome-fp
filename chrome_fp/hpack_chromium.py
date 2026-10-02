"""复刻 Chromium(net/spdy/hpack/hpack_encoder.cc)的 HPACK 编码选择。

为什么需要: 头**解码后**一样, 不代表**编码后的字节**一样。JA3/JA4/Akamai 都不看 HPACK,
但服务器/中间盒只要 dump HEADERS 帧的原始载荷, 就能用编码方式把客户端区分开
(哪些头用索引、哪些字面量、是否 Huffman、动态表怎么变)。

下面这套规则不是照着源码猜的, 是从本机真 Chrome 153 抓包的原始 HEADERS 字节里
统计出来的(tools/_tally.py 对 100+ 个真实请求按头名统计表示类型):

  header            索引   +增量索引  不索引
  :authority          0      14        0
  :method            45       0        3
  :path               1       0       47
  :scheme            48       0        0
  accept/accept-*/cookie/referer/user-agent 等全部走 +增量索引

归纳成三条:
  * 静态表精确命中 -> 索引表示           (实证: :method GET/POST、:scheme https、:path /)
  * **:method / :path 命中不到精确项时 -> 字面量+不索引(0x04)**
    (OPTIONS 的 :method、各种 :path; 注意 :authority 不在此列, 它是 0x41 增量索引)
  * 其余头 -> 字面量+增量索引(0x40)      (实证: cookie / referer 都是 0x44 —— Chromium
                                          **并不**把 cookie 当"从不索引", 全量统计里 0 次)
  * Huffman **择优**: 编码后严格更短才用, 平局用原始字节
    (实证: /?n=0 两者都是 5 字节 -> raw; /style.css 用 Huffman)

动态表大小用服务器广告的 SETTINGS_HEADER_TABLE_SIZE(上限是我们自己广告的 65536),
变化时在下一个头块开头补一个"动态表大小更新"。
"""

from __future__ import annotations

from ._huffman_table import HUFFMAN_TABLE

# RFC 7541 附录 A 静态表(索引 = 位置 + 1)
STATIC_TABLE: list[tuple[str, str]] = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"),
    (":status", "200"), (":status", "204"), (":status", "206"), (":status", "304"),
    (":status", "400"), (":status", "404"), (":status", "500"),
    ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""), ("accept-ranges", ""), ("accept", ""),
    ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
    ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""),
    ("cookie", ""), ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
    ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""),
    ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
    ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""),
    ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
    ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
]
STATIC_EXACT = {(n, v): i + 1 for i, (n, v) in enumerate(STATIC_TABLE)}
STATIC_NAME = {}
for _i, (_n, _v) in enumerate(STATIC_TABLE):
    STATIC_NAME.setdefault(_n, _i + 1)

# 实证: 只有 :method / :path 在命中不到静态精确项时用"不索引"(0x04)
WITHOUT_INDEXING = frozenset({":method", ":path"})

STATIC_TABLE_SIZE = 61
ENTRY_OVERHEAD = 32


def huffman_encode(data: bytes) -> bytes:
    """HPACK Huffman 编码(RFC 7541 附录 B), 末尾用 1 补齐"""
    out = bytearray()
    cur = 0
    nbits = 0
    for b in data:
        code, bits = HUFFMAN_TABLE[b]
        cur = (cur << bits) | code
        nbits += bits
        while nbits >= 8:
            nbits -= 8
            out.append((cur >> nbits) & 0xFF)
    if nbits:
        pad = 8 - nbits
        out.append(((cur << pad) | ((1 << pad) - 1)) & 0xFF)
    return bytes(out)


def _encode_int(value: int, prefix_bits: int, high: int = 0) -> bytes:
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([high | value])
    out = bytearray([high | max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _encode_string(text: str) -> bytes:
    """Huffman 择优: 编码后严格更短才用(平局用原始字节, 与 Chromium 一致)"""
    raw = text.encode("utf-8")
    huff = huffman_encode(raw)
    if len(huff) < len(raw):
        return _encode_int(len(huff), 7, 0x80) + huff
    return _encode_int(len(raw), 7, 0x00) + raw


class ChromiumHpackEncoder:
    """与 Chromium 编码选择一致的 HPACK 编码器(带动态表)"""

    def __init__(self, max_table_size: int = 4096):
        self.max_table_size = max_table_size
        self._pending_size_update: int | None = None
        # [(name, value, size)], 索引 0 = 最新插入(动态索引 62)
        self._dynamic: list[tuple[str, str, int]] = []
        self._dynamic_size = 0

    # ------------------------------------------------------------ 配置

    @property
    def header_table_size(self) -> int:
        return self.max_table_size

    @header_table_size.setter
    def header_table_size(self, value: int) -> None:
        self.set_max_table_size(value)

    def set_max_table_size(self, size: int) -> None:
        """对端改了 SETTINGS_HEADER_TABLE_SIZE: 下个头块开头要发一次大小更新"""
        if size == self.max_table_size and self._pending_size_update is None:
            return
        self.max_table_size = size
        self._pending_size_update = size
        self._evict()

    # ------------------------------------------------------------ 动态表

    def _evict(self) -> None:
        while self._dynamic and self._dynamic_size > self.max_table_size:
            _, _, size = self._dynamic.pop()
            self._dynamic_size -= size

    def _add(self, name: str, value: str) -> None:
        size = len(name.encode()) + len(value.encode()) + ENTRY_OVERHEAD
        if size > self.max_table_size:
            # 单条就超上限 -> 清空动态表且不插入(RFC 7541 §4.4)
            self._dynamic.clear()
            self._dynamic_size = 0
            return
        self._dynamic.insert(0, (name, value, size))
        self._dynamic_size += size
        self._evict()

    def _exact_index(self, name: str, value: str) -> int | None:
        """只有**名和值都命中**才返回索引; 找不到就返回 None(不能退化成按名索引)"""
        if (name, value) in STATIC_EXACT:
            return STATIC_EXACT[(name, value)]
        for i, (n, v, _) in enumerate(self._dynamic):
            if n == name and v == value:
                return STATIC_TABLE_SIZE + 1 + i
        return None

    def _name_index(self, name: str) -> int | None:
        """按名匹配(静态优先, 然后动态), 用于字面量表示的名字索引"""
        if name in STATIC_NAME:
            return STATIC_NAME[name]
        for i, (n, _v, _s) in enumerate(self._dynamic):
            if n == name:
                return STATIC_TABLE_SIZE + 1 + i
        return None

    # ------------------------------------------------------------ 编码

    def encode(self, headers) -> bytes:
        out = bytearray()
        if self._pending_size_update is not None:
            out += _encode_int(self._pending_size_update, 5, 0x20)
            self._pending_size_update = None
        for name, value in headers:
            if isinstance(name, bytes):
                name = name.decode("utf-8")
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            out += self._encode_one(name, value)
        return bytes(out)

    def _encode_one(self, name: str, value: str) -> bytes:
        # 1) 名和值都精确命中 -> 索引表示
        exact = self._exact_index(name, value)
        if exact is not None:
            return _encode_int(exact, 7, 0x80)

        name_idx = self._name_index(name)
        if name in WITHOUT_INDEXING:
            # 2) :path 这类 -> 字面量+不索引(0x04), 不进动态表
            if name_idx is not None:
                return _encode_int(name_idx, 4, 0x00) + _encode_string(value)
            return _encode_int(0, 4, 0x00) + _encode_string(name) + _encode_string(value)

        # 3) 其余 -> 字面量+增量索引(0x40)并插入动态表
        if name_idx is not None:
            head = _encode_int(name_idx, 6, 0x40)
        else:
            head = _encode_int(0, 6, 0x40) + _encode_string(name)
        self._add(name, value)
        return head + _encode_string(value)
