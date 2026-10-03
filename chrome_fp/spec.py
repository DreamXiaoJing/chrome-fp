"""Chrome 客户端指纹规格 —— **多版本 profile**, 全部来自真机实抓字节核对。

当前支持:
  * ``154`` —— Chrome **154.0.8037.98** (Windows x64, 本机 Stable)
  * ``153`` —— Chrome **153.0.8010.48** (Windows x64, 上一版)

本轮 153 → 154 的证据 (2026-10-03, 本机 A/B 实抓; 工具 ``tools/run_capture.py`` +
``tools/analyze_hello.py``, 原始字节在 ``capture/chrome154/`` 与 ``capture/chrome153cft/``):

  | 项目 | Chrome 153 | Chrome 154 | 结论 |
  |---|---|---|---|
  | JA4_a              | ``t13d1517h2``    | ``t13d1517h2``    | 不变 |
  | JA4_b              | ``8daaf6152771``  | ``8daaf6152771``  | 不变 |
  | cipher 列表 (15)   | 见 CIPHER_SUITES  | 完全相同          | 不变 |
  | supported_groups   | 4 个 (+GREASE)    | 完全相同          | 不变 |
  | signature_algorithms | 11 个 (+GREASE) | 完全相同          | 不变 |
  | 扩展集合 (17)      | 见 ACTIVE_EXTS    | 完全相同          | 不变 |
  | trust_anchors(0xca34) | 28 个 ID       | 同一集合          | 不变 |
  | H2 SETTINGS / WINDOW_UPDATE / 帧序 | 见 H2_SETTINGS | 完全相同 | 不变 |
  | ``sec-ch-ua`` 品牌 | ``"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"`` | ``"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`` | **随版本变**(含品牌顺序与 GREASE 品牌) |
  | UA / full-version  | ``Chrome/153.0.0.0`` / ``153.0.8010.48`` | ``Chrome/154.0.0.0`` / ``154.0.8037.98`` | **随版本变** |

  即: **TLS 与 HTTP/2 的线格式在 153→154 没有变化**, 差异只在版本字符串和 UA 品牌串。

本轮顺带实测到一处**旧实现与真机不符**(153/154 都一样, 已修):
真 Chrome 的 HEADERS 帧带 ``PRIORITY`` 标志(flags ``0x25``), 前置 5 字节
``(E=1, depends_on=0, weight=按 RFC 9218 urgency 查表)`` —— 见 ``h2_priority_prefix()``。

其他实测结论:
  * 扩展的**顺序**是每次连接重新做 Fisher-Yates 置换(同一次启动 20 条样本顺序各不相同),
    所以 profile 里存的是**集合**(EXT_TABLE 是置换基准表, ACTIVE_EXTS 是实际集合)。
  * ``trust_anchors`` 的**顺序**在两次启动间会变(153 实测两次启动两个顺序), 集合恒定;
    这里按抓到的顺序发, 属于该集合的一个合法样本。
  * 扩展 ``0x12e0``(len=2) 只在 Chrome for Testing 153.0.8010.47 上出现, Stable
    153.0.8010.48 与 Stable 154 都没有 —— 是构建渠道差异, 不是版本特征, 不写进 profile。
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, replace

__all__ = [
    "Profile", "PROFILES", "PROFILE_153", "PROFILE_154", "DEFAULT_PROFILE",
    "DEFAULT_VERSION", "get_profile", "active_profile", "activate", "deactivate",
    "h2_priority_prefix", "header_order", "h1_header_name",
]


@dataclass
class Profile:
    """一个 Chrome 版本的完整线上指纹。字段与旧版 spec.py 的模块级常量一一对应。"""

    name: str
    chrome_version: str
    chrome_major: str
    chrome_platform: str
    chrome_arch: str
    ja4_prefix: str                       # 期望的 JA4 前缀(不含随机部分)

    # ---- TLS
    cipher_suites: list[int]
    supported_groups: list[int]
    signature_algorithms: list[int]
    supported_versions: list[int]
    alpn_protocols: list[bytes]
    ext_table: list[int]                  # BoringSSL kExtensions[] 置换基准顺序
    active_exts: list[int]                # 实际发出的扩展集合
    grease_values: list[int]
    trust_anchor_ids: list[str]

    # ---- HTTP/2
    h2_settings: list[tuple[int, int]]
    h2_window_update_increment: int
    akamai_fingerprint: str
    h2_priority_streams_legacy: list[int]
    h2_priority_weight: int
    h2_priority_depends_on: int
    h2_priority_exclusive: int

    # ---- 请求头
    default_headers: dict[str, str]
    ua_platform: str
    accept_navigate: str
    accept_xhr: str
    accept_json: str
    accept_style: str
    accept_image: str
    accept_by_dest: dict[str, str]
    priority_by_dest: dict[str, str]
    sec_fetch_dest_by_dest: dict[str, str]
    order_navigate: list[str]
    order_subresource: list[str]
    order_font: list[str]
    order_preflight: list[str]
    order_subresource_body: list[str]
    order_navigate_body: list[str]
    client_hint_order: list[str]
    client_hint_values: dict[str, str]
    order_subresource_hints: list[str]

    # ---------------------------------------------------------------- 派生
    @property
    def default_user_agent(self) -> str:
        return (f"Mozilla/5.0 ({self.ua_platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{self.chrome_major}.0.0.0 Safari/537.36")

    @property
    def num_ext_slots(self) -> int:
        return len(self.ext_table)

    @property
    def low_entropy_hints(self) -> frozenset[str]:
        return frozenset({"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"})

    @property
    def high_entropy_hints(self) -> frozenset[str]:
        return frozenset(self.client_hint_order) - self.low_entropy_hints

    @property
    def supported_dests(self) -> tuple[str, ...]:
        return tuple(self.accept_by_dest)

    def header_order(self, dest: str, mode: str, method: str, has_body: bool = False,
                     hints: bool = False) -> list[str]:
        """返回该请求类型下 Chrome 的头顺序(槽位)"""
        if dest == "preflight" or (dest == "empty" and mode == "cors"
                                   and method.upper() == "OPTIONS"):
            return self.order_preflight
        if dest == "font":
            return self.order_font
        if mode == "navigate":
            return self.order_navigate_body if has_body else self.order_navigate
        if hints:
            return self.order_subresource_hints
        return self.order_subresource_body if has_body else self.order_subresource

    @staticmethod
    def h1_header_name(lower: str) -> str:
        """HTTP/1.1 上 Chrome 用 Title-Case 发头名(h2 才全小写)"""
        return "-".join(part.capitalize() for part in lower.split("-"))


# ====================================================================== 153
PROFILE_153 = Profile(
    name="153",
    chrome_version="153.0.8010.48",
    chrome_major="153",
    chrome_platform="Windows",
    chrome_arch="x86_64",
    ja4_prefix="t13d1517h2_8daaf6152771",

    # 线上字节顺序（真抓核对；BoringSSL 默认偏好序 + Chromium strict cipher list）
    cipher_suites=[
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
        0x1303,  # TLS_CHACHA20_POLY1305_SHA256
        0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
        0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
    ],
    supported_groups=[0x11EC, 0x001D, 0x0017, 0x0018],
    signature_algorithms=[
        0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401,
        0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ],
    supported_versions=[0x0304, 0x0303],
    alpn_protocols=[b"h2", b"http/1.1"],

    # BoringSSL kExtensions[] 表顺序 (ssl/extensions.cc) —— 置换的基准顺序
    ext_table=[
        0x0000, 0xFE0D, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010,
        0x0005, 0x000D, 0x3374, 0x0012, 0x754F, 0x000E, 0x0033, 0x002D,
        0x002A, 0x002B, 0x002C, 0x0039, 0xFFA5, 0x001B, 0x0022, 0x44CD,
        0x4469, 0x002F, 0x0029, 0xCA34, 0x0013, 0x0014, 0x0015,
    ],
    active_exts=[
        0x0000, 0xFE0D, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023,
        0x0010, 0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B,
        0x001B, 0x44CD, 0xCA34,
    ],
    grease_values=[0x0A0A + 0x1010 * i for i in range(16)],
    # Chrome 的 MTC trust anchor ID 集合。152 是 32 个, 153/154 实测都是这 28 个
    trust_anchor_ids=[
        "82df130201", "82df130206", "82df13020d", "82df13020e", "82df13020f",
        "82df130212", "82df130213", "82df130214",
        "839a648c9b2d0107", "839a648c9b2d0108", "839a648c9b2d0109", "839a648c9b2d010a",
        "839a648c9b2d010b", "839a648c9b2d010c", "839a648c9b2d010d", "839a648c9b2d0112",
        "839a648c9b2d0113",
        "d6790901", "d6790904", "d6790905", "d6790906", "d6790907", "d6790908",
        "d679090a", "d679090b", "d679090c", "d679090d", "d679090f",
    ],

    h2_settings=[
        (0x0001, 65536),       # SETTINGS_HEADER_TABLE_SIZE
        (0x0002, 0),           # SETTINGS_ENABLE_PUSH
        (0x0004, 6291456),     # SETTINGS_INITIAL_WINDOW_SIZE
        (0x0006, 262144),      # SETTINGS_MAX_HEADER_LIST_SIZE
    ],
    h2_window_update_increment=15663105,
    akamai_fingerprint="1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    h2_priority_streams_legacy=[3, 5, 7, 9],
    h2_priority_weight=256,
    h2_priority_depends_on=0,
    h2_priority_exclusive=1,

    default_headers={
        "sec-ch-ua": '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9",
    },
    ua_platform="Windows NT 10.0; Win64; x64",
    accept_navigate=(
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    accept_xhr="*/*",
    accept_json="application/json, text/plain, */*",
    accept_style="text/css,*/*;q=0.1",
    accept_image="image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    accept_by_dest={
        "document": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
            "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "iframe": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
            "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "empty": "*/*",
        "script": "*/*",
        "style": "text/css,*/*;q=0.1",
        "image": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "font": "*/*",
        "preflight": "*/*",
    },
    priority_by_dest={
        "document": "u=0, i",
        "iframe": "u=0, i",
        "empty": "u=1, i",
        "script": "u=1",
        "style": "u=0",
        "image": "i",
        "font": "u=1",
        "preflight": "u=1, i",
    },
    sec_fetch_dest_by_dest={
        "document": "document", "iframe": "iframe", "empty": "empty", "script": "script",
        "style": "style", "image": "image", "font": "font", "preflight": "empty",
    },
    order_navigate=[
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "referer", "accept-encoding", "accept-language", "cookie", "priority",
    ],
    order_subresource=[
        "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
        "accept", "origin",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
        "referer", "accept-encoding", "accept-language", "cookie", "priority",
    ],
    order_font=[
        "origin", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
        "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
        "referer", "accept-encoding", "accept-language", "cookie", "priority",
    ],
    order_preflight=[
        "accept", "access-control-request-method", "access-control-request-headers",
        "origin", "user-agent",
        "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest",
        "referer", "accept-encoding", "accept-language", "cookie", "priority",
    ],
    order_subresource_body=[
        "content-length", "sec-ch-ua-platform", "user-agent", "sec-ch-ua",
        "content-type", "sec-ch-ua-mobile", "accept", "origin",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
        "referer", "accept-encoding", "accept-language", "cookie", "priority",
    ],
    order_navigate_body=[
        "content-length", "content-type",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "upgrade-insecure-requests", "user-agent", "accept",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "referer", "accept-encoding", "accept-language", "cookie", "priority",
    ],
    client_hint_order=[
        "sec-ch-ua-full-version-list",
        "sec-ch-ua-platform",
        "viewport-width",
        "device-memory",
        "sec-ch-ua",
        "sec-ch-ua-model",
        "sec-ch-ua-mobile",
        "sec-ch-ua-bitness",
        "sec-ch-ua-wow64",
        "sec-ch-ua-arch",
        "sec-ch-ua-full-version",
        "downlink",
        "ect",
        "dpr",
        "user-agent",
        "rtt",
        "sec-ch-ua-platform-version",
        "viewport-height",
    ],
    client_hint_values={
        "sec-ch-ua": '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-full-version-list":
            '"Google Chrome";v="153.0.8010.48", "Not_A Brand";v="8.0.0.0", '
            '"Chromium";v="153.0.8010.48"',
        "sec-ch-ua-full-version": '"153.0.8010.48"',
        "sec-ch-ua-arch": '"x86"',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-model": '""',
        "sec-ch-ua-platform-version": '"15.0.0"',
        "sec-ch-ua-wow64": "?0",
        "device-memory": "8",
        "dpr": "1",
        "viewport-width": "1280",
        "viewport-height": "720",
        "rtt": "0",
        "downlink": "10",
        "ect": "4g",
    },
    order_subresource_hints=[
        "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "viewport-width",
        "device-memory", "sec-ch-ua", "sec-ch-ua-model", "sec-ch-ua-mobile",
        "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch",
        "sec-ch-ua-full-version", "downlink", "ect", "dpr", "user-agent", "rtt",
        "sec-ch-ua-platform-version", "viewport-height",
        "accept", "origin",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
        "referer", "accept-encoding", "accept-language", "cookie", "priority",
    ],
)


# ====================================================================== 154
# 与 153 的差异**只有版本字符串与 UA 品牌串**(TLS / HTTP2 线格式实测完全一致),
# 所以这里只覆盖这几个字段。sec-ch-ua 的品牌顺序与 GREASE 品牌是 Stable 154 实测值,
# 两次独立启动完全一致(见 capture/chrome154b/)。
_SEC_CH_UA_154 = '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"'
_SEC_CH_UA_FULL_154 = (
    '"Chromium";v="154.0.8037.98", "Google Chrome";v="154.0.8037.98", '
    '"Not A(Brand";v="99.0.0.0"'
)

PROFILE_154 = replace(
    PROFILE_153,
    name="154",
    chrome_version="154.0.8037.98",
    chrome_major="154",
    ja4_prefix="t13d1517h2_8daaf6152771",       # 实测与 153 完全一致
    default_headers={
        **PROFILE_153.default_headers,
        "sec-ch-ua": _SEC_CH_UA_154,
    },
    client_hint_values={
        **PROFILE_153.client_hint_values,
        "sec-ch-ua": _SEC_CH_UA_154,
        "sec-ch-ua-full-version-list": _SEC_CH_UA_FULL_154,
        "sec-ch-ua-full-version": '"154.0.8037.98"',
    },
)

PROFILES: dict[str, Profile] = {
    PROFILE_153.name: PROFILE_153,
    PROFILE_154.name: PROFILE_154,
}
DEFAULT_VERSION = "154"
DEFAULT_PROFILE = PROFILE_154


# ====================================================================== profile 上下文
_ACTIVE: ContextVar[Profile] = ContextVar("chrome_fp_profile", default=DEFAULT_PROFILE)
_PROFILE_FIELDS = frozenset(Profile.__dataclass_fields__)


def get_profile(version: str | Profile | None = None) -> Profile:
    """``"154"`` / ``"154.0.8037.98"`` / ``Profile`` / ``None``(默认版本) -> Profile"""
    if version is None:
        return DEFAULT_PROFILE
    if isinstance(version, Profile):
        return version
    key = str(version).strip().split(".")[0]
    if key not in PROFILES:
        raise ValueError(f"不支持的 Chrome 版本 {version!r}, 可选: {sorted(PROFILES)}")
    return PROFILES[key]


def active_profile() -> Profile:
    """当前生效的 profile(Session 构造时会切到自己那版)"""
    return _ACTIVE.get()


def activate(version: str | Profile | None) -> Token:
    return _ACTIVE.set(get_profile(version))


def deactivate(token: Token) -> None:
    _ACTIVE.reset(token)


# 旧接口: 模块级常量现在转发到"当前生效 profile", 因此两个版本可以共存于同一进程。
# 旧名字(全大写)保持可用, 见 _LEGACY_ALIASES。
_LEGACY_ALIASES = {
    "CHROME_VERSION": "chrome_version",
    "CHROME_MAJOR": "chrome_major",
    "CHROME_PLATFORM": "chrome_platform",
    "CHROME_ARCH": "chrome_arch",
    "CIPHER_SUITES": "cipher_suites",
    "SUPPORTED_GROUPS": "supported_groups",
    "SIGNATURE_ALGORITHMS": "signature_algorithms",
    "SUPPORTED_VERSIONS": "supported_versions",
    "ALPN_PROTOCOLS": "alpn_protocols",
    "EXT_TABLE": "ext_table",
    "NUM_EXT_SLOTS": "num_ext_slots",
    "ACTIVE_EXTS": "active_exts",
    "GREASE_VALUES": "grease_values",
    "TRUST_ANCHOR_IDS": "trust_anchor_ids",
    "H2_SETTINGS": "h2_settings",
    "H2_WINDOW_UPDATE_INCREMENT": "h2_window_update_increment",
    "AKAMAI_FINGERPRINT": "akamai_fingerprint",
    "H2_PRIORITY_STREAMS_LEGACY": "h2_priority_streams_legacy",
    "H2_PRIORITY_WEIGHT": "h2_priority_weight",
    "H2_PRIORITY_DEPENDS_ON": "h2_priority_depends_on",
    "H2_PRIORITY_EXCLUSIVE": "h2_priority_exclusive",
    "DEFAULT_HEADERS": "default_headers",
    "DEFAULT_USER_AGENT": "default_user_agent",
    "UA_PLATFORM": "ua_platform",
    "ACCEPT_NAVIGATE": "accept_navigate",
    "ACCEPT_XHR": "accept_xhr",
    "ACCEPT_JSON": "accept_json",
    "ACCEPT_STYLE": "accept_style",
    "ACCEPT_IMAGE": "accept_image",
    "ACCEPT_BY_DEST": "accept_by_dest",
    "PRIORITY_BY_DEST": "priority_by_dest",
    "SEC_FETCH_DEST_BY_DEST": "sec_fetch_dest_by_dest",
    "ORDER_NAVIGATE": "order_navigate",
    "ORDER_SUBRESOURCE": "order_subresource",
    "ORDER_FONT": "order_font",
    "ORDER_PREFLIGHT": "order_preflight",
    "ORDER_SUBRESOURCE_BODY": "order_subresource_body",
    "ORDER_NAVIGATE_BODY": "order_navigate_body",
    "CLIENT_HINT_ORDER": "client_hint_order",
    "CLIENT_HINT_VALUES": "client_hint_values",
    "ORDER_SUBRESOURCE_HINTS": "order_subresource_hints",
    "LOW_ENTROPY_HINTS": "low_entropy_hints",
    "HIGH_ENTROPY_HINTS": "high_entropy_hints",
    "SUPPORTED_DESTS": "supported_dests",
}


def __getattr__(name: str):
    if name in _PROFILE_FIELDS:
        return getattr(_ACTIVE.get(), name)
    alias = _LEGACY_ALIASES.get(name)
    if alias:
        return getattr(_ACTIVE.get(), alias)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ====================================================================== 兼容旧名字
def header_order(dest: str, mode: str, method: str, has_body: bool = False,
                 hints: bool = False) -> list[str]:
    """返回该请求类型下 Chrome 的头顺序(槽位)"""
    return _ACTIVE.get().header_order(dest, mode, method, has_body=has_body, hints=hints)


def h1_header_name(lower: str) -> str:
    """HTTP/1.1 上 Chrome 用 Title-Case 发头名(h2 才全小写)"""
    return Profile.h1_header_name(lower)


NAVIGATE_HEADER_ORDER = PROFILE_153.order_navigate  # 兼容旧名字(153 顺序, 两版一致)

# Chrome 152 的旧 trust anchor 集合(仅对照)
TRUST_ANCHOR_IDS_152 = PROFILE_153.trust_anchor_ids + [
    "d6790902", "d6790903", "d6790909", "d679090e",
]


# ====================================================================== H2 优先级前缀
# 真机抓包(153/154 一致): HEADERS 带 PRIORITY 标志, 前缀 (E=1, depends_on=0, weight)。
# weight 由 RFC 9218 的 urgency 查下面这张表 —— Chrome 内部就是这几个离散值:
#   document "u=0, i" -> 256,  image "u=1, i" -> 220,  image "i"(u=3) -> 147
H2_WEIGHT_BY_URGENCY = (256, 220, 183, 147, 110, 74, 37, 37)


def h2_priority_prefix(priority_header: str | None) -> dict | None:
    """RFC 9218 ``priority`` 头 -> 真 Chrome 的 HEADERS PRIORITY 前缀(dict)。

    没有 priority 头时返回 ``None``(不发前缀); Chrome 自己总会带这个头。
    """
    if not priority_header:
        return None
    urgency = 3                                  # RFC 9218 默认 urgency
    for part in priority_header.split(","):
        part = part.strip()
        if part.startswith("u="):
            try:
                urgency = max(0, min(7, int(part[2:])))
            except ValueError:
                pass
    return {
        "exclusive": True,
        "depends_on": 0,
        "weight": H2_WEIGHT_BY_URGENCY[urgency],
    }
