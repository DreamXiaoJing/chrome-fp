"""Chrome 153 客户端指纹规格 — 全部来自本地源码 + 真机实抓字节核对。

证据来源:
- 本轮真机抓包: 本机 Chrome 153.0.8010.48, Windows x64, 17 条 ClientHello +
  10 条 HTTP/2 连接 (capture/chrome153/, 见 tools/run_capture.py 与 README)
- 本地 Chromium/BoringSSL 源码:
  - 扩展表顺序          : ssl/extensions.cc:4067-4295 (kExtensions[])
  - 扩展置换(随机顺序)  : ssl/extensions.cc:4306-4328 (Fisher-Yates over kNumExtensions)
  - GREASE 头/尾        : ssl/extensions.cc:4490-4494, 4517-4523
  - padding(0x0015)规则 : ssl/extensions.cc:4527-4560
  - session_id 32 字节  : ssl/handshake_client.cc:427-432 (RAND_bytes)
  - ECH GREASE 结构     : ssl/encrypted_client_hello.cc:732-784
  - trust_anchors 0xca34: include/openssl/tls1.h:141 + extensions.cc:2948-2965
  - ALPS 0x44cd         : ssl/extensions.cc:3645-3670

实测真值 (Chrome 153.0.8010.48, 本机 Windows):
  JA4  = t13d1517h2_8daaf6152771_<随机>   (17/17 条一致)
  JA4_r= t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,
         c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,
         44cd,ca34,fe0d,ff01_<GREASE 签名算法>,0904,0905,0906,0403,0804,0401,0503,
         0805,0501,0806,0601
  Akamai(H2) = 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p   (10/10 条一致)
  PRIORITY 帧数量 = 0  (Chrome 153 不再发 3/5/7/9 优先级树, 见 README「与 152 的差异」)
"""

from __future__ import annotations

CHROME_VERSION = "153.0.8010.48"
CHROME_MAJOR = "153"
CHROME_PLATFORM = "Windows"
CHROME_ARCH = "x86_64"

# ---------------------------------------------------------------- TLS 1.3 / 密码套件

# 线上字节顺序（真抓核对；BoringSSL 默认偏好序 + Chromium strict cipher list）
CIPHER_SUITES = [
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
]

SUPPORTED_GROUPS = [0x11EC, 0x001D, 0x0017, 0x0018]   # X25519MLKEM768, x25519, secp256r1, secp384r1
SIGNATURE_ALGORITHMS = [
    0x0904,  # ecdsa_secp256r1_sha256
    0x0905,  # ecdsa_secp384r1_sha384
    0x0906,  # ecdsa_secp521r1_sha512
    0x0403,  # ecdsa_secp256r1_sha256 (legacy 私钥用)
    0x0804,  # rsa_pss_rsae_sha256
    0x0401,  # rsa_pkcs1_sha256
    0x0503,  # ecdsa_sha256 (legacy)
    0x0805,  # rsa_pss_rsae_sha384
    0x0501,  # rsa_pkcs1_sha384
    0x0806,  # rsa_pss_rsae_sha512
    0x0601,  # rsa_pkcs1_sha512
]
SUPPORTED_VERSIONS = [0x0304, 0x0303]   # TLS1.3, TLS1.2
ALPN_PROTOCOLS = [b"h2", b"http/1.1"]

# BoringSSL kExtensions[] 表顺序 (ssl/extensions.cc:4067-4295) —— 置换的基准顺序
EXT_TABLE = [
    0x0000,  # server_name
    0xFE0D,  # encrypted_client_hello
    0x0017,  # extended_master_secret
    0xFF01,  # renegotiate
    0x000A,  # supported_groups
    0x000B,  # ec_point_formats
    0x0023,  # session_ticket
    0x0010,  # application_layer_protocol_negotiation
    0x0005,  # status_request
    0x000D,  # signature_algorithms
    0x3374,  # next_proto_neg
    0x0012,  # certificate_timestamp
    0x754F,  # channel_id
    0x000E,  # srtp
    0x0033,  # key_share
    0x002D,  # psk_key_exchange_modes
    0x002A,  # early_data
    0x002B,  # supported_versions
    0x002C,  # cookie
    0x0039,  # quic_transport_parameters
    0xFFA5,  # quic_transport_parameters_legacy
    0x001B,  # cert_compression
    0x0022,  # delegated_credential
    0x44CD,  # application_settings (ALPS)
    0x4469,  # application_settings_old
    0x002F,  # certificate_authorities
    0x0029,  # pake
    0xCA34,  # trust_anchors
    0x0013,  # client_cert_type
    0x0014,  # server_cert_type
    0x0015,  # server_padding
]
NUM_EXT_SLOTS = len(EXT_TABLE)   # 31

# 实际会发出的扩展（其余因条件不满足而为空）
ACTIVE_EXTS = [
    0x0000, 0xFE0D, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023,
    0x0010, 0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B,
    0x001B, 0x44CD, 0xCA34,
]

# GREASE 值集合 (RFC 8701)
GREASE_VALUES = [0x0A0A + 0x1010 * i for i in range(16)]

# ---------------------------------------------------------------- trust anchors (0xca34)

# Chrome 的 MTC trust anchor ID 集合。**数量随版本变**: 152 是 32 个, 153 实测只有 28 个
# (本轮 17 条真机 ClientHello 集合完全一致, 见 capture/chrome153/tls_diff.txt)。
# 相比 152 少了 d6790902 / d6790903 / d6790909 / d679090e 四个 —— 发多了会被看出不是 153。
TRUST_ANCHOR_IDS = [
    "82df130201", "82df130206", "82df13020d", "82df13020e", "82df13020f",
    "82df130212", "82df130213", "82df130214",
    "839a648c9b2d0107", "839a648c9b2d0108", "839a648c9b2d0109", "839a648c9b2d010a",
    "839a648c9b2d010b", "839a648c9b2d010c", "839a648c9b2d010d", "839a648c9b2d0112",
    "839a648c9b2d0113",
    "d6790901", "d6790904", "d6790905", "d6790906", "d6790907", "d6790908",
    "d679090a", "d679090b", "d679090c", "d679090d", "d679090f",
]

# Chrome 152 的旧集合(仅用于对照/回归, 默认不发)
TRUST_ANCHOR_IDS_152 = TRUST_ANCHOR_IDS + [
    "d6790902", "d6790903", "d6790909", "d679090e",
]

# ---------------------------------------------------------------- HTTP/2 (SPDY)

H2_SETTINGS = [
    (0x0001, 65536),       # SETTINGS_HEADER_TABLE_SIZE
    (0x0002, 0),           # SETTINGS_ENABLE_PUSH
    (0x0004, 6291456),     # SETTINGS_INITIAL_WINDOW_SIZE
    (0x0006, 262144),      # SETTINGS_MAX_HEADER_LIST_SIZE
]
H2_WINDOW_UPDATE_INCREMENT = 15663105
AKAMAI_FINGERPRINT = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

# Chrome 152 曾发送 3/5/7/9 的 PRIORITY 树(Akamai 第 3 段 = m,a,s,p 其实是**伪头顺序**,
# 不是优先级流)。Chrome 153 实测 **一个 PRIORITY 帧都不发**, 所以第 3 段恒为 "0"。
# 这里保留常量做历史对照, 默认关闭, 见 Session(send_priority_tree=False)。
H2_PRIORITY_STREAMS_LEGACY = [3, 5, 7, 9]
H2_PRIORITY_WEIGHT = 256
H2_PRIORITY_DEPENDS_ON = 0
H2_PRIORITY_EXCLUSIVE = 1

# ---------------------------------------------------------------- 请求头

DEFAULT_HEADERS = {
    # Chrome 153 (Windows) 实测: 品牌顺序 = Google Chrome, Not_A Brand, Chromium
    "sec-ch-ua": '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "zh-CN,zh;q=0.9",
}
UA_PLATFORM = "Windows NT 10.0; Win64; x64"
DEFAULT_USER_AGENT = (
    f"Mozilla/5.0 ({UA_PLATFORM}) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36"
)

ACCEPT_NAVIGATE = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
    "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)
ACCEPT_XHR = "*/*"
ACCEPT_JSON = "application/json, text/plain, */*"
ACCEPT_STYLE = "text/css,*/*;q=0.1"
ACCEPT_IMAGE = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"

# ---- 每种资源类型的 accept / priority (真抓逐条核对, 见 capture/chrome153/summary.txt)

ACCEPT_BY_DEST = {
    "document": ACCEPT_NAVIGATE,
    "iframe": ACCEPT_NAVIGATE,
    "empty": ACCEPT_XHR,
    "script": ACCEPT_XHR,
    "style": ACCEPT_STYLE,
    "image": ACCEPT_IMAGE,
    "font": ACCEPT_XHR,
    "preflight": ACCEPT_XHR,
}

PRIORITY_BY_DEST = {
    "document": "u=0, i",
    "iframe": "u=0, i",
    "empty": "u=1, i",
    "script": "u=1",
    "style": "u=0",
    # <img> 元素实测是 "i"(incremental + 默认 urgency); favicon 那类才是 "u=1, i"。
    # 需要精确复刻时用 Session(priority=...) / get(..., priority=...) 覆盖。
    "image": "i",
    "font": "u=1",
    "preflight": "u=1, i",
}

SEC_FETCH_DEST_BY_DEST = {
    "document": "document",
    "iframe": "iframe",
    "empty": "empty",
    "script": "script",
    "style": "style",
    "image": "image",
    "font": "font",
    "preflight": "empty",
}

# 头顺序槽位: 出现在列表里就按这个顺序发, 不适用的槽位跳过。
# 真 Chrome 的导航请求和子资源请求顺序**不一样**, 所以不能只有一份顺序表。
ORDER_NAVIGATE = [
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "upgrade-insecure-requests", "user-agent", "accept",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie", "priority",
]
ORDER_SUBRESOURCE = [
    "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
    "accept", "origin",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie", "priority",
]
# <link rel=preload as=font crossorigin> 这类: origin 排在最前面
ORDER_FONT = [
    "origin", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
    "accept",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie", "priority",
]
# CORS 预检: 没有 client hints, 且 sec-fetch-mode 在 sec-fetch-site 之前
ORDER_PREFLIGHT = [
    "accept", "access-control-request-method", "access-control-request-headers",
    "origin", "user-agent",
    "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie", "priority",
]
# 带 body 的子资源请求: 真抓显示 content-length 跑到最前, content-type 夹在
# sec-ch-ua 和 sec-ch-ua-mobile 之间(Chrome 内部按 header 加入顺序去重后的结果)
ORDER_SUBRESOURCE_BODY = [
    "content-length", "sec-ch-ua-platform", "user-agent", "sec-ch-ua",
    "content-type", "sec-ch-ua-mobile", "accept", "origin",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie", "priority",
]
ORDER_NAVIGATE_BODY = [
    "content-length", "content-type",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "upgrade-insecure-requests", "user-agent", "accept",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie", "priority",
]

# ---------------------------------------------------------------- 高熵 client hints
#
# 网站用 Accept-CH 让浏览器在**后续**请求里带上这些头。Chrome 内部有一张固定的
# 顺序表(不是 Accept-CH 里的顺序): 没开启的跳过, 开启的保持相对顺序。
# 下面这张表是从探针抓包读出来的 —— 服务器下发 Accept-CH 列 14 个 hint, 1.5 秒后的
# fetch 请求就带上了, 而且低熵的 sec-ch-ua* 也交错在同一张表里(tools 里 run_capture
# 的 --probe + CHROME_FP_ACCEPT_CH 可以复现)。
CLIENT_HINT_ORDER = [
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
]

# 取值。注意: 探针抓包里 UA 派生那几个(full-version / full-version-list / arch /
# bitness / platform-version)是**空串**, 因为抓包时为了 UA 逐字节一致加了
# --user-agent 覆盖, Chrome 会把 UA 派生的高熵 hint 置空。正常 UA 下它们有真实值,
# 这里按 Chrome 153 / Windows x86_64 填; 要精确对齐可以逐项覆盖:
#     Session(client_hint_values={"device-memory": "4"})
CLIENT_HINT_VALUES = {
    "sec-ch-ua": DEFAULT_HEADERS["sec-ch-ua"],
    "sec-ch-ua-mobile": DEFAULT_HEADERS["sec-ch-ua-mobile"],
    "sec-ch-ua-platform": DEFAULT_HEADERS["sec-ch-ua-platform"],
    "sec-ch-ua-full-version-list":
        f'"Google Chrome";v="{CHROME_VERSION}", "Not_A Brand";v="8.0.0.0", '
        f'"Chromium";v="{CHROME_VERSION}"',
    "sec-ch-ua-full-version": f'"{CHROME_VERSION}"',
    "sec-ch-ua-arch": '"x86"',              # Windows 上 32/64 位都报 x86
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform-version": '"15.0.0"',   # Windows 11 23H2+ 的映射值
    "sec-ch-ua-wow64": "?0",
    "device-memory": "8",
    "dpr": "1",
    "viewport-width": "1280",
    "viewport-height": "720",
    "rtt": "0",
    "downlink": "10",
    "ect": "4g",
}

LOW_ENTROPY_HINTS = frozenset({"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"})
HIGH_ENTROPY_HINTS = frozenset(CLIENT_HINT_ORDER) - LOW_ENTROPY_HINTS

# 开启高熵 hint 时的子资源头顺序(实证交错顺序)
ORDER_SUBRESOURCE_HINTS = [
    "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "viewport-width",
    "device-memory", "sec-ch-ua", "sec-ch-ua-model", "sec-ch-ua-mobile",
    "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch",
    "sec-ch-ua-full-version", "downlink", "ect", "dpr", "user-agent", "rtt",
    "sec-ch-ua-platform-version", "viewport-height",
    "accept", "origin",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie", "priority",
]

# 兼容旧名字
NAVIGATE_HEADER_ORDER = ORDER_NAVIGATE


def header_order(dest: str, mode: str, method: str, has_body: bool = False,
                 hints: bool = False) -> list[str]:
    """返回该请求类型下 Chrome 的头顺序(槽位)"""
    if dest == "preflight" or (dest == "empty" and mode == "cors" and method.upper() == "OPTIONS"):
        return ORDER_PREFLIGHT
    if dest == "font":
        return ORDER_FONT
    if mode == "navigate":
        return ORDER_NAVIGATE_BODY if has_body else ORDER_NAVIGATE
    if hints:
        return ORDER_SUBRESOURCE_HINTS
    return ORDER_SUBRESOURCE_BODY if has_body else ORDER_SUBRESOURCE


SUPPORTED_DESTS = tuple(ACCEPT_BY_DEST)


def h1_header_name(lower: str) -> str:
    """HTTP/1.1 上 Chrome 用 Title-Case 发头名(h2 才全小写)"""
    return "-".join(part.capitalize() for part in lower.split("-"))
