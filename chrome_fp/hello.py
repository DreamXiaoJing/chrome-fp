"""按 Chrome/BoringSSL 源码规则逐字节构造 ClientHello。

结构完全照 ssl_add_clienthello_tlsext (extensions.cc:4462+) 实现:
  1. 先写一个空的 GREASE 扩展 (ssl_grease_extension1)
  2. 按 kExtensions[] 表顺序(或 Fisher-Yates 随机置换后的顺序)逐个尝试添加扩展
  3. 最后写一个 1 字节的 GREASE 扩展 (ssl_grease_extension2)
  4. 长度落在 (0xff, 0x200) 时补 padding 扩展 (本库通常用不到, 保留规则)

另外支持 **HelloRetryRequest 的第二个 ClientHello**(RFC 8446 §4.1.4):
`rebuild_for_hrr()` 会复用第一个 ClientHello 的 random / session_id / GREASE 取值 /
扩展顺序, 只把 key_share 换成服务器要求的那个组并按需补上 cookie 扩展 —— 这正是
BoringSSL 的做法(ClientHello 除被点名的部分外必须逐字节不变)。
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import mlkem, spec

HANDSHAKE_CLIENT_HELLO = 1
SSL3_HM_HEADER_LENGTH = 4

# 能放进 key_share 的命名曲线(ECDH)
EC_GROUPS = {0x0017: ec.SECP256R1, 0x0018: ec.SECP384R1}


def _u8(x: int) -> bytes:
    return struct.pack(">B", x)


def _u16(x: int) -> bytes:
    return struct.pack(">H", x)


def _u16len(b: bytes) -> bytes:
    return _u16(len(b)) + b


def _u8len(b: bytes) -> bytes:
    return _u8(len(b)) + b


def _grease() -> int:
    return spec.GREASE_VALUES[os.urandom(1)[0] % len(spec.GREASE_VALUES)]


def generate_share(group: int):
    """生成一个组的密钥对, 返回 (私钥, 公开的 key_exchange 字节)"""
    if group == 0x001D:                                  # x25519
        priv = x25519.X25519PrivateKey.generate()
        return priv, priv.public_key().public_bytes_raw()
    if group in EC_GROUPS:                               # secp256r1 / secp384r1
        priv = ec.generate_private_key(EC_GROUPS[group]())
        return priv, priv.public_key().public_bytes(Encoding.X962,
                                                    PublicFormat.UncompressedPoint)
    raise ValueError(f"不支持生成组 0x{group:04x} 的 key share")


@dataclass
class ClientHello:
    """构造结果 + 完成握手所需的密钥材料"""

    record: bytes
    handshake: bytes
    host: str
    random: bytes
    session_id: bytes
    key_share_private_x25519: x25519.X25519PrivateKey
    x25519_public: bytes
    mlkem_ek: bytes
    mlkem_dk: bytes
    grease: dict = field(default_factory=dict)
    # ---- 以下用于 HRR 重放(第二个 ClientHello 必须和第一个保持一致的部分) ----
    key_shares: dict = field(default_factory=dict)     # group -> 私钥
    supported_groups: list = field(default_factory=list)
    ext_order: list = field(default_factory=list)
    grease_parts: tuple = ()
    include_grease: bool = True
    is_hrr_retry: bool = False

    @property
    def ja3(self) -> tuple[str, str]:
        from .fingerprint import ja3_from_hello

        return ja3_from_hello(self.record)

    def explain(self) -> str:
        from .fingerprint import describe

        return describe(self.record)


GREASE_PARTS = ("cipher", "ext", "group", "version", "sigalg", "keyshare")


def _extension_bodies(host: str, grease: dict, materials: dict, include_mlkem: bool = True,
                      grease_parts: tuple[str, ...] = GREASE_PARTS,
                      supported_groups: list[int] | None = None,
                      key_share_groups: list[int] | None = None,
                      cookie: bytes | None = None,
                      grease_key_share: bool = True) -> dict[int, bytes]:
    """返回 {扩展类型: 内容}, 内容与真 Chrome 完全一致。

    supported_groups / key_share_groups 分开传, 是因为 HRR 的第二个 ClientHello 里
    supported_groups 必须和第一个完全一样, 但 key_share 只能留服务器点的那个组。
    """
    if supported_groups is None:
        supported_groups = (spec.SUPPORTED_GROUPS if include_mlkem
                            else [g for g in spec.SUPPORTED_GROUPS if g != 0x11EC])
    if key_share_groups is None:
        key_share_groups = [0x11EC, 0x001D] if include_mlkem else [0x001D]

    key_shares: dict[int, object] = {}
    pubs: dict[int, bytes] = {}
    materials["key_shares"] = key_shares
    materials["pub_bytes"] = pubs
    # X25519MLKEM768 的混合份额用的是**自己那把** x25519 密钥, 和后面独立的 x25519
    # 份额不是同一把 —— 真机抓包实测: 混合份额尾 32 字节 != 独立 x25519 份额。
    mlkem_ek = mlkem_dk = b""
    if 0x11EC in key_share_groups:
        mlkem_ek, mlkem_dk = mlkem.keygen()
    for group in key_share_groups:
        if group == 0x11EC:                              # X25519MLKEM768
            priv, xpub = generate_share(0x001D)
            key_shares[0x11EC] = priv
            pubs[0x11EC] = mlkem_ek + xpub
        elif group == 0x001D:                            # 纯 x25519
            priv, xpub = generate_share(0x001D)
            key_shares[0x001D] = priv
            pubs[0x001D] = xpub
            materials["x25519_priv"] = priv
            materials["x25519_pub"] = xpub
        else:                                            # secp256r1 / secp384r1 (HRR 后常见)
            priv, pub = generate_share(group)
            key_shares[group] = priv
            pubs[group] = pub
    materials.setdefault("x25519_priv", None)
    materials.setdefault("x25519_pub", b"")
    materials["mlkem_ek"] = mlkem_ek
    materials["mlkem_dk"] = mlkem_dk
    materials["supported_groups"] = list(supported_groups)
    materials["key_share_groups"] = list(key_share_groups)

    bodies: dict[int, bytes] = {}

    # server_name
    host_b = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode()
    bodies[0x0000] = _u16len(_u8(0x00) + _u16len(host_b))

    # encrypted_client_hello (ECH GREASE): encrypted_client_hello.cc:732-784
    config_id = os.urandom(1)
    payload_len = 32 * (4 + os.urandom(1)[0] % 4) + 16   # {144,176,208,240}
    ech = (
        _u8(0x00)                      # type = outer
        + _u16(0x0001)                 # kdf_id = HKDF-SHA256
        + _u16(0x0001)                 # aead_id = AES-128-GCM
        + config_id                    # config_id (random)
        + _u16len(os.urandom(32))      # enc (x25519 public, 随机)
        + _u16len(os.urandom(payload_len))  # payload (随机)
    )
    bodies[0xFE0D] = ech

    bodies[0x0017] = b""               # extended_master_secret
    bodies[0xFF01] = b"\x00"           # renegotiation_info
    groups = list(supported_groups)
    if "group" in grease_parts:
        groups = [grease["group"], *groups]
    bodies[0x000A] = _u16len(b"".join(_u16(g) for g in groups))   # supported_groups
    bodies[0x000B] = b"\x01\x00"       # ec_point_formats: uncompressed
    bodies[0x0023] = b""               # session_ticket (empty)
    bodies[0x0010] = _u16len(b"".join(_u8len(p) for p in spec.ALPN_PROTOCOLS))
    bodies[0x0005] = b"\x01\x00\x00\x00\x00"   # status_request (OCSP)
    sigalgs = spec.SIGNATURE_ALGORITHMS if "sigalg" not in grease_parts else [grease["sigalg"], *spec.SIGNATURE_ALGORITHMS]
    bodies[0x000D] = _u16len(b"".join(_u16(s) for s in sigalgs))   # signature_algorithms
    bodies[0x0012] = b""               # signed_certificate_timestamp (empty)
    if "keyshare" in grease_parts and grease_key_share:
        # GREASE 组值必须与 supported_groups 里的 GREASE 相同
        # (OpenSSL 会因 key_share 的组不在 supported_groups 里而报 illegal_parameter;
        #  真 Chrome 两处本来就是同一个值, 见 8 份抓包样本)
        ks = _u16(grease["group"]) + _u16len(b"\x00")             # GREASE key share
    else:
        # HRR 的第二个 ClientHello 里不能带 GREASE key share:
        # RFC 8446 §4.1.2 要求此时 key_share **恰好一个** KeyShareEntry,
        # OpenSSL 见到多余的组直接 illegal_parameter(实测踩到)。
        ks = b""
    for group in key_share_groups:
        ks += _u16(group) + _u16len(pubs[group])
    bodies[0x0033] = _u16len(ks)       # key_share
    bodies[0x002D] = b"\x01\x01"       # psk_key_exchange_modes: psk_dhe_ke
    versions = spec.SUPPORTED_VERSIONS if "version" not in grease_parts else [grease["version"], *spec.SUPPORTED_VERSIONS]
    bodies[0x002B] = _u8len(b"".join(_u16(v) for v in versions))   # supported_versions
    bodies[0x001B] = b"\x02\x00\x02"   # compress_certificate: brotli
    bodies[0x44CD] = _u16len(_u8len(b"h2"))     # ALPS
    if cookie is not None:
        # HRR 的 cookie 扩展(RFC 8446 §4.2.2): opaque cookie<1..2^16-1>
        bodies[0x002C] = _u16len(cookie)

    # trust_anchors: 32 个 ID 随机排序
    ids = [bytes.fromhex(x) for x in spec.TRUST_ANCHOR_IDS]
    ids = _shuffle(ids)
    blob = b"".join(_u8len(i) for i in ids)
    bodies[0xCA34] = _u16len(blob)

    return bodies


def _shuffle(items: list) -> list:
    out = list(items)
    for i in range(len(out) - 1, 0, -1):
        j = os.urandom(4)[0] % (i + 1) if False else int.from_bytes(os.urandom(4), "big") % (i + 1)
        out[i], out[j] = out[j], out[i]
    return out


def _permutation(n: int) -> list[int]:
    """BoringSSL ssl_setup_extension_permutation (extensions.cc:4306-4328) 的 Fisher-Yates"""
    perm = list(range(n))
    seeds = [int.from_bytes(os.urandom(4), "big") for _ in range(n - 1)]
    for i in range(n - 1, 0, -1):
        j = seeds[i - 1] % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def _assemble(host: str, bodies: dict[int, bytes], grease: dict, random: bytes,
              session_id: bytes, order: list[int], grease_parts: tuple[str, ...],
              include_grease: bool) -> tuple[bytes, bytes]:
    """按扩展顺序把 ClientHello 拼出来, 返回 (handshake, record)"""
    hello = bytearray()
    hello += b"\x03\x03"                          # legacy_version = TLS1.2
    hello += random
    hello += _u8len(session_id)                   # 32 字节随机 session id
    ciphers = ([grease["cipher"]] if "cipher" in grease_parts else []) + spec.CIPHER_SUITES
    hello += _u16len(b"".join(_u16(c) for c in ciphers))
    hello += _u8len(b"\x00")                      # compression: null

    # ---- 扩展 ----
    exts = bytearray()
    if include_grease:
        exts += _u16(grease["ext1"]) + _u16(0)    # 空 GREASE 扩展, 永远第一个

    last_was_empty = False
    for idx in order:
        ext_type = spec.EXT_TABLE[idx]
        body = bodies.get(ext_type)
        if body is None:
            continue
        exts += _u16(ext_type) + _u16len(body)
        last_was_empty = len(body) == 0

    if include_grease:
        exts += _u16(grease["ext2"]) + _u16len(b"\x00")   # 1 字节 GREASE 扩展, 永远最后
        last_was_empty = False

    # ---- padding 规则 (extensions.cc:4527-4560) ----
    msg_len = SSL3_HM_HEADER_LENGTH + len(hello) + 2 + len(exts)
    padding_len = 0
    if last_was_empty:
        padding_len = 1
        msg_len += 4 + padding_len
    if 0xFF < msg_len < 0x200:
        if padding_len:
            msg_len -= 4 + padding_len
        padding_len = 0x200 - msg_len
        if padding_len == 0:
            padding_len = 1
    if padding_len:
        exts += _u16(0x0015) + _u16len(b"\x00" * padding_len)

    hello += _u16len(bytes(exts))

    handshake = _u8(HANDSHAKE_CLIENT_HELLO) + len(hello).to_bytes(3, "big") + bytes(hello)
    record = b"\x16\x03\x01" + _u16(len(handshake)) + handshake
    return handshake, record


def build_client_hello(
    host: str,
    *,
    permute_extensions: bool = True,
    include_grease: bool = True,
    include_mlkem: bool = True,
    grease_parts: tuple[str, ...] | None = None,
) -> ClientHello:
    """生成 record 层字节 + 握手密钥材料"""
    grease = {
        "cipher": _grease(),
        "ext1": _grease(),
        "ext2": _grease(),
        "group": _grease(),
        "version": _grease(),
        "sigalg": _grease(),
    }
    materials: dict = {}
    grease["keyshare_group"] = grease["group"]   # key_share 与 supported_groups 共用同一个 GREASE 组值
    if grease_parts is None:
        grease_parts = GREASE_PARTS if include_grease else ()
    if not include_grease:
        grease_parts = ()
    # GREASE 的 key_share 与 supported_groups 必须成对出现(否则服务器报 illegal_parameter)
    if "keyshare" in grease_parts and "group" not in grease_parts:
        grease_parts = (*grease_parts, "group")
    bodies = _extension_bodies(host, grease, materials, include_mlkem=include_mlkem,
                               grease_parts=grease_parts)

    client_random = os.urandom(32)
    session_id = os.urandom(32)
    order = _permutation(spec.NUM_EXT_SLOTS) if permute_extensions else list(range(spec.NUM_EXT_SLOTS))
    handshake, record = _assemble(host, bodies, grease, client_random, session_id, order,
                                  grease_parts, include_grease)

    return ClientHello(
        record=record,
        handshake=handshake,
        host=host,
        random=client_random,
        session_id=session_id,
        key_share_private_x25519=materials["x25519_priv"] or materials["key_shares"].get(0x001D),
        x25519_public=materials["x25519_pub"],
        mlkem_ek=materials["mlkem_ek"],
        mlkem_dk=materials["mlkem_dk"],
        grease=grease,
        key_shares=materials["key_shares"],
        supported_groups=materials["supported_groups"],
        ext_order=order,
        grease_parts=grease_parts,
        include_grease=include_grease,
    )


def rebuild_for_hrr(ch: ClientHello, group: int, cookie: bytes | None = None) -> ClientHello:
    """HelloRetryRequest 之后的第二个 ClientHello (RFC 8446 §4.1.4)。

    除以下三点外必须与第一个逐字节相同:
      * key_share 只保留服务器点名的那个组
      * 服务器给了 cookie 就补上 cookie 扩展
      * 不允许再带 early_data(本库本来就没有)
    所以这里直接复用 CH1 的 random / session_id / GREASE 取值 / 扩展置换顺序。
    """
    grease = dict(ch.grease)
    materials: dict = {}
    bodies = _extension_bodies(ch.host, grease, materials,
                               grease_parts=ch.grease_parts,
                               supported_groups=list(ch.supported_groups),
                               key_share_groups=[group],
                               cookie=cookie,
                               grease_key_share=False)
    handshake, record = _assemble(ch.host, bodies, grease, ch.random, ch.session_id,
                                  ch.ext_order, ch.grease_parts, ch.include_grease)
    return ClientHello(
        record=record,
        handshake=handshake,
        host=ch.host,
        random=ch.random,
        session_id=ch.session_id,
        key_share_private_x25519=materials["x25519_priv"] or materials["key_shares"].get(0x001D),
        x25519_public=materials["x25519_pub"],
        mlkem_ek=materials["mlkem_ek"],
        mlkem_dk=materials["mlkem_dk"],
        grease=grease,
        key_shares=materials["key_shares"],
        supported_groups=materials["supported_groups"],
        ext_order=ch.ext_order,
        grease_parts=ch.grease_parts,
        include_grease=ch.include_grease,
        is_hrr_retry=True,
    )
