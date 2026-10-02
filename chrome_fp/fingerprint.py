"""ClientHello 解析 + JA3 / JA4 计算 (用于自检: 生成的握手是否与真 Chrome 一致)"""

from __future__ import annotations

import struct
from hashlib import md5, sha256

GREASE = {0x0A0A + 0x1010 * i for i in range(16)}

EXT_NAME = {
    0x0000: "server_name", 0x0005: "status_request", 0x000A: "supported_groups",
    0x000B: "ec_point_formats", 0x000D: "signature_algorithms", 0x0010: "alpn",
    0x0012: "signed_certificate_timestamp", 0x0015: "padding", 0x0017: "extended_master_secret",
    0x001B: "compress_certificate", 0x001C: "record_size_limit", 0x0023: "session_ticket",
    0x002B: "supported_versions", 0x002D: "psk_key_exchange_modes", 0x0033: "key_share",
    0x44CD: "application_settings(ALPS)", 0x4469: "application_settings(old)",
    0xCA34: "trust_anchors", 0xFE0D: "encrypted_client_hello(GREASE)", 0xFF01: "renegotiation_info",
}

GROUP_NAME = {
    0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001E: "x448", 0x11EC: "X25519MLKEM768", 0x6399: "X25519Kyber768Draft00",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
}


def _u16(b: bytes, p: int) -> int:
    return struct.unpack(">H", b[p:p + 2])[0]


def parse_client_hello(record: bytes) -> dict:
    """解析 record 层字节, 返回结构化信息"""
    body = record[5:]
    p = 4
    out: dict = {
        "record_len": len(record),
        "legacy_version": body[p:p + 2].hex(),
    }
    p += 2
    out["random"] = body[p:p + 32].hex()
    p += 32
    sid_len = body[p]
    out["session_id"] = body[p + 1:p + 1 + sid_len].hex()
    p += 1 + sid_len
    cs_len = _u16(body, p)
    p += 2
    ciphers = [body[p + i:p + i + 2].hex() for i in range(0, cs_len, 2)]
    out["ciphers"] = ciphers
    p += cs_len
    comp_len = body[p]
    out["compressions"] = body[p + 1:p + 1 + comp_len].hex()
    p += 1 + comp_len
    ext_total = _u16(body, p)
    p += 2
    end = p + ext_total
    exts: list[tuple[int, bytes]] = []
    while p + 4 <= end:
        et = _u16(body, p)
        el = _u16(body, p + 2)
        exts.append((et, body[p + 4:p + 4 + el]))
        p += 4 + el
    out["extensions"] = exts
    out["ext_types"] = [et for et, _ in exts]
    out["ext_names"] = [
        f"0x{et:04x}" + ("(GREASE)" if et in GREASE else f"({EXT_NAME.get(et, '?')})")
        for et, _ in exts
    ]
    out["handshake_len"] = int.from_bytes(body[1:4], "big")

    d = dict(exts)
    if 0x000A in d:
        n = _u16(d[0x000A], 0)
        out["supported_groups"] = [
            GROUP_NAME.get(_u16(d[0x000A], 2 + i), f"0x{_u16(d[0x000A], 2 + i):04x}")
            for i in range(0, n, 2)
        ]
    if 0x000D in d:
        n = _u16(d[0x000D], 0)
        out["signature_algorithms"] = [f"0x{_u16(d[0x000D], 2 + i):04x}" for i in range(0, n, 2)]
    if 0x002B in d:
        n = d[0x002B][0]
        out["supported_versions"] = [f"0x{_u16(d[0x002B], 1 + i):04x}" for i in range(0, n, 2)]
    if 0x0033 in d:
        b = d[0x0033]
        total = _u16(b, 0)
        ks, q = [], 2
        while q < 2 + total:
            g = _u16(b, q)
            kl = _u16(b, q + 2)
            ks.append({"group": GROUP_NAME.get(g, f"0x{g:04x}"), "len": kl})
            q += 4 + kl
        out["key_shares"] = ks
    if 0x0000 in d:
        b = d[0x0000]
        name_len = _u16(b, 3)          # [0:2]=list len, [2]=type, [3:5]=name len, [5:]=name
        out["sni"] = b[5:5 + name_len].decode("ascii", "replace")
    if 0x0010 in d:
        b = d[0x0010]
        n = _u16(b, 0)
        protos, i = [], 2
        while i < 2 + n:
            ln = b[i]
            protos.append(b[i + 1:i + 1 + ln].decode())
            i += 1 + ln
        out["alpn"] = protos
    if 0xFE0D in d:
        out["ech_len"] = len(d[0xFE0D])
        out["ech_config_id"] = d[0xFE0D][5]
    if 0xCA34 in d:
        b = d[0xCA34]
        inner = b[2:]
        ids, i = [], 0
        while i < len(inner):
            ln = inner[i]
            ids.append(inner[i + 1:i + 1 + ln].hex())
            i += 1 + ln
        out["trust_anchor_count"] = len(ids)
        out["trust_anchor_set"] = sorted(ids)
    if 0x001B in d:
        out["compress_certificate"] = d[0x001B].hex()
    if 0x44CD in d:
        out["alps"] = d[0x44CD].hex()
    if 0x0005 in d:
        out["status_request"] = d[0x0005].hex()
    return out


def ja3_from_hello(record: bytes) -> tuple[str, str]:
    info = parse_client_hello(record)
    ciphers_d = parse_client_hello(record)["ciphers"]
    ciphers = ",".join(c for c in ciphers_d if int(c, 16) not in GREASE)
    exts = ",".join(str(e) for e in info["ext_types"] if e not in GREASE)
    d = dict(info["extensions"])
    curves = ""
    if 0x000A in d:
        n = _u16(d[0x000A], 0)
        curves = ",".join(
            str(_u16(d[0x000A], 2 + i)) for i in range(0, n, 2)
            if _u16(d[0x000A], 2 + i) not in GREASE
        )
    fmt = ""
    if 0x000B in d:
        b = d[0x000B]
        fmt = ",".join(str(x) for x in b[1:1 + b[0]])
    s = f"{ciphers},{exts},{curves},{fmt}"
    return s, md5(s.encode()).hexdigest()


def ja4_from_hello(record: bytes) -> str:
    """JA4 — 按 FoxIO 官方实现 (python/ja4.py to_ja4):
    扩展列表带 0x 前缀、升序; 签名算法按出现顺序、不带前缀; 二者用 "_" 连接; GREASE 全部剔除。
    """
    info = parse_client_hello(record)
    d = dict(info["extensions"])
    ciphers = sorted(c for c in info["ciphers"] if int(c, 16) not in GREASE)
    exts = sorted(f"0x{e:04x}" for e in info["ext_types"] if e not in GREASE)
    sigalgs: list[str] = []
    if 0x000D in d:
        n = _u16(d[0x000D], 0)
        sigalgs = [
            f"{_u16(d[0x000D], 2 + i):04x}"
            for i in range(0, n, 2)
            if _u16(d[0x000D], 2 + i) not in GREASE
        ]
    alpn = ""
    if 0x0010 in d:
        b = d[0x0010]
        n = _u16(b, 0)
        if n >= 2:
            ln = b[2]
            alpn = b[3:3 + ln].decode("ascii", "replace")

    def h12(s: str) -> str:
        return sha256(s.encode()).hexdigest()[:12]

    a = "t" + "13" + ("d" if 0x0000 in d else "i") + f"{len(ciphers):02d}" + f"{len(exts):02d}" + (alpn or "00")
    b = h12(",".join(ciphers))
    ext_str = ",".join(exts)
    if sigalgs:
        ext_str += "_" + ",".join(sigalgs)
    c = h12(ext_str)
    return f"{a}_{b}_{c}"


def describe(record: bytes) -> str:
    info = parse_client_hello(record)
    _, j3 = ja3_from_hello(record)
    lines = [
        f"record_len={info['record_len']} handshake_len={info['handshake_len']}",
        f"ciphers({len(info['ciphers'])}): {info['ciphers']}",
        f"extensions({len(info['ext_types'])}): {info['ext_names']}",
        f"groups: {info.get('supported_groups')}",
        f"versions: {info.get('supported_versions')}",
        f"key_shares: {info.get('key_shares')}",
        f"sni: {info.get('sni')} alpn: {info.get('alpn')}",
        f"ja3={j3}",
        f"ja4={ja4_from_hello(record)}",
    ]
    return "\n".join(lines)
