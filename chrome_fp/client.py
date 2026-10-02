"""连接分派: 发同一个 Chrome ClientHello, 读第一条 ServerHello, 自动走 TLS 1.3 或回落到 TLS 1.2。

真 Chrome 遇到只支持 1.2 的服务器也是用同一个 ClientHello 回落的(我们发的 ClientHello 里
supported_versions 已含 0x0303、密码套件里也有 TLS1.2 套件), 所以**指纹完全不变**。
"""

from __future__ import annotations

import socket
import struct
import sys

from . import tls12, tls13
from .hello import ClientHello


def parse_server_hello_exts(msg: bytes) -> tuple[dict[int, bytes], int]:
    """返回 (扩展字典, 套件号)"""
    body = msg[4:]
    p = 2 + 32
    sid_len = body[p]
    p += 1 + sid_len
    suite = struct.unpack(">H", body[p:p + 2])[0]
    p += 2
    comp_len = body[p]
    p += 1 + comp_len
    exts: dict[int, bytes] = {}
    if p + 2 <= len(body):
        ext_total = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        end = min(p + ext_total, len(body))
        while p + 4 <= end:
            et, el = struct.unpack(">HH", body[p:p + 4])
            exts[et] = body[p + 4:p + 4 + el]
            p += 4 + el
    return exts, suite


def is_tls13(msg: bytes) -> bool:
    exts, _ = parse_server_hello_exts(msg)
    return exts.get(0x002B, b"")[:2] == b"\x03\x04"


def open_connection(
    sock: socket.socket,
    client_hello: ClientHello,
    *,
    verify_certs: bool = True,
    ca_file: str | None = None,
    timeout: float | None = 30.0,
    allow_tls12: bool = True,
    debug: bool = False,
    keylog_file: str | None = None,
    client_cert=None,
):
    """发 ClientHello 并完成握手; 返回 TLS13Connection 或 TLS12Connection(接口一致)"""
    if timeout is not None:
        sock.settimeout(timeout)
    sock.sendall(client_hello.record)
    # 注: RFC 8446 D.4 的"CH 后立刻发 dummy CCS"实测会把只支持 TLS 1.2 的服务器搞坏
    # (它们会把这个 CCS 当成密钥切换), 所以只在确认是 TLS 1.3 之后才发 —— 见 tls13.py
    # 里发送 client Finished 之前那一条。

    # ---- 预读第一条握手消息(用于判断版本) ----
    raw = b""
    hs_buf = b""
    first: bytes | None = None
    while first is None:
        while len(raw) < 5:
            chunk = sock.recv(65536)
            if not chunk:
                raise tls13.TLSException("连接被对端关闭")
            raw += chunk
        ctype = raw[0]
        length = struct.unpack(">H", raw[3:5])[0]
        while len(raw) < 5 + length:
            chunk = sock.recv(65536)
            if not chunk:
                raise tls13.TLSException("连接被对端关闭")
            raw += chunk
        payload = raw[5:5 + length]
        raw = raw[5 + length:]
        if ctype == tls13.CT_CHANGE_CIPHER_SPEC:
            continue
        if ctype == tls13.CT_ALERT:
            raise tls13.TLSException(f"收到 alert: {tls13.alert_text(payload)}")
        hs_buf += payload
        if len(hs_buf) >= 4:
            msglen = int.from_bytes(hs_buf[1:4], "big")
            if len(hs_buf) >= 4 + msglen:
                first = hs_buf[:4 + msglen]
                hs_buf = hs_buf[4 + msglen:]

    if first[0] != tls13.HS_SERVER_HELLO:
        raise tls13.TLSException(f"期待 ServerHello, 收到消息类型 {first[0]}")

    tls13_ok = is_tls13(first)
    if debug:
        print(f"[client] ServerHello -> {'TLS1.3' if tls13_ok else 'TLS1.2'}", file=sys.stderr)

    if tls13_ok:
        conn = tls13.TLS13Connection(
            sock, client_hello, verify_certs=verify_certs, ca_file=ca_file, timeout=timeout,
            ch_sent=True, server_hello_msg=first, hs_buf=hs_buf, preload_buf=raw,
            keylog_file=keylog_file, client_cert=client_cert,
        )
    else:
        if not allow_tls12:
            raise tls13.TLSException("服务器只支持 TLS 1.2, 而 allow_tls12=False")
        conn = tls12.TLS12Connection(
            sock, client_hello, server_hello_msg=first, hs_buf=hs_buf, preload_buf=raw,
            verify_certs=verify_certs, ca_file=ca_file, timeout=timeout,
            keylog_file=keylog_file, client_cert=client_cert,
        )
    alpn = conn.do_handshake()
    conn.tls_version = "1.3" if tls13_ok else "1.2"
    return conn
