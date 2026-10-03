#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tap_probe —— 本机 TLS/H2 探针: 抓真 Chrome 的 ClientHello 原字节 + HTTP/2 帧/请求头。

原理: Chrome 通过 `--host-resolver-rules=MAP <host> 127.0.0.1` 连到本探针, 探针自己
终止 TLS(自签证书, 用 --ignore-certificate-errors-spki-list 让 Chrome 放行), 因此
ClientHello 的原始字节与解密后的 HTTP/2 明文都在我们手里, 不需要 Wireshark。

每个端口 = 一个独立 origin(端口不同不会被 h2 连接合并), 所以一次启动就能拿到多条
互相独立的 ClientHello。

用法:
    python tools/tap_probe.py --ports 8443-8462 --out capture/chrome154 --wait 40
然后另开一个终端 / 子进程启动 Chrome:
    python tools/launch_chrome.py --probe-port 8443 --count 20
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_NAMES = {
    0x0: "DATA", 0x1: "HEADERS", 0x2: "PRIORITY", 0x3: "RST_STREAM",
    0x4: "SETTINGS", 0x5: "PUSH_PROMISE", 0x6: "PING", 0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE", 0x9: "CONTINUATION",
}
SETTINGS_NAMES = {
    0x1: "HEADER_TABLE_SIZE", 0x2: "ENABLE_PUSH", 0x3: "MAX_CONCURRENT_STREAMS",
    0x4: "INITIAL_WINDOW_SIZE", 0x5: "MAX_FRAME_SIZE", 0x6: "MAX_HEADER_LIST_SIZE",
    0x8: "ENABLE_CONNECT_PROTOCOL", 0x9: "NO_RFC7540_PRIORITIES",
}

# 1x1 透明 PNG
PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000a49444154789c6360000002000100ffff03000006000557bfabd400"
    "00000049454e44ae426082"
)


# --------------------------------------------------------------------- 自签证书
def ensure_cert(cert_dir: Path, host: str = "probe.test"):
    """生成/复用自签证书, 返回 (cert_pem, key_pem, spki_sha256_b64)。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cert_dir.mkdir(parents=True, exist_ok=True)
    key_file, cert_file = cert_dir / "probe.key", cert_dir / "probe.crt"

    if not (key_file.exists() and cert_file.exists()):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(host),
                    x509.DNSName(f"*.{host}"),
                ]), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_file.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    import base64
    import hashlib
    spki_b64 = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    return cert_file, key_file, spki_b64


# --------------------------------------------------------------------- BIO 收发
class TlsChannel:
    """手工驱动 MemoryBIO, 这样握手期间的原始字节能逐字节留档。"""

    def __init__(self, conn: socket.socket, ctx: ssl.SSLContext, record_raw: bool = True):
        self.conn = conn
        self.inbio = ssl.MemoryBIO()
        self.outbio = ssl.MemoryBIO()
        self.sslobj = ctx.wrap_bio(self.inbio, self.outbio, server_side=True)
        self.raw = bytearray()
        self.record_raw = record_raw
        self.plain = bytearray()      # 解密后的应用层字节
        self._pending = bytearray()

    def handshake(self) -> None:
        while True:
            try:
                self.sslobj.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                if not self._pump():
                    raise ConnectionError("peer closed during handshake")

    def _flush(self) -> None:
        out = self.outbio.read()
        if out:
            self.conn.sendall(out)

    def _pump(self) -> bool:
        data = self.conn.recv(65536)
        if not data:
            return False
        if self.record_raw:
            self.raw.extend(data)
        self.inbio.write(data)
        return True

    def read(self, n: int = 65536) -> bytes:
        """返回解密后的应用层数据(内部已处理 record 边界)。"""
        while not self._pending:
            try:
                chunk = self.sslobj.read(n)
                if chunk:
                    self.plain.extend(chunk)
                    return chunk
                raise ConnectionError("eof")
            except ssl.SSLWantReadError:
                self._flush()
                if not self._pump():
                    raise ConnectionError("eof")
        return bytes(self._pending)

    def read_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.read(n - len(buf))
            buf.extend(chunk)
        return bytes(buf)

    def write(self, data: bytes) -> None:
        self.sslobj.write(data)
        self._flush()

    def close(self) -> None:
        try:
            self.sslobj.unwrap()
            self._flush()
        except Exception:
            pass


# --------------------------------------------------------------------- HTTP/2
@dataclass
class H2Record:
    frames: list = field(default_factory=list)
    headers: list = field(default_factory=list)


def parse_settings(payload: bytes) -> list:
    out = []
    for i in range(0, len(payload) - 5, 6):
        ident, value = struct.unpack("!HI", payload[i:i + 6])
        out.append({"id": ident, "name": SETTINGS_NAMES.get(ident, hex(ident)), "value": value})
    return out


def read_h2(chan: TlsChannel, rec: H2Record, serve, hpack_dec, hpack_enc,
            max_frames: int = 60) -> None:
    """serve(path) -> (status, content_type, body)"""
    """读 preface + 帧; 收到 HEADERS 就按 serve() 回一个最简响应。"""
    pre = chan.read_exact(24)
    if pre != H2_PREFACE:
        raise ValueError(f"bad h2 preface: {pre!r}")

    # 服务器 SETTINGS(我们这边不需要调参, 发空表即可)
    chan.write(struct.pack("!I", 0)[1:] + bytes([0x4, 0x0]) + b"\x00\x00\x00\x00")

    got = 0
    while got < max_frames:
        hdr = chan.read_exact(9)
        length = int.from_bytes(hdr[0:3], "big")
        ftype, flags = hdr[3], hdr[4]
        stream = int.from_bytes(hdr[5:9], "big") & 0x7FFFFFFF
        payload = chan.read_exact(length) if length else b""
        entry = {
            "type": ftype, "name": FRAME_NAMES.get(ftype, hex(ftype)),
            "flags": flags, "stream": stream, "length": length,
        }
        if ftype == 0x4 and not (flags & 0x1):          # SETTINGS
            entry["settings"] = parse_settings(payload)
        elif ftype == 0x8:                               # WINDOW_UPDATE
            entry["increment"] = int.from_bytes(payload, "big") & 0x7FFFFFFF
        elif ftype == 0x2:                               # PRIORITY
            entry["priority"] = {
                "depends_on": int.from_bytes(payload[0:4], "big"),
                "weight": payload[4] + 1,
            }
        elif ftype == 0x1:                               # HEADERS
            block = payload
            pad = 0
            if flags & 0x8:                              # PADDED
                pad = block[0]
                block = block[1:]
            if flags & 0x20:                             # PRIORITY
                entry["priority_prefix"] = {
                    "depends_on": int.from_bytes(block[0:4], "big"),
                    "weight": block[4] + 1,
                    "exclusive": bool(block[0] & 0x80),
                }
                block = block[5:]
            if pad:
                block = block[:-pad]
            try:
                decoded = hpack_dec.decode(block, raw=True)
                entry["headers_raw"] = [[k.decode("latin1"), v.decode("latin1")]
                                        for k, v in decoded]
            except Exception as exc:                     # noqa: BLE001
                entry["decode_error"] = repr(exc)
            rec.headers.append(entry.get("headers_raw", []))

        if ftype == 0x4 and not (flags & 0x1):           # 回 SETTINGS ACK
            chan.write(bytes([0, 0, 0, 0x4, 0x1]) + b"\x00\x00\x00\x00")
        if ftype == 0x1:                                 # 回响应
            path = ""
            try:
                path = dict(entry.get("headers_raw", [])).get(":path", "")
            except Exception:                            # noqa: BLE001
                pass
            status, ctype, body = serve(path)
            resp = hpack_enc.encode([
                (":status", str(status)), ("content-type", ctype),
                ("content-length", str(len(body))),
                ("server", "tap-probe"),
            ])
            chan.write(len(resp).to_bytes(3, "big") + bytes([0x1, 0x4])
                       + stream.to_bytes(4, "big") + resp)
            if body:
                chan.write(len(body).to_bytes(3, "big") + bytes([0x0, 0x1])
                           + stream.to_bytes(4, "big") + body)
            else:
                chan.write(b"\x00\x00\x00" + bytes([0x0, 0x1])
                           + stream.to_bytes(4, "big"))
        if ftype == 0x6 and not (flags & 0x1):           # PING -> PONG
            chan.write(len(payload).to_bytes(3, "big") + bytes([0x6, 0x1])
                       + b"\x00\x00\x00\x00" + payload)

        rec.frames.append(entry)
        got += 1
        if ftype == 0x7:                                 # GOAWAY
            return


# --------------------------------------------------------------------- 单连接
def handle(conn: socket.socket, ctx: ssl.SSLContext, out_dir: Path, idx: int,
           page_ports: list[int], timeout: float) -> dict:
    import hpack

    info: dict = {"index": idx, "peer": conn.getpeername(), "t": time.time()}
    conn.settimeout(timeout)
    chan = TlsChannel(conn, ctx)
    try:
        chan.handshake()
    except Exception as exc:                             # noqa: BLE001
        info["error"] = f"handshake: {exc!r}"
        (out_dir / "hellos").mkdir(parents=True, exist_ok=True)
        (out_dir / "hellos" / f"hello-{idx:03d}.bin").write_bytes(bytes(chan.raw))
        conn.close()
        return info

    info["alpn"] = chan.sslobj.selected_alpn_protocol()
    info["tls_version"] = chan.sslobj.version()
    info["cipher"] = chan.sslobj.cipher()
    (out_dir / "hellos").mkdir(parents=True, exist_ok=True)
    (out_dir / "hellos" / f"hello-{idx:03d}.bin").write_bytes(bytes(chan.raw))

    def serve(path: str):
        if path in ("/", "/index.html", ""):
            imgs = "".join(
                f'<img src="https://probe.test:{p}/p.png" width="1" height="1">'
                for p in page_ports)
            html = (f"<!doctype html><html><head><title>probe</title></head>"
                    f"<body>probe{imgs}</body></html>").encode()
            return 200, "text/html; charset=utf-8", html
        return 200, "image/png", PNG_1PX

    try:
        if info["alpn"] == "h2":
            rec = H2Record()
            # 先用同一个 list 对象挂到 info 上: 万一中途 EOF/超时, 已经收到的帧也要留存
            info["h2_frames"] = rec.frames
            info["h2_headers"] = rec.headers
            read_h2(chan, rec, serve=serve, hpack_dec=hpack.Decoder(), hpack_enc=hpack.Encoder())
        else:
            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) < 65536:
                data.extend(chan.read())
            info["h1_request"] = bytes(data).decode("latin1", "replace")
            body = b"ok"
            chan.write(b"HTTP/1.1 200 OK\r\ncontent-length: %d\r\n"
                       b"content-type: text/plain\r\nconnection: close\r\n\r\n%s"
                       % (len(body), body))
    except Exception as exc:                             # noqa: BLE001
        info["error"] = f"app: {exc!r}"
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()
        info["raw_len"] = len(chan.raw)
    return info


# --------------------------------------------------------------------- main
def parse_ports(spec: str) -> list[int]:
    if "-" in spec:
        a, b = spec.split("-", 1)
        return list(range(int(a), int(b) + 1))
    return [int(x) for x in spec.split(",")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", default="8443-8462", help="监听端口, 如 8443-8462")
    ap.add_argument("--out", default="capture/chrome154")
    ap.add_argument("--host", default="probe.test")
    ap.add_argument("--wait", type=float, default=45.0, help="总等待秒数")
    ap.add_argument("--idle", type=float, default=6.0, help="最后一条连接后多久收工")
    ap.add_argument("--timeout", type=float, default=6.0, help="单连接 socket 超时")
    args = ap.parse_args()

    out_dir = (ROOT / args.out) if not Path(args.out).is_absolute() else Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_file, key_file, spki_b64 = ensure_cert(out_dir / "certs", args.host)
    (out_dir / "spki.txt").write_text(spki_b64)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_file), str(key_file))
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ports = parse_ports(args.ports)
    listeners = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", p))
        s.listen(16)
        s.settimeout(0.5)
        listeners.append((p, s))

    print(f"[probe] listening on {ports[0]}..{ports[-1]}  ({len(ports)} ports)", flush=True)
    print(f"[probe] SPKI sha256 = {spki_b64}", flush=True)
    print(f"[probe] out = {out_dir}", flush=True)

    results: list[dict] = []
    lock = threading.Lock()
    counter = {"n": 0}
    last = {"t": time.time()}
    deadline = time.time() + args.wait
    threads: list[threading.Thread] = []

    def run_one(conn: socket.socket, idx: int) -> None:
        try:
            r = handle(conn, ctx, out_dir, idx, ports[1:], args.timeout)
        except Exception as exc:                         # noqa: BLE001
            r = {"index": idx, "error": f"thread: {exc!r}"}
        with lock:
            results.append(r)
            last["t"] = time.time()

    try:
        import select as _select
        socks = [s for _p, s in listeners]
        while time.time() < deadline:
            if results and (time.time() - last["t"]) > args.idle:
                break
            # 必须用 select 等: 逐个 accept 会串行阻塞, 20 个端口最坏要 10s 才轮到,
            # Chrome 等不到 ServerHello 会直接 abort 掉这条连接。
            ready, _, _ = _select.select(socks, [], [], 0.3)
            for s in ready:
                try:
                    conn, _addr = s.accept()
                except (BlockingIOError, socket.timeout, TimeoutError):
                    continue
                with lock:
                    counter["n"] += 1
                    idx = counter["n"]
                last["t"] = time.time()
                t = threading.Thread(target=run_one, args=(conn, idx), daemon=True)
                t.start()
                threads.append(t)
    finally:
        for _p, s in listeners:
            s.close()
        for t in threads:
            # 必须等所有连接线程收尾, 否则慢的那几条不会写进 probe.json
            t.join(timeout=max(8.0, args.timeout + 3))

    results.sort(key=lambda r: r["index"])
    (out_dir / "probe.json").write_text(json.dumps({
        "host": args.host,
        "ports": ports,
        "spki_sha256_b64": spki_b64,
        "connections": results,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    n_hello = len(list((out_dir / "hellos").glob("*.bin")))
    n_h2 = sum(1 for r in results if r.get("alpn") == "h2")
    print(f"[probe] connections={len(results)}  hellos={n_hello}  h2={n_h2}")
    for r in results[:40]:
        err = f"  error={r['error']}" if r.get("error") else ""
        print(f"  #{r['index']:03d} alpn={r.get('alpn')} version={r.get('tls_version')} "
              f"cipher={r.get('cipher', ('',))[0] if r.get('cipher') else None} "
              f"frames={len(r.get('h2_frames', []))}{err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
