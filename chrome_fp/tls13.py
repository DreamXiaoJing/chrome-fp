"""纯 Python TLS 1.3 客户端 —— 配合 hello.py 生成的 Chrome ClientHello 完成握手。

为什么不用 ssl 模块: CPython 的 ssl 不允许自定义 ClientHello 字节(扩展顺序/GREASE/ALPS/PQ keyshare),
所以这里自己实现 record 层 + 密钥调度, 只借用 cryptography 的密码原语。

支持:
  - TLS 1.3: AES-128-GCM-SHA256 / AES-256-GCM-SHA384 / CHACHA20-POLY1305-SHA256
  - X25519MLKEM768 (0x11ec) 混合密钥共享 + x25519 回退
  - 证书压缩 (brotli) —— 因为 Chrome 会广告 compress_certificate
  - CertificateVerify 签名校验 + 证书链校验(可关)
  - post-handshake NewSessionTicket / KeyUpdate 的容忍处理
"""

from __future__ import annotations

import hmac
import os
import socket
import struct
import sys
import time
from hashlib import sha256, sha384

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from . import mlkem, spec
from .clientcert import (
    ClientCertError,
    build_certificate_13,
    build_certificate_verify_13,
    certificate_verify_content_13,
    pick_signature_algorithm,
    sign_data,
)
from .hello import ClientHello, EC_GROUPS, rebuild_for_hrr

CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_ENCRYPTED_EXTENSIONS = 8
HS_SERVER_KEY_EXCHANGE = 12
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_HELLO_DONE = 14
HS_CERTIFICATE_STATUS = 22
HS_CERTIFICATE = 11
HS_CERTIFICATE_VERIFY = 15
HS_CLIENT_KEY_EXCHANGE = 16
HS_FINISHED = 20
HS_KEY_UPDATE = 24
HS_COMPRESSED_CERTIFICATE = 25

HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

# TLS alert description(RFC 8446 §6) —— 报错时给出名字比一串十六进制有用得多
ALERT_NAMES = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error", 60: "export_restriction",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol",
}


def alert_text(payload: bytes) -> str:
    """把 alert 记录内容翻成人看得懂的名字"""
    if len(payload) >= 2:
        level, desc = payload[0], payload[1]
        lvl = {1: "warning", 2: "fatal"}.get(level, f"level{level}")
        return f"{lvl} {ALERT_NAMES.get(desc, hex(desc))}({desc})"
    return payload.hex()

CIPHER_SUITES = {
    0x1301: ("sha256", 16, "aes128"),
    0x1302: ("sha384", 32, "aes256"),
    0x1303: ("sha256", 32, "chacha20"),
}

# 签名算法: code -> (hash, 类型)
SIG_ALGS = {
    0x0403: ("sha256", "ecdsa"),
    0x0503: ("sha384", "ecdsa"),
    0x0603: ("sha512", "ecdsa"),
    0x0401: ("sha256", "rsa_pkcs1"),
    0x0501: ("sha384", "rsa_pkcs1"),
    0x0601: ("sha512", "rsa_pkcs1"),
    0x0804: ("sha256", "rsa_pss"),
    0x0805: ("sha384", "rsa_pss"),
    0x0806: ("sha512", "rsa_pss"),
    0x0807: ("sha256", "ed25519"),
    0x0808: ("sha384", "ed448"),
    0x0809: ("sha512", "rsa_pss_pss"),
    0x080A: ("sha384", "rsa_pss_pss"),
    0x080B: ("sha512", "rsa_pss_pss"),
    0x0904: ("sha256", "ecdsa"),
    0x0905: ("sha384", "ecdsa"),
    0x0906: ("sha512", "ecdsa"),
}

HASHES = {"sha1": __import__("hashlib").sha1, "sha256": sha256, "sha384": sha384,
          "sha512": __import__("hashlib").sha512}
# cryptography 侧的 HashAlgorithm 工厂(与 hashlib 区分: HKDF/签名需要前者)
CRYPTO_HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384,
                 "sha512": hashes.SHA512}


class TLSException(Exception):
    pass


def _dnsname_matches(host: str, pattern: str) -> bool:
    """证书主机名匹配(支持 *.example.com 单层通配, 大小写不敏感)"""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return host == pattern


def verify_server_chain(chain: list, host: str | None, ca_file: str | None = None,
                        context: str = "server") -> None:
    """浏览器语义的证书链校验(BoringSSL/webpki 风格)。

    关键点(踩过的坑):
    - 服务器常发**交叉签名根**(如 Google GTS Root R4 由 GlobalSign 签、DigiCert G2 由 GlobalSign 签),
      所以不能用"名字字符串相等"找信任锚 —— 必须逐级建路(BFS)找到落在本地信任库里的锚。
    - 名称匹配要在 DER 层比较(subject.public_bytes() vs issuer.public_bytes()), 字符串表示会因属性顺序/编码差异误判。
    - EKU: 有则必须含 serverAuth; **没有则放行**(RFC 5280 / Chrome 行为)。
    - 优先选择全部在有效期内的路径(交叉签名根可能已过期, 但另一条路径有效)。
    """
    import os as _os
    import warnings as _warnings
    from datetime import datetime as _dt, timezone as _tz
    from hashlib import sha256 as _sha256

    if ca_file is None:
        try:
            import certifi

            ca_file = certifi.where()
        except ImportError:
            ca_file = _os.environ.get("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
    with open(ca_file, "rb") as f:
        # 系统 CA 信任库里常含序列号非正数的旧证书(新版 cryptography 会发弃用警告)
        with _warnings.catch_warnings():
            _warnings.filterwarnings("ignore", message="Parsed a serial number")
            roots = x509.load_pem_x509_certificates(f.read())

    if not chain:
        raise TLSException("服务器未提供证书")
    if len(chain) > 12:
        raise TLSException("证书链过长")

    def fp(cert) -> bytes:
        return _sha256(cert.public_bytes(serialization.Encoding.DER)).digest()

    store_fps = {fp(r): r for r in roots}
    now = _dt.now(_tz.utc)

    def in_validity(cert) -> bool:
        try:
            return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        except AttributeError:
            naive = now.replace(tzinfo=None)
            return cert.not_valid_before <= naive <= cert.not_valid_after

    def issuers_of(cert, pool):
        out = []
        issuer_bytes = cert.issuer.public_bytes()
        for cand in pool:
            if cand.subject.public_bytes() == issuer_bytes:
                try:
                    cert.verify_directly_issued_by(cand)
                    out.append(cand)
                except Exception:  # noqa: BLE001
                    continue
        return out

    leaf = chain[0]
    intermediates = list(chain[1:])
    pool = intermediates + roots

    # BFS 建路: 从叶证书往上, 直到走到"在信任库里的证书"
    paths: list[list] = [[leaf]]
    good_path: list | None = None
    best_effort: list | None = None
    for _ in range(6):
        next_paths: list[list] = []
        for path in paths:
            last = path[-1]
            for issuer in issuers_of(last, pool):
                new_path = path + [issuer]
                if fp(issuer) in store_fps:            # 到达信任锚
                    if all(in_validity(c) for c in new_path):
                        good_path = new_path
                        break
                    if best_effort is None:
                        best_effort = new_path
                elif fp(issuer) not in {fp(c) for c in path}:
                    next_paths.append(new_path)
            if good_path:
                break
        if good_path:
            break
        paths = [p for p in next_paths if len(p) <= 8]
        if not paths:
            break

    if good_path is None:
        if best_effort is not None:
            bad = [c.subject.rfc4514_string() for c in best_effort if not in_validity(c)]
            raise TLSException(f"证书链上的证书不在有效期内: {bad}")
        raise TLSException("证书链无法追溯到受信任根")
    full = good_path

    for i, cert in enumerate(full):
        if i > 0:
            try:
                bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                if not bc.ca:
                    raise TLSException("中间证书不是 CA")
            except x509.ExtensionNotFound:
                raise TLSException("签发者缺少基本约束(CA)扩展")
            try:
                ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                if not ku.key_cert_sign:
                    raise TLSException("签发者 KeyUsage 不允许签证书")
            except x509.ExtensionNotFound:
                pass

    # EKU: 有则必须允许 serverAuth
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        allowed = {x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                   x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE}
        if not (set(eku) & allowed):
            raise TLSException("证书 EKU 不允许 serverAuth")
    except x509.ExtensionNotFound:
        pass

    # 主机名
    if host:
        import ipaddress

        names: list[str] = []
        ip_addrs: list[str] = []
        try:
            san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = san.get_values_for_type(x509.DNSName)
            ip_addrs = [str(x) for x in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            cn = leaf.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            names = [cn[0].value] if cn else []
        try:
            ip = str(ipaddress.ip_address(host))
            if ip in ip_addrs:
                return
            if not any(_dnsname_matches(host, n) for n in names) and names:
                raise TLSException(f"证书 IP/主机名不匹配: {host} not in {names + ip_addrs}")
        except ValueError:
            if not any(_dnsname_matches(host, n) for n in names):
                raise TLSException(f"证书主机名不匹配: {host} not in {names + ip_addrs}")


def _hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int, hash_name: str) -> bytes:
    full_label = b"tls13 " + label.encode()
    info = (
        struct.pack(">H", length)
        + struct.pack(">B", len(full_label)) + full_label
        + struct.pack(">B", len(context)) + context
    )
    return HKDFExpand(algorithm=CRYPTO_HASHES[hash_name](), length=length, info=info).derive(secret)


def _derive_secret(secret: bytes, label: str, messages: bytes, hash_name: str) -> bytes:
    h = HASHES[hash_name]()
    h.update(messages)
    return _hkdf_expand_label(secret, label, h.digest(), len(h.digest()), hash_name)


def _hkdf_extract(salt: bytes, ikm: bytes, hash_name: str) -> bytes:
    """HKDF-Extract = HMAC(salt, ikm) —— 注意不能用 cryptography 的 HKDF(它 extract 后还会 expand)"""
    if not salt:
        salt = b"\x00" * HASHES[hash_name]().digest_size
    return hmac.new(salt, ikm, HASHES[hash_name]).digest()


class _RecordCipher:
    """TLS 1.3 record 保护 (RFC 8446 §5.2/5.3)"""

    def __init__(self, secret: bytes, hash_name: str, key_len: int, aead_name: str):
        self.hash_name = hash_name
        self.key = _hkdf_expand_label(secret, "key", b"", key_len, hash_name)
        self.iv = _hkdf_expand_label(secret, "iv", b"", 12, hash_name)
        self.seq = 0
        if aead_name == "chacha20":
            self.aead = ChaCha20Poly1305(self.key)
        else:
            self.aead = AESGCM(self.key)

    def _nonce(self) -> bytes:
        n = bytearray(self.iv)
        pad = self.seq.to_bytes(8, "big")
        for i in range(8):
            n[4 + i] ^= pad[i]
        return bytes(n)

    def encrypt(self, content_type: int, plaintext: bytes) -> bytes:
        inner = plaintext + bytes([content_type])
        aad = bytes([CT_APPLICATION_DATA, 0x03, 0x03]) + struct.pack(">H", len(inner) + 16)
        ct = self.aead.encrypt(self._nonce(), inner, aad)
        self.seq += 1
        return aad + ct

    def decrypt(self, header: bytes, ciphertext: bytes) -> tuple[int, bytes]:
        pt = self.aead.decrypt(self._nonce(), ciphertext, header)
        self.seq += 1
        return pt[-1], pt[:-1]


class TLS13Connection:
    """在已连接的 socket 上完成 TLS 1.3 握手并提供加解密收发"""

    def __init__(
        self,
        sock: socket.socket,
        client_hello: ClientHello,
        *,
        verify_certs: bool = True,
        ca_file: str | None = None,
        timeout: float | None = 30.0,
        ch_sent: bool = False,
        server_hello_msg: bytes | None = None,
        hs_buf: bytes = b"",
        preload_buf: bytes = b"",
        keylog_file: str | None = None,
        client_cert=None,
    ):
        self.sock = sock
        self.ch = client_hello
        self._ch_sent = ch_sent              # 调用方是否已发出 ClientHello
        self._pre_sh = server_hello_msg      # 调用方已读到的 ServerHello 原始消息
        self._hs_buf = hs_buf
        self.verify_certs = verify_certs
        self.ca_file = ca_file
        self.timeout = timeout
        self.transcript = bytearray()
        self.recv_buf = preload_buf     # 分派器预读后剩下的原始字节, 必须接着用
        self.app_buf = b""
        self.alpn: str | None = None
        self.cipher_suite: int | None = None
        self.peer_certificate_chain: list[x509.Certificate] = []
        self._read_cipher: _RecordCipher | None = None
        self._write_cipher: _RecordCipher | None = None
        self._handshake_done = False
        self.handshake_time = 0.0
        # SSLKEYLOGFILE 兼容: 给了路径就把会话密钥按 NSS key log 格式追加进去,
        # 这样 Wireshark/tshark 能直接解密本库的流量(调试指纹时非常有用)。
        self.keylog_file = keylog_file
        # 客户端证书(mTLS): ClientCertificate 或 None
        self.client_cert = client_cert
        self._cert_request: tuple[bytes, list[int]] | None = None
        self._cert_sent = False

    # ------------------------------------------------------------ keylog

    def _keylog(self, label: str, secret: bytes) -> None:
        if not self.keylog_file:
            return
        try:
            with open(self.keylog_file, "a", encoding="utf-8") as f:
                f.write(f"{label} {self.ch.random.hex()} {secret.hex()}\n")
        except OSError:
            pass

    # ------------------------------------------------------------ 底层 IO

    def _send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def _recv_exact(self, n: int) -> bytes:
        while len(self.recv_buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise TLSException("连接被对端关闭")
            self.recv_buf += chunk
        out, self.recv_buf = self.recv_buf[:n], self.recv_buf[n:]
        return out

    def _read_record(self) -> tuple[int, bytes]:
        header = self._recv_exact(5)
        ctype = header[0]
        length = struct.unpack(">H", header[3:5])[0]
        payload = self._recv_exact(length)
        return ctype, payload

    def _read_handshake_record(self) -> tuple[int, bytes]:
        """读一条握手记录并解密(如已启用加密)。返回 (内容类型, **明文**)"""
        while True:
            ctype, payload = self._read_record()
            if ctype == CT_CHANGE_CIPHER_SPEC:
                continue
            if self._read_cipher is not None:
                if ctype != CT_APPLICATION_DATA:
                    continue
                header = bytes([ctype, 0x03, 0x03]) + struct.pack(">H", len(payload))
                ctype, payload = self._read_cipher.decrypt(header, payload)
            if ctype == CT_ALERT:
                raise TLSException(f"收到 alert: {alert_text(payload)}")
            if ctype != CT_HANDSHAKE:
                raise TLSException(f"握手期间收到意外记录类型 {ctype}")
            return ctype, payload

    def _read_handshake_message(self) -> tuple[int, bytes]:
        """按需跨记录拼接一条完整握手消息, ciphertext 已被前一层解密"""
        while True:
            if len(self._hs_buf) >= 4:
                msglen = int.from_bytes(self._hs_buf[1:4], "big")
                if len(self._hs_buf) >= 4 + msglen:
                    msg = self._hs_buf[:4 + msglen]
                    self._hs_buf = self._hs_buf[4 + msglen:]
                    return msg[0], msg
            _, data = self._read_handshake_record()
            self._hs_buf += data

    # ------------------------------------------------------------ 握手

    def _dbg(self, *a) -> None:
        if os.environ.get("CHROME_FP_DEBUG"):
            print("    [tls]", *a, file=sys.stderr)

    def do_handshake(self) -> str | None:
        t0 = time.time()
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
        # transcript 永远从 ClientHello 开始(即使 ClientHello 由分派器代发)
        self.transcript += self.ch.handshake
        if not self._ch_sent:
            self._send(self.ch.record)

        if self._pre_sh is not None:
            server_hello_msg = self._pre_sh      # 由 client.open_connection 预读(用于分派 1.3/1.2)
        else:
            hs_type, server_hello_msg = self._read_handshake_message()
            if hs_type != HS_SERVER_HELLO:
                raise TLSException(f"期待 ServerHello, 收到 {hs_type}")
        self.transcript += server_hello_msg
        sh = self._parse_server_hello(server_hello_msg[4:])
        self._dbg("ServerHello: suite=0x%04x group=0x%04x keyshare=%d B" % (
            sh["cipher_suite"], sh["key_share"][0], len(sh["key_share"][1])))

        if sh["is_hrr"]:
            sh, server_hello_msg = self._handle_hello_retry(sh, server_hello_msg)

        cipher = sh["cipher_suite"]
        if cipher not in CIPHER_SUITES:
            raise TLSException(f"服务器选择了不支持的套件 0x{cipher:04x}")
        hash_name, key_len, aead_name = CIPHER_SUITES[cipher]
        self.cipher_suite = cipher
        self.suite_hash = hash_name   # handshake hash = 套件的哈希(RFC 8446 用它算 Transcript-Hash)

        shared = self._compute_shared_secret(sh["key_share"])

        # ---- 密钥调度 (RFC 8446 §7.1) ----
        hlen = HASHES[hash_name]().digest_size
        early_secret = _hkdf_extract(b"\x00" * hlen, b"\x00" * hlen, hash_name)
        derived = _derive_secret(early_secret, "derived", b"", hash_name)
        hs_secret = _hkdf_extract(derived, shared, hash_name)
        c_hs = _derive_secret(hs_secret, "c hs traffic", bytes(self.transcript), hash_name)
        s_hs = _derive_secret(hs_secret, "s hs traffic", bytes(self.transcript), hash_name)
        self._keylog("CLIENT_HANDSHAKE_TRAFFIC_SECRET", c_hs)
        self._keylog("SERVER_HANDSHAKE_TRAFFIC_SECRET", s_hs)
        self._read_cipher = _RecordCipher(s_hs, hash_name, key_len, aead_name)
        c_hs_cipher = _RecordCipher(c_hs, hash_name, key_len, aead_name)

        # ---- 加密扩展 / 证书 / Finished ----
        server_cert = None
        cert_verify = None
        while True:
            hs_type, msg = self._read_handshake_message()
            self.transcript += msg
            self._dbg("收到握手消息 type=%d len=%d" % (hs_type, len(msg)))
            if hs_type == HS_ENCRYPTED_EXTENSIONS:
                self.alpn = self._parse_encrypted_extensions(msg[4:])
            elif hs_type == HS_CERTIFICATE:
                server_cert = self._parse_certificate(msg[4:])
            elif hs_type == HS_COMPRESSED_CERTIFICATE:
                server_cert = self._parse_compressed_certificate(msg[4:])
            elif hs_type == HS_CERTIFICATE_VERIFY:
                cert_verify = self._parse_certificate_verify(msg[4:])
                # 校验要等拿到 leaf 证书, 但 transcript 必须冻结在此刻(否则会混入后面的 Finished)
                self._cv_transcript = bytes(self.transcript)
            elif hs_type == HS_CERTIFICATE_REQUEST:
                self._cert_request = self._parse_certificate_request13(msg[4:])
                self._dbg("服务器要求客户端证书: context=%s sigalgs=%s" % (
                    self._cert_request[0].hex(),
                    [hex(a) for a in self._cert_request[1]]))
            elif hs_type == HS_FINISHED:
                self._verify_finished(s_hs, hash_name, msg[4:])
                break
            else:
                raise TLSException(f"握手期收到意外消息 {hs_type}")

        if cert_verify and server_cert and not os.environ.get("CHROME_FP_SKIP_CV"):
            self._check_certificate_verify(server_cert, cert_verify)
        if self.verify_certs and self.peer_certificate_chain:
            self._verify_chain(self.ch.host)

        # ---- 应用数据密钥: transcript 截止到 server Finished (RFC 8446 §7.1) ----
        derived2 = _derive_secret(hs_secret, "derived", b"", hash_name)
        master = _hkdf_extract(derived2, b"\x00" * hlen, hash_name)
        c_ap = _derive_secret(master, "c ap traffic", bytes(self.transcript), hash_name)
        s_ap = _derive_secret(master, "s ap traffic", bytes(self.transcript), hash_name)
        self._app_secrets = {"client": c_ap, "server": s_ap, "master": master,
                             "hash": hash_name, "key_len": key_len, "aead": aead_name}
        self._keylog("CLIENT_TRAFFIC_SECRET_0", c_ap)
        self._keylog("SERVER_TRAFFIC_SECRET_0", s_ap)
        self._keylog("EXPORTER_SECRET", _derive_secret(master, "exporter", bytes(self.transcript),
                                                       hash_name))
        self._write_cipher = _RecordCipher(c_ap, hash_name, key_len, aead_name)
        self._read_cipher = _RecordCipher(s_ap, hash_name, key_len, aead_name)

        # ---- 客户端 Finished ----
        # Chrome 在 ClientHello 后已发过一个 dummy CCS(client.py), 这里再随 Finished 发一个
        # (BoringSSL handshake_client.cc:1610 / tls13_client.cc:192-198)。
        self._send(b"\x14\x03\x03\x00\x01\x01")
        # ALPS (draft-vvv-tls-alps-01, BoringSSL 现行实现): 服务器在 EncryptedExtensions
        # 里回了 application_settings(0x44cd) 扩展后, 客户端必须用握手密钥再发一条
        # **客户端 EncryptedExtensions** 消息回传自己的 settings(扩展数据 = 裸 blob,
        # 不再有 draft-00 的 ClientApplicationSettings 消息)。顺序:
        #   server Finished -> client EncryptedExtensions -> client Finished
        # 该消息计入 Finished 的 transcript。Chrome 的 h2 ALPS settings 是空 blob
        # (net/http/http_network_session.cc: "Enable ALPS for HTTP/2 with empty data")。
        if self.alps:
            blob = b""
            ext = (0x44CD).to_bytes(2, "big") + len(blob).to_bytes(2, "big") + blob
            body = len(ext).to_bytes(2, "big") + ext
            ee_msg = (bytes([HS_ENCRYPTED_EXTENSIONS])
                      + len(body).to_bytes(3, "big") + body)
            self._dbg("发送客户端 EncryptedExtensions (ALPS) len=%d" % len(ee_msg))
            self._send(c_hs_cipher.encrypt(CT_HANDSHAKE, ee_msg))
            self.transcript += ee_msg
        # 服务器要过客户端证书就回 Certificate(+CertificateVerify),
        # 顺序(RFC 8446 §4.4): client EncryptedExtensions -> Certificate ->
        # CertificateVerify -> Finished, 全部用握手密钥加密。
        if self._cert_request is not None:
            self._send_client_certificate(c_hs_cipher)
        finished_key = _hkdf_expand_label(c_hs, "finished", b"", hlen, hash_name)
        transcript_hash = HASHES[hash_name](bytes(self.transcript)).digest()
        verify_data = hmac.new(finished_key, transcript_hash, HASHES[hash_name]).digest()
        fin = bytes([HS_FINISHED]) + len(verify_data).to_bytes(3, "big") + verify_data
        self._dbg("server Finished 校验通过, 发送 client Finished")
        self._send(c_hs_cipher.encrypt(CT_HANDSHAKE, fin))
        self.transcript += fin
        self._handshake_done = True
        self.handshake_time = time.time() - t0
        return self.alpn

    # ------------------------------------------------------------ HRR

    @staticmethod
    def _parse_certificate_request13(body: bytes) -> tuple[bytes, list[int]]:
        """CertificateRequest (RFC 8446 §4.4.2) -> (context, signature_algorithms)"""
        p = 0
        ctx_len = body[p]
        p += 1
        context = body[p:p + ctx_len]
        p += ctx_len
        ext_total = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        end = p + ext_total
        sigalgs: list[int] = []
        while p + 4 <= end:
            et, el = struct.unpack(">HH", body[p:p + 4])
            data = body[p + 4:p + 4 + el]
            if et == 0x000D and len(data) >= 2:
                n = struct.unpack(">H", data[:2])[0]
                sigalgs = [struct.unpack(">H", data[2 + i:4 + i])[0] for i in range(0, n, 2)]
            p += 4 + el
        return context, sigalgs

    def _send_client_certificate(self, c_hs_cipher: "_RecordCipher") -> None:
        """回应 CertificateRequest: 发 Certificate(+CertificateVerify), 计入 transcript。

        没有可用证书时也必须发一条**空 Certificate**(RFC 8446 §4.4.2), 否则服务器会
        一直等; 发空之后由服务器决定是继续还是报错。
        """
        context, sigalgs = self._cert_request
        cc = self.client_cert
        if cc is None:
            self._dbg("没有客户端证书, 发空 Certificate")
            msg = build_certificate_13(context, [])
            self._send(c_hs_cipher.encrypt(CT_HANDSHAKE, msg))
            self.transcript += msg
            return

        alg = pick_signature_algorithm(cc, sigalgs)
        if alg is None:
            raise TLSException(
                f"服务器给的 signature_algorithms {[hex(a) for a in sigalgs]} 里没有"
                f"适配 {cc.kind} 客户端证书的算法")

        cert_msg = build_certificate_13(context, cc.chain_der)
        self._send(c_hs_cipher.encrypt(CT_HANDSHAKE, cert_msg))
        self.transcript += cert_msg
        self._cert_sent = True

        transcript_hash = HASHES[self.suite_hash](bytes(self.transcript)).digest()
        content = certificate_verify_content_13(transcript_hash, "client")
        signature = sign_data(cc, alg, content)
        cv_msg = build_certificate_verify_13(alg, signature)
        self._send(c_hs_cipher.encrypt(CT_HANDSHAKE, cv_msg))
        self.transcript += cv_msg
        self._dbg("已发送客户端证书(%d 张), CertificateVerify alg=0x%04x" % (
            len(cc.chain_der), alg))

    # ------------------------------------------------------------ HRR

    def _handle_hello_retry(self, sh: dict, hrr_msg: bytes) -> tuple[dict, bytes]:
        """处理 HelloRetryRequest (RFC 8446 §4.1.4 / §4.4.1)。

        服务器想让客户端换一个 key_share 组(我们发了 X25519MLKEM768 + x25519, 它可能
        偏偏要 secp256r1), 或者要我们先带上 cookie。做法是重发一个几乎一样的
        ClientHello, 并且把 transcript 换成:
            message_hash(CH1) || HRR || CH2 || SH2 || ...
        """
        group = sh.get("hrr_group")
        cookie = sh.get("hrr_cookie")
        if group is None:
            raise TLSException("HelloRetryRequest 没有带 key_share(没指定要哪个组)")
        if group not in self.ch.supported_groups:
            raise TLSException(
                f"HRR 要的组 0x{group:04x} 不在 ClientHello 的 supported_groups 里")
        if group not in self.ch.key_shares and group not in (0x001D, 0x0017, 0x0018):
            raise TLSException(f"HRR 要的组 0x{group:04x} 本库还不会算共享密钥")
        if sh["cipher_suite"] not in CIPHER_SUITES:
            raise TLSException(f"HRR 选择了不支持的套件 0x{sh['cipher_suite']:04x}")

        self._dbg("收到 HelloRetryRequest: 换组 0x%04x cookie=%s" % (
            group, f"{len(cookie)}B" if cookie else "无"))

        # transcript 里的哈希算法用 HRR 里选定的套件对应的哈希
        hash_name = CIPHER_SUITES[sh["cipher_suite"]][0]
        digest = HASHES[hash_name](bytes(self.ch.handshake)).digest()
        message_hash = bytes([254]) + len(digest).to_bytes(3, "big") + digest

        ch2 = rebuild_for_hrr(self.ch, group, cookie)
        self._send(ch2.record)
        self.ch = ch2
        self._hrr_group = group
        # RFC 8446 §4.4.1: 从这里开始的 transcript = message_hash(CH1) || HRR || CH2 || ...
        self.transcript = bytearray(message_hash + hrr_msg + ch2.handshake)

        hs_type, sh2 = self._read_handshake_message()
        if hs_type != HS_SERVER_HELLO:
            raise TLSException(f"HRR 之后期待 ServerHello, 收到消息类型 {hs_type}")
        if len(sh2) >= 38 and sh2[6:38] == HRR_RANDOM:
            raise TLSException("服务器发了第二个 HelloRetryRequest(协议不允许)")
        self.transcript += sh2
        parsed = self._parse_server_hello(sh2[4:])
        self._dbg("ServerHello(HRR 后): suite=0x%04x group=0x%04x keyshare=%d B" % (
            parsed["cipher_suite"], parsed["key_share"][0], len(parsed["key_share"][1])))
        return parsed, sh2

    # ------------------------------------------------------------ 各类解析

    @staticmethod
    def _parse_server_hello(body: bytes) -> dict:
        p = 0
        legacy_version = body[p:p + 2]
        p += 2
        random = body[p:p + 32]
        p += 32
        sid_len = body[p]
        p += 1 + sid_len
        cipher = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        comp_len = body[p]
        p += 1 + comp_len
        ext_total = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        end = p + ext_total
        exts = {}
        while p + 4 <= end:
            et, el = struct.unpack(">HH", body[p:p + 4])
            exts[et] = body[p + 4:p + 4 + el]
            p += 4 + el
        out = {"legacy_version": legacy_version, "is_hrr": random == HRR_RANDOM, "cipher_suite": cipher}
        if out["is_hrr"]:
            # HRR 的 key_share 扩展体只有 2 字节: SelectedGroup (没有 key_exchange)
            if 0x0033 in exts:
                out["hrr_group"] = struct.unpack(">H", exts[0x0033][:2])[0]
            if 0x002C in exts:                      # cookie<1..2^16-1>
                ck = exts[0x002C]
                out["hrr_cookie"] = ck[2:2 + struct.unpack(">H", ck[:2])[0]]
            out["key_share"] = (out.get("hrr_group", 0), b"")
            if 0x002B in exts:
                out["version"] = exts[0x002B][:2]
            return out
        if 0x0033 in exts:   # key_share
            b = exts[0x0033]
            group = struct.unpack(">H", b[0:2])[0]
            klen = struct.unpack(">H", b[2:4])[0]
            out["key_share"] = (group, b[4:4 + klen])
        else:
            ver = exts.get(0x002B, b"?").hex()
            raise TLSException(
                f"ServerHello 缺少 key_share (legacy_version={legacy_version.hex()}, supported_version={ver}, "
                f"exts={[hex(x) for x in exts]}) —— 多半是服务器协商了 TLS 1.2"
            )
        if 0x002B in exts:
            out["version"] = exts[0x002B][:2]
        return out

    def _compute_shared_secret(self, key_share: tuple[int, bytes]) -> bytes:
        group, peer = key_share
        priv = self.ch.key_shares.get(group)
        if group == 0x11EC:      # X25519MLKEM768: ML-KEM 密文(1088) || X25519 公钥(32)
            if len(peer) != 1120:
                raise TLSException(f"X25519MLKEM768 key share 长度异常 {len(peer)}")
            ct, x_pub = peer[:1088], peer[1088:]
            ml_ss = mlkem.decaps(self.ch.mlkem_dk, ct, self.ch.mlkem_ek)
            if priv is None:
                priv = self.ch.key_share_private_x25519
            x_ss = priv.exchange(x25519.X25519PublicKey.from_public_bytes(x_pub))
            return ml_ss + x_ss
        if group == 0x001D:      # x25519 回退
            if priv is None:
                priv = self.ch.key_share_private_x25519
            if priv is None:
                raise TLSException("没有 x25519 私钥可用于计算共享密钥")
            return priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
        if group in EC_GROUPS:   # secp256r1 / secp384r1 (HRR 之后常见)
            if priv is None:
                raise TLSException(f"服务器选了组 0x{group:04x}, 但本库没有对应私钥")
            peer_key = ec.EllipticCurvePublicKey.from_encoded_point(EC_GROUPS[group](), peer)
            return priv.exchange(ec.ECDH(), peer_key)
        raise TLSException(f"服务器选择了未提供的组 0x{group:04x}")

    def _parse_encrypted_extensions(self, body: bytes) -> str | None:
        p = 0
        ext_total = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        end = p + ext_total
        self._dbg("EE body=%s" % body.hex())
        alpn = None
        self.alps = False
        while p + 4 <= end:
            et, el = struct.unpack(">HH", body[p:p + 4])
            data = body[p + 4:p + 4 + el]
            if et == 0x0010:
                n = struct.unpack(">H", data[:2])[0]
                ln = data[2]
                alpn = data[3:3 + ln].decode()
            elif et == 0x44CD:
                # application_settings (ALPS, draft-vvv-tls-alps-01): 服务器对已协商的
                # ALPN 启用 ALPS, 扩展数据 = 裸 settings blob(opaque, 由应用层解读)。
                self._dbg("server ALPS ext data=%s" % data.hex())
                self.alps = True
            p += 4 + el
        return alpn

    def _parse_certificate(self, body: bytes) -> bytes:
        p = 0
        ctx_len = body[p]
        p += 1 + ctx_len
        cert_list_len = int.from_bytes(body[p:p + 3], "big")
        p += 3
        end = p + cert_list_len
        chain = []
        while p + 3 <= end:
            clen = int.from_bytes(body[p:p + 3], "big")
            p += 3
            der = body[p:p + clen]
            p += clen
            # 后面可能跟扩展
            elen = struct.unpack(">H", body[p:p + 2])[0]
            p += 2 + elen
            chain.append(der)
        self.peer_certificate_chain = [x509.load_der_x509_certificate(d) for d in chain]
        return chain[0] if chain else b""

    def _parse_compressed_certificate(self, body: bytes) -> bytes:
        import brotli

        alg = struct.unpack(">H", body[0:2])[0]
        uncompressed_len = int.from_bytes(body[2:5], "big")
        clen = int.from_bytes(body[5:8], "big")
        payload = body[8:8 + clen]
        if alg == 2:
            raw = brotli.decompress(payload)
        elif alg == 1:
            import zlib

            raw = zlib.decompress(payload)
        else:
            raise TLSException(f"不支持的证书压缩算法 {alg}")
        if len(raw) != uncompressed_len:
            raise TLSException("解压后证书长度不符")
        return self._parse_certificate(raw)

    @staticmethod
    def _parse_certificate_verify(body: bytes) -> dict:
        p = 0
        alg = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        siglen = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        return {"algorithm": alg, "signature": body[p:p + siglen]}

    def _verify_finished(self, s_hs: bytes, hash_name: str, verify_data: bytes) -> None:
        hlen = HASHES[hash_name]().digest_size
        finished_key = _hkdf_expand_label(s_hs, "finished", b"", hlen, hash_name)
        # transcript 已包含 server Finished 之前的所有消息(调用方在加之前验证)
        transcript_without_finished = bytes(self.transcript[:-len(verify_data) - 4])
        expect = hmac.new(
            finished_key, HASHES[hash_name](transcript_without_finished).digest(), HASHES[hash_name]
        ).digest()
        if not hmac.compare_digest(expect, verify_data):
            raise TLSException("服务器 Finished 校验失败")

    def _check_certificate_verify(self, leaf_der: bytes, cv: dict) -> None:
        leaf = x509.load_der_x509_certificate(leaf_der)
        alg = cv["algorithm"]
        if alg not in SIG_ALGS:
            raise TLSException(f"未知签名算法 0x{alg:04x}")
        hash_name, kind = SIG_ALGS[alg]
        # transcript 截止到 CertificateVerify 之前(用收到该消息时冻结的快照)
        cv_msg_len = 4 + 2 + 2 + len(cv["signature"])
        snapshot = getattr(self, "_cv_transcript", bytes(self.transcript))
        signed_ctx = snapshot[:-cv_msg_len]
        # 关键: Transcript-Hash 用的是**密码套件的哈希**(如 0x1302 -> SHA-384),
        # 不是签名算法自己的哈希(如 rsa_pss_rsae_sha256 -> SHA-256)。混用会在
        # 与 AES-256-GCM-SHA384 套件协商的服务器上全部校验失败。
        suite_hash = getattr(self, "suite_hash", hash_name)
        context = (
            b"\x20" * 64
            + b"TLS 1.3, server CertificateVerify"
            + b"\x00"
            + HASHES[suite_hash](signed_ctx).digest()
        )
        pub = leaf.public_key()
        h = CRYPTO_HASHES[hash_name]()
        try:
            if kind == "ecdsa":
                pub.verify(cv["signature"], context, ec.ECDSA(h))
            elif kind in ("rsa_pss", "rsa_pss_pss"):
                pub.verify(
                    cv["signature"], context,
                    padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h,
                )
            elif kind == "rsa_pkcs1":
                pub.verify(cv["signature"], context, padding.PKCS1v15(), h)
            elif kind == "ed25519":
                pub.verify(cv["signature"], context)
            else:
                raise TLSException(f"未实现的签名类型 {kind}")
        except Exception as e:  # noqa: BLE001
            raise TLSException(f"CertificateVerify 校验失败: {e}") from e

    def _verify_chain(self, host: str | None = None) -> None:
        """委托给模块级 verify_server_chain(浏览器语义, 支持交叉签名根)"""
        verify_server_chain(self.peer_certificate_chain, host, getattr(self, "ca_file", None))

    # ------------------------------------------------------------ 应用数据

    def send_app(self, data: bytes) -> None:
        if not self._handshake_done:
            raise TLSException("握手尚未完成")
        # 单条 record 最大 2^14 + 256, 这里按 16384 分片
        for i in range(0, len(data), 16384):
            self._send(self._write_cipher.encrypt(CT_APPLICATION_DATA, data[i:i + 16384]))

    def recv_app(self, max_bytes: int = 65536) -> bytes:
        while not self.app_buf:
            ctype, payload = self._read_record()
            if self._read_cipher is not None:
                header = bytes([ctype, 0x03, 0x03]) + struct.pack(">H", len(payload))
                inner_type, data = self._read_cipher.decrypt(header, payload)
                if inner_type == CT_ALERT:
                    self._dbg("recv_app alert: ct=%s payload=%s lastheader=%s" % (
                        hex(ctype), data.hex(), header.hex()))
                    raise TLSException(f"收到 alert: {alert_text(data)}")
                if inner_type == CT_HANDSHAKE:
                    self._handle_post_handshake(data)
                    continue
                self.app_buf += data
            else:
                self.app_buf += payload
        out, self.app_buf = self.app_buf[:max_bytes], self.app_buf[max_bytes:]
        return out

    def _handle_post_handshake(self, data: bytes) -> None:
        """处理 NewSessionTicket(忽略) 与 KeyUpdate(必须换密钥)"""
        p = 0
        while p + 4 <= len(data):
            hs_type = data[p]
            msglen = int.from_bytes(data[p + 1:p + 4], "big")
            if hs_type == HS_KEY_UPDATE and len(data) >= p + 4 + msglen:
                secrets = self._app_secrets
                hs = secrets["hash"]
                klen = secrets["key_len"]
                aead = secrets["aead"]
                secrets["server"] = _hkdf_expand_label(
                    secrets["server"], "traffic upd", b"", HASHES[hs]().digest_size, hs
                )
                self._read_cipher = _RecordCipher(secrets["server"], hs, klen, aead)
                if msglen >= 1 and data[p + 4] == 1:   # update_requested: 回一个 KeyUpdate
                    secrets["client"] = _hkdf_expand_label(
                        secrets["client"], "traffic upd", b"", HASHES[hs]().digest_size, hs
                    )
                    self._write_cipher = _RecordCipher(secrets["client"], hs, klen, aead)
                    msg = bytes([HS_KEY_UPDATE, 0, 0, 1, 0])
                    self._send(self._write_cipher.encrypt(CT_HANDSHAKE, msg))
            p += 4 + msglen

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
