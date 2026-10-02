"""纯 Python TLS 1.2 客户端(回落路径) —— 与 tls13.py 同接口。

为什么需要: 一部分服务器(nginx.org / bing.com / sohu.com 等)只支持 TLS 1.2。
真 Chrome 遇到这种服务器会用**同一个 ClientHello** 回落到 1.2(我们发的 ClientHello 里
supported_versions 已含 0x0303、密码套件里也含 TLS1.2 套件),所以指纹不变。

支持:
  - ECDHE + AES-GCM (c02b/c02f/c02c/c030)
  - ECDHE + ChaCha20-Poly1305 (cca9/cca8)
  - RSA 密钥交换 + AES-GCM (009c/009d)
  - **CBC 类套件**(c013/c014/002f/0035, MAC-then-Encrypt + HMAC-SHA1) —— 都在 Chrome
    的密码套件表里, 老服务器还不少
  - extended_master_secret (RFC 7627)、ALPN、ServerKeyExchange 签名校验、服务器 Finished 校验
  - 证书链 + 主机名校验(复用 tls13 的浏览器语义实现)
  - 客户端证书(mTLS, CertificateRequest -> Certificate + CertificateVerify)
不支持: 会话恢复、0-RTT、TLS 1.0/1.1(Chrome 也不支持)、非 AES 的 CBC 套件。
"""

from __future__ import annotations

import hmac
import os
import socket
import struct
import time
from hashlib import sha256, sha384

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .hello import ClientHello
from .clientcert import (
    certificate_12_body,
    certificate_verify_12_body,
    pick_signature_algorithm,
    sign_data,
)
from .tls13 import (
    CT_ALERT,
    HS_CERTIFICATE_STATUS,
    CT_APPLICATION_DATA,
    CT_CHANGE_CIPHER_SPEC,
    CT_HANDSHAKE,
    CRYPTO_HASHES,
    HASHES,
    HS_CERTIFICATE,
    HS_CERTIFICATE_REQUEST,
    HS_CERTIFICATE_VERIFY,
    HS_FINISHED,
    HS_NEW_SESSION_TICKET,
    HS_SERVER_HELLO,
    HS_SERVER_HELLO_DONE,
    SIG_ALGS,
    TLSException,
    alert_text,
    _dnsname_matches,
)

HS_CLIENT_KEY_EXCHANGE = 16
HS_SERVER_KEY_EXCHANGE = 12

# TLS 1.2 套件: code -> (PRF哈希, 密钥长度, AEAD, 是否RSA密钥交换, MAC哈希)
# MAC 哈希只对 CBC 类套件有意义(None 表示 AEAD)。
TLS12_SUITES: dict[int, tuple[str, int, str, bool, str | None]] = {
    0xC02B: ("sha256", 16, "aesgcm", False, None),
    0xC02F: ("sha256", 16, "aesgcm", False, None),
    0xC02C: ("sha384", 32, "aesgcm", False, None),
    0xC030: ("sha384", 32, "aesgcm", False, None),
    0xCCA9: ("sha256", 32, "chacha20", False, None),
    0xCCA8: ("sha256", 32, "chacha20", False, None),
    0x009C: ("sha256", 16, "aesgcm", True, None),
    0x009D: ("sha384", 32, "aesgcm", True, None),
    # ---- CBC 类(MAC-then-Encrypt), 这 4 个都在 Chrome 的密码套件表里 ----
    # RFC 5246 附录 A.5: *_WITH_AES_128_CBC_SHA 的 PRF 是 SHA-256, 记录层 MAC 是 HMAC-SHA1
    0xC013: ("sha256", 16, "aescbc", False, "sha1"),   # ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC014: ("sha256", 32, "aescbc", False, "sha1"),   # ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x002F: ("sha256", 16, "aescbc", True, "sha1"),    # RSA_WITH_AES_128_CBC_SHA
    0x0035: ("sha256", 32, "aescbc", True, "sha1"),    # RSA_WITH_AES_256_CBC_SHA
}

CBC_MAC_LEN = {"sha1": 20, "sha256": 32, "sha384": 48}
CBC_BLOCK = 16

# ECDHE 曲线: group -> 名称(用于生成临时密钥)
ECDHE_CURVES = {
    0x001D: "x25519",
    0x001E: "x448",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
}


def prf(secret: bytes, label: bytes, seed: bytes, length: int, hash_name: str) -> bytes:
    """TLS 1.2 PRF (RFC 5246 §5, P_hash)"""
    hash_fn = HASHES[hash_name]
    label_seed = label + seed
    out = b""
    a = hmac.new(secret, label_seed, hash_fn).digest()
    while len(out) < length:
        out += hmac.new(secret, a + label_seed, hash_fn).digest()
        a = hmac.new(secret, a, hash_fn).digest()
    return out[:length]


class _RecordCipher12:
    """TLS 1.2 AEAD 记录保护"""

    def __init__(self, key: bytes, iv: bytes, aead_name: str):
        self.key = key
        self.iv = iv
        self.aead_name = aead_name
        self.seq = 0
        self.aead = ChaCha20Poly1305(key) if aead_name == "chacha20" else AESGCM(key)

    def _nonce(self, explicit: bytes | None) -> bytes:
        if self.aead_name == "chacha20":
            n = bytearray(self.iv)
            pad = self.seq.to_bytes(8, "big")
            for i in range(8):
                n[4 + i] ^= pad[i]
            return bytes(n)
        # GCM: fixed_iv(4) || explicit_nonce(8); 明文里传输 explicit(用 seq)
        assert explicit is not None and len(explicit) == 8
        return self.iv + explicit

    def encrypt(self, content_type: int, plaintext: bytes) -> bytes:
        length = len(plaintext)
        if self.aead_name == "chacha20":
            aad = self.seq.to_bytes(8, "big") + bytes([content_type, 3, 3]) + struct.pack(">H", length)
            out = self.aead.encrypt(self._nonce(None), plaintext, aad)
        else:
            explicit = self.seq.to_bytes(8, "big")
            aad = self.seq.to_bytes(8, "big") + bytes([content_type, 3, 3]) + struct.pack(">H", length)
            out = explicit + self.aead.encrypt(self._nonce(explicit), plaintext, aad)
        self.seq += 1
        return out

    def decrypt(self, content_type: int, payload: bytes) -> bytes:
        if self.aead_name == "chacha20":
            aad_len = len(payload) - 16
            aad = self.seq.to_bytes(8, "big") + bytes([content_type, 3, 3]) + struct.pack(">H", aad_len)
            pt = self.aead.decrypt(self._nonce(None), payload, aad)
        else:
            explicit, ct = payload[:8], payload[8:]
            aad_len = len(ct) - 16
            aad = self.seq.to_bytes(8, "big") + bytes([content_type, 3, 3]) + struct.pack(">H", aad_len)
            pt = self.aead.decrypt(self._nonce(explicit), ct, aad)
        self.seq += 1
        return pt


class _RecordCipher12CBC:
    """TLS 1.2 CBC 记录保护(MAC-then-Encrypt, RFC 5246 §6.2.3.2)。

    与 AEAD 的区别:
      * 记录体 = 显式 IV(TLS 1.1+ 每条记录随机) || AES-CBC 密文
      * 明文 = 应用数据 || HMAC || padding, 填充到 16 字节整数倍
      * MAC 覆盖 seq_num(8) || type(1) || version(2) || length(2) || 明文
      * 隐式 IV(密钥块里的 client/server_write_IV)在 TLS 1.1+ 之后不再使用
    """

    def __init__(self, key: bytes, mac_key: bytes, mac_name: str):
        self.key = key
        self.mac_key = mac_key
        self.mac_name = mac_name
        self.mac_len = CBC_MAC_LEN[mac_name]
        self.seq = 0

    def _cipher_for(self, iv: bytes):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # 每条记录一个随机 IV(TLS 1.1+ 显式 IV), 所以 cipher 不能提前建好
        return Cipher(algorithms.AES(self.key), modes.CBC(iv))

    def _mac(self, content_type: int, plaintext: bytes) -> bytes:
        msg = (self.seq.to_bytes(8, "big") + bytes([content_type, 3, 3])
               + struct.pack(">H", len(plaintext)) + plaintext)
        return hmac.new(self.mac_key, msg, HASHES[self.mac_name]).digest()

    def encrypt(self, content_type: int, plaintext: bytes) -> bytes:
        data = plaintext + self._mac(content_type, plaintext)
        pad_len = CBC_BLOCK - (len(data) % CBC_BLOCK)
        data += bytes([pad_len - 1]) * pad_len          # TLS 用"填充长度=值"
        iv = os.urandom(CBC_BLOCK)
        enc = self._cipher_for(iv).encryptor()
        ct = enc.update(data) + enc.finalize()
        self.seq += 1
        return iv + ct

    def decrypt(self, content_type: int, payload: bytes) -> bytes:
        if len(payload) < CBC_BLOCK * 2 or (len(payload) - CBC_BLOCK) % CBC_BLOCK:
            raise TLSException("CBC 记录长度非法")
        iv, ct = payload[:CBC_BLOCK], payload[CBC_BLOCK:]
        dec = self._cipher_for(iv).decryptor()
        data = dec.update(ct) + dec.finalize()
        pad_len = data[-1] + 1
        if pad_len > len(data) - self.mac_len or any(b != data[-1] for b in data[-pad_len:]):
            raise TLSException("CBC 填充校验失败")
        data = data[:-pad_len]
        plaintext, mac = data[:-self.mac_len], data[-self.mac_len:]
        expect = self._mac(content_type, plaintext)
        if not hmac.compare_digest(mac, expect):
            raise TLSException("CBC 记录 MAC 校验失败")
        self.seq += 1
        return plaintext


class TLS12Connection:
    """在已连接的 socket 上完成 TLS 1.2 握手(ClientHello 已由调用方发出)"""

    def __init__(
        self,
        sock: socket.socket,
        client_hello: ClientHello,
        *,
        server_hello_msg: bytes,
        hs_buf: bytes = b"",
        preload_buf: bytes = b"",
        verify_certs: bool = True,
        ca_file: str | None = None,
        timeout: float | None = 30.0,
        keylog_file: str | None = None,
        client_cert=None,
    ):
        self.sock = sock
        self.ch = client_hello
        self.verify_certs = verify_certs
        self.ca_file = ca_file
        self.timeout = timeout
        self.transcript = bytearray(client_hello.handshake)
        self._pre_sh = server_hello_msg
        self._hs_buf = hs_buf
        self.recv_buf = preload_buf
        self.app_buf = b""
        self.alpn: str | None = None
        self.cipher_suite: int | None = None
        self.peer_certificate_chain: list[x509.Certificate] = []
        self._read_cipher: _RecordCipher12 | None = None
        self._write_cipher: _RecordCipher12 | None = None
        self._peer_ccs = False
        self._handshake_done = False
        self.handshake_time = 0.0
        # SSLKEYLOGFILE 兼容(TLS1.2 用 CLIENT_RANDOM 行), 方便 Wireshark 解密
        self.keylog_file = keylog_file
        self.client_cert = client_cert
        self._cert_request12: tuple[list[int], list[int]] | None = None

    # ------------------------------------------------------------ IO

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
        length = struct.unpack(">H", header[3:5])[0]
        return header[0], self._recv_exact(length)

    def _read_plain_or_decrypted(self) -> tuple[int, bytes]:
        """读一条记录; 对端 CCS 之后的记录才解密。

        注意 RFC 5077: NewSessionTicket 是在服务器 CCS **之前**以明文发出的,
        所以不能用"我方已装密钥"来判断该不该解密。
        """
        while True:
            ctype, payload = self._read_record()
            if ctype == CT_CHANGE_CIPHER_SPEC:
                self._peer_ccs = True
                continue
            if self._read_cipher is not None and self._peer_ccs and ctype != CT_ALERT:
                self._last_ct = (ctype, payload)     # 解密失败时留证, 供诊断脚本用
                payload = self._read_cipher.decrypt(ctype, payload)
            if ctype == CT_ALERT:
                raise TLSException(f"收到 alert: {alert_text(payload)}")
            return ctype, payload

    def _read_handshake_message(self) -> tuple[int, bytes]:
        while True:
            if len(self._hs_buf) >= 4:
                msglen = int.from_bytes(self._hs_buf[1:4], "big")
                if len(self._hs_buf) >= 4 + msglen:
                    msg = self._hs_buf[:4 + msglen]
                    self._hs_buf = self._hs_buf[4 + msglen:]
                    return msg[0], msg
            ctype, data = self._read_plain_or_decrypted()
            if ctype != CT_HANDSHAKE:
                raise TLSException(f"握手期收到意外记录类型 {ctype}")
            self._hs_buf += data

    def _send_handshake(self, msg_type: int, body: bytes, *, plain: bool = True) -> bytes:
        msg = bytes([msg_type]) + len(body).to_bytes(3, "big") + body
        self.transcript += msg
        record = bytes([CT_HANDSHAKE, 3, 3]) + struct.pack(">H", len(msg)) + msg
        if plain:
            self._send(record)
        else:
            ct = self._write_cipher.encrypt(CT_HANDSHAKE, msg)
            self._send(bytes([CT_HANDSHAKE, 3, 3]) + struct.pack(">H", len(ct)) + ct)
        return msg

    # ------------------------------------------------------------ 客户端证书

    @staticmethod
    def _parse_certificate_request12(body: bytes) -> tuple[list[int], list[int]]:
        """CertificateRequest (RFC 5246 §7.4.4) -> (certificate_types, sigalgs)"""
        p = 0
        types_len = body[p]
        p += 1
        types = list(body[p:p + types_len])
        p += types_len
        sig_len = int.from_bytes(body[p:p + 2], "big")
        p += 2
        sigalgs = [int.from_bytes(body[p + i:p + i + 2], "big") for i in range(0, sig_len, 2)]
        return types, sigalgs

    def _send_certificate12(self):
        """回 Certificate(必须在 ClientKeyExchange 之前), 返回选定的签名算法或 None"""
        if self._cert_request12 is None:
            return None
        _types, sigalgs = self._cert_request12
        cc = self.client_cert
        if cc is None:
            # RFC 5246 §7.4.6: 没有合适证书就发一条空链
            self._dbg("服务器要客户端证书, 但我们没有 -> 发空 Certificate")
            self._send_handshake(HS_CERTIFICATE, b"\x00\x00\x00")
            return None
        alg = pick_signature_algorithm(cc, sigalgs)
        if alg is None:
            raise TLSException(
                f"服务器给的 signature_algorithms {[hex(a) for a in sigalgs]} 里没有"
                f"适配 {cc.kind} 客户端证书的算法")
        self._send_handshake(HS_CERTIFICATE, certificate_12_body(cc.chain_der))
        self._dbg("已发送客户端证书(%d 张), 待签名算法 0x%04x" % (len(cc.chain_der), alg))
        return alg

    def _send_certificate_verify12(self, alg: int) -> None:
        """CertificateVerify: 对"到 ClientKeyExchange 为止"的握手消息签名(无上下文串)"""
        cc = self.client_cert
        digest = HASHES[self._sig_hash_name(alg)](bytes(self.transcript)).digest()
        signature = sign_data(cc, alg, digest)
        self._send_handshake(HS_CERTIFICATE_VERIFY, certificate_verify_12_body(alg, signature))
        self._dbg("已发送 CertificateVerify alg=0x%04x" % alg)

    @staticmethod
    def _sig_hash_name(alg: int) -> str:
        from .clientcert import SIGN_ALGORITHMS

        kind, hash_name = SIGN_ALGORITHMS[alg]
        return hash_name or "sha256"

    # ------------------------------------------------------------ 握手

    def do_handshake(self) -> str | None:
        t0 = time.time()
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
        self.transcript += self._pre_sh
        sh = self._parse_server_hello(self._pre_sh[4:])
        suite = sh["cipher_suite"]
        if suite not in TLS12_SUITES:
            raise TLSException(
                f"TLS 1.2 选择了本库未实现的套件 0x{suite:04x}"
                f"(该服务器可能不支持 AES-GCM/ChaCha20/AES-CBC)"
            )
        prf_hash, key_len, aead_name, rsa_kex, mac_hash = TLS12_SUITES[suite]
        self.cipher_suite = suite
        self.alpn = sh.get("alpn")
        self.suite_hash = prf_hash
        self._sh = sh
        self._prf_hash, self._key_len, self._aead = prf_hash, key_len, aead_name
        self._mac_hash = mac_hash

        # ---- Certificate / ServerKeyExchange / ServerHelloDone ----
        certs_der: list[bytes] = []
        ske: dict | None = None
        server_cert_verify: dict | None = None
        for _ in range(20):
            hs_type, msg = self._read_handshake_message()
            self.transcript += msg
            if hs_type == HS_CERTIFICATE:
                certs_der = self._parse_certificate12(msg[4:])
            elif hs_type == HS_SERVER_KEY_EXCHANGE:
                ske = self._parse_ske(msg[4:])
            elif hs_type == HS_CERTIFICATE_STATUS:
                pass   # OCSP 装订响应: 只影响 transcript, 已在上面统一追加
            elif hs_type == HS_CERTIFICATE_REQUEST:
                self._cert_request12 = self._parse_certificate_request12(msg[4:])
            elif hs_type == HS_SERVER_HELLO_DONE:
                break
            else:
                raise TLSException(f"握手期收到意外消息 {hs_type}")
        self.peer_certificate_chain = [x509.load_der_x509_certificate(d) for d in certs_der]
        if self.verify_certs and self.peer_certificate_chain:
            self._verify_chain12()

        # ---- 密钥交换 ----
        # TLS 1.2 的客户端证书要在 ClientKeyExchange **之前**发(RFC 5246 §7.3 的消息顺序)
        alg12 = self._send_certificate12()
        if rsa_kex:
            if not self.peer_certificate_chain:
                raise TLSException("RSA 密钥交换但服务器未提供证书")
            premaster = b"\x03\x03" + os.urandom(46)
            pub = self.peer_certificate_chain[0].public_key()
            if not isinstance(pub, rsa.RSAPublicKey):
                raise TLSException("RSA 密钥交换但证书公钥不是 RSA")
            enc = pub.encrypt(premaster, padding.PKCS1v15())
            self._send_handshake(HS_CLIENT_KEY_EXCHANGE, struct.pack(">H", len(enc)) + enc)
        else:
            if ske is None:
                raise TLSException("缺少 ServerKeyExchange(ECDHE 握手必需)")
            priv, pub_bytes = self._gen_ecdhe(ske["group"])
            self._check_ske_signature(ske)
            self._send_handshake(HS_CLIENT_KEY_EXCHANGE, bytes([len(pub_bytes)]) + pub_bytes)
            premaster = self._ecdhe_secret(ske, priv)

        # ---- 主密钥 ----
        self._premaster = premaster
        cr, sr = self.ch.random, sh["random"]
        if sh["extended_master_secret"]:
            session_hash = HASHES[prf_hash](bytes(self.transcript)).digest()
            master = prf(premaster, b"extended master secret", session_hash, 48, prf_hash)
        else:
            master = prf(premaster, b"master secret", cr + sr, 48, prf_hash)
        self._master = master
        # CertificateVerify 要在 session_hash(EMS) 之后、CCS 之前发:
        # RFC 7627 的 session_hash 只算到 ClientKeyExchange, 不含 CertificateVerify。
        if alg12 is not None:
            self._send_certificate_verify12(alg12)
        if self.keylog_file:
            # TLS 1.2 的 NSS key log 格式: CLIENT_RANDOM <client_random> <master_secret>
            try:
                with open(self.keylog_file, "a", encoding="utf-8") as f:
                    f.write(f"CLIENT_RANDOM {cr.hex()} {master.hex()}\n")
            except OSError:
                pass

        # ---- key_block (RFC 5246 §6.3: MAC 密钥 -> 加密密钥 -> IV) ----
        iv_len = 12 if aead_name == "chacha20" else 4
        mac_len = CBC_MAC_LEN[mac_hash] if mac_hash else 0
        need = 2 * mac_len + 2 * key_len + 2 * iv_len
        kb = prf(master, b"key expansion", sr + cr, need, prf_hash)
        p = 0
        c_mac, s_mac = kb[p:p + mac_len], kb[p + mac_len:p + 2 * mac_len]
        p += 2 * mac_len
        c_key, s_key = kb[p:p + key_len], kb[p + key_len:p + 2 * key_len]
        p += 2 * key_len
        c_iv, s_iv = kb[p:p + iv_len], kb[p + iv_len:need]
        if aead_name == "aescbc":
            self._write_cipher = _RecordCipher12CBC(c_key, c_mac, mac_hash)
            self._read_cipher = _RecordCipher12CBC(s_key, s_mac, mac_hash)
        else:
            self._write_cipher = _RecordCipher12(c_key, c_iv, aead_name)
            self._read_cipher = _RecordCipher12(s_key, s_iv, aead_name)

        # ---- Finished (client) ----
        self._send(bytes([CT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]))
        verify_data = prf(master, b"client finished", HASHES[prf_hash](bytes(self.transcript)).digest(), 12, prf_hash)
        self._send_handshake(HS_FINISHED, verify_data, plain=False)

        # ---- 服务器 CCS + Finished ----
        while True:
            hs_type, msg = self._read_handshake_message()
            if hs_type == HS_FINISHED:
                self._server_finished = msg[4:4 + 12]
                # 期望值必须在**读到在此之前的所有消息之后**才算:
                # RFC 5077 的 NewSessionTicket 是明文发在 CCS 之前, 它也算进 handshake hash。
                expect = prf(master, b"server finished",
                             HASHES[prf_hash](bytes(self.transcript)).digest(), 12, prf_hash)
                if not hmac.compare_digest(msg[4:4 + 12], expect):
                    raise TLSException("服务器 Finished 校验失败")
                self.transcript += msg
                break
            if hs_type != HS_NEW_SESSION_TICKET:
                raise TLSException(f"握手期收到意外消息 {hs_type}")
            self.transcript += msg

        self._handshake_done = True
        self.handshake_time = time.time() - t0
        return self.alpn

    # ------------------------------------------------------------ 解析

    @staticmethod
    def _parse_server_hello(body: bytes) -> dict:
        p = 0
        version = body[p:p + 2]
        p += 2
        random = body[p:p + 32]
        p += 32
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
            end = p + ext_total
            while p + 4 <= end:
                et, el = struct.unpack(">HH", body[p:p + 4])
                exts[et] = body[p + 4:p + 4 + el]
                p += 4 + el
        out = {
            "version": version.hex(),
            "random": random,
            "cipher_suite": suite,
            "extended_master_secret": 0x0017 in exts,
        }
        if 0x0010 in exts:
            b = exts[0x0010]
            n = struct.unpack(">H", b[:2])[0]
            ln = b[2]
            out["alpn"] = b[3:3 + ln].decode()
        if version != b"\x03\x03" and version != b"\x03\x04":
            raise TLSException(f"不支持的协议版本 {version.hex()}")
        return out

    @staticmethod
    def _parse_certificate12(body: bytes) -> list[bytes]:
        """TLS 1.2 Certificate: 3 字节总长, 每张 3 字节长度 + DER(无扩展)"""
        total = int.from_bytes(body[0:3], "big")
        p = 3
        end = p + total
        out = []
        while p + 3 <= end:
            ln = int.from_bytes(body[p:p + 3], "big")
            p += 3
            out.append(body[p:p + ln])
            p += ln
        return out

    @staticmethod
    def _parse_ske(body: bytes) -> dict:
        """ServerKeyExchange: curve_type(3) + named_curve + pubkey, 然后签名算法 + 签名"""
        p = 0
        curve_type = body[p]
        p += 1
        if curve_type != 3:
            raise TLSException(f"不支持的 curve_type {curve_type}(只支持 named_curve)")
        group = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        pub_len = body[p]
        p += 1
        pub = body[p:p + pub_len]
        p += pub_len
        params = body[:p]
        sig_alg = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        sig_len = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        sig = body[p:p + sig_len]
        return {"group": group, "pub": pub, "params": params, "sig_alg": sig_alg, "signature": sig}

    def _check_ske_signature(self, ske: dict) -> None:
        # 签名内容 = client_random || server_random || ServerECDHParams
        sh = self._parse_server_hello(self._pre_sh[4:])
        content = self.ch.random + sh["random"] + ske["params"]
        alg = ske["sig_alg"]
        if alg not in SIG_ALGS:
            raise TLSException(f"未知签名算法 0x{alg:04x}")
        hash_name, kind = SIG_ALGS[alg]
        h = CRYPTO_HASHES[hash_name]()
        pub = self.peer_certificate_chain[0].public_key()
        try:
            if kind == "ecdsa":
                pub.verify(ske["signature"], content, ec.ECDSA(h))
            elif kind in ("rsa_pss", "rsa_pss_pss"):
                pub.verify(ske["signature"], content,
                           padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
            elif kind == "rsa_pkcs1" or kind == "rsa":
                pub.verify(ske["signature"], content, padding.PKCS1v15(), h)
            elif kind == "ed25519":
                pub.verify(ske["signature"], content)
            else:
                raise TLSException(f"未实现的签名类型 {kind}")
        except Exception as e:  # noqa: BLE001
            raise TLSException(f"ServerKeyExchange 签名校验失败: {e}") from e

    def _gen_ecdhe(self, group: int):
        if group == 0x001D:
            priv = x25519.X25519PrivateKey.generate()
            return priv, priv.public_key().public_bytes_raw()
        if group == 0x0017:
            priv = ec.generate_private_key(ec.SECP256R1())
        elif group == 0x0018:
            priv = ec.generate_private_key(ec.SECP384R1())
        elif group == 0x0019:
            priv = ec.generate_private_key(ec.SECP521R1())
        elif group == 0x001E:
            priv = x25519.X25519PrivateKey.generate()
            return priv, priv.public_key().public_bytes_raw()
        else:
            raise TLSException(f"未实现的服务端曲线 0x{group:04x}")
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        pub_bytes = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return priv, pub_bytes

    def _ecdhe_secret(self, ske: dict, priv) -> bytes:
        group, peer = ske["group"], ske["pub"]
        if group in (0x001D, 0x001E):
            return priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
        curve = {0x0017: ec.SECP256R1, 0x0018: ec.SECP384R1, 0x0019: ec.SECP521R1}[group]
        peer_key = ec.EllipticCurvePublicKey.from_encoded_point(curve(), peer)
        return priv.exchange(ec.ECDH(), peer_key)

    def _verify_chain12(self) -> None:
        """复用 TLS 1.3 的浏览器语义校验逻辑(结构相同: 链 + 主机名)"""
        from .tls13 import TLS13Connection

        class _Shim:
            pass

        shim = _Shim()
        shim.ca_file = self.ca_file
        shim.peer_certificate_chain = self.peer_certificate_chain
        TLS13Connection._verify_chain(shim, self.ch.host)

    # ------------------------------------------------------------ 应用数据

    def send_app(self, data: bytes) -> None:
        if not self._handshake_done:
            raise TLSException("握手尚未完成")
        for i in range(0, len(data), 16384):
            chunk = data[i:i + 16384]
            ct = self._write_cipher.encrypt(CT_APPLICATION_DATA, chunk)
            self._send(bytes([CT_APPLICATION_DATA, 3, 3]) + struct.pack(">H", len(ct)) + ct)

    def recv_app(self, max_bytes: int = 65536) -> bytes:
        while not self.app_buf:
            ctype, payload = self._read_record()
            if self._read_cipher is not None and self._peer_ccs and ctype != CT_ALERT:
                self._last_ct = (ctype, payload)
                payload = self._read_cipher.decrypt(ctype, payload)
            if ctype == CT_ALERT:
                raise TLSException(f"收到 alert: {alert_text(payload)}")
            if ctype == CT_HANDSHAKE:
                continue   # KeyUpdate/NewSessionTicket 之类, 忽略
            self.app_buf += payload
        out, self.app_buf = self.app_buf[:max_bytes], self.app_buf[max_bytes:]
        return out

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
