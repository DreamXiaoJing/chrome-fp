"""客户端证书(mTLS)支持 —— 加载证书/私钥、挑签名算法、按 TLS 1.2/1.3 规则做签名。

`cert=` 的取值和 requests 一致:
    cert="client.pem"                 # 证书和私钥在同一个 PEM 里
    cert=("client.pem", "client.key") # 分开两个文件
PEM 里可以是一整条链(叶子在前), 会原样发给服务器。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

# 我们能签的算法 -> (签名类型, 哈希名)
# 只列标准 IANA 编号; 0x09xx 那几个只有 Chrome 在广告, 这里不主动选。
SIGN_ALGORITHMS = {
    0x0403: ("ecdsa", "sha256"),
    0x0503: ("ecdsa", "sha384"),
    0x0603: ("ecdsa", "sha512"),
    0x0804: ("rsa_pss", "sha256"),
    0x0805: ("rsa_pss", "sha384"),
    0x0806: ("rsa_pss", "sha512"),
    0x0401: ("rsa_pkcs1", "sha256"),
    0x0501: ("rsa_pkcs1", "sha384"),
    0x0601: ("rsa_pkcs1", "sha512"),
    0x0807: ("ed25519", None),
}

_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}

# 各密钥类型下的偏好顺序(越靠前越优先)
_PREFERENCE = {
    "rsa": [0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
    "ec": [0x0403, 0x0503, 0x0603],
    "ed25519": [0x0807],
}


class ClientCertError(Exception):
    pass


@dataclass
class ClientCertificate:
    chain_der: list[bytes]
    private_key: object
    cert: x509.Certificate

    @property
    def kind(self) -> str:
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return "rsa"
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            return "ec"
        if isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            return "ed25519"
        return "unknown"


def load_client_certificate(cert) -> ClientCertificate:
    """cert 是文件路径或 (cert_path, key_path); 返回解析好的证书链 + 私钥。"""
    if isinstance(cert, (tuple, list)):
        if len(cert) != 2:
            raise ClientCertError("cert 应该是 (证书文件, 私钥文件)")
        cert_file, key_file = cert
    else:
        cert_file = key_file = cert
    try:
        with open(cert_file, "rb") as f:
            chain = x509.load_pem_x509_certificates(f.read())
    except (OSError, ValueError) as e:
        raise ClientCertError(f"读取客户端证书失败 {cert_file!r}: {e}") from e
    if not chain:
        raise ClientCertError(f"客户端证书文件里没有证书: {cert_file!r}")
    try:
        with open(key_file, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError, TypeError) as e:
        raise ClientCertError(f"读取客户端私钥失败 {key_file!r}: {e}") from e
    return ClientCertificate(
        chain_der=[c.public_bytes(serialization.Encoding.DER) for c in chain],
        private_key=key,
        cert=chain[0],
    )


def pick_signature_algorithm(cc: ClientCertificate, offered: list[int]) -> int | None:
    """从服务器广告的 signature_algorithms 里挑一个我们能用的"""
    kind = cc.kind
    if kind == "ec":
        # 只签匹配曲线的哈希(P-256 配 sha256 ...), 免得服务器拒绝
        curve = cc.private_key.curve
        if isinstance(curve, ec.SECP384R1):
            prefs = [0x0503, 0x0603, 0x0403]
        elif isinstance(curve, ec.SECP521R1):
            prefs = [0x0603, 0x0503, 0x0403]
        else:
            prefs = [0x0403, 0x0503, 0x0603]
    else:
        prefs = _PREFERENCE.get(kind, [])
    for alg in prefs:
        if alg in offered:
            return alg
    # 服务器没给出我们能用的: 退而求其次, 只要它给了列表就挑第一个我们能实现的
    for alg in offered:
        if alg in SIGN_ALGORITHMS:
            return alg
    return None


def sign_data(cc: ClientCertificate, alg: int, data: bytes) -> bytes:
    """按 TLS 的规则对 data 签名"""
    if alg not in SIGN_ALGORITHMS:
        raise ClientCertError(f"不支持用算法 0x{alg:04x} 签名")
    kind, hash_name = SIGN_ALGORITHMS[alg]
    key = cc.private_key
    if kind == "ed25519":
        return key.sign(data)
    h = _HASHES[hash_name]()
    if kind == "ecdsa":
        return key.sign(data, ec.ECDSA(h))
    if kind == "rsa_pss":
        return key.sign(data, padding.PSS(mgf=padding.MGF1(h),
                                          salt_length=h.digest_size))
    if kind == "rsa_pkcs1":
        return key.sign(data, padding.PKCS1v15())
    raise ClientCertError(f"未实现的签名类型 {kind}")


def signature_algorithm_name(alg: int) -> str:
    if alg not in SIGN_ALGORITHMS:
        return f"0x{alg:04x}"
    return f"{SIGN_ALGORITHMS[alg][0]}+{SIGN_ALGORITHMS[alg][1]}"


# ---------------------------------------------------------------- 消息构造

def build_certificate_13(context: bytes, chain_der: list[bytes]) -> bytes:
    """TLS 1.3 Certificate (RFC 8446 §4.4.2)"""
    body = bytes([len(context)]) + context
    entries = b"".join(len(d).to_bytes(3, "big") + d + b"\x00\x00" for d in chain_der)
    body += len(entries).to_bytes(3, "big") + entries
    return b"\x0b" + len(body).to_bytes(3, "big") + body


def build_certificate_verify_13(alg: int, signature: bytes) -> bytes:
    """TLS 1.3 CertificateVerify (RFC 8446 §4.4.3)"""
    body = struct.pack(">H", alg) + len(signature).to_bytes(2, "big") + signature
    return b"\x0f" + len(body).to_bytes(3, "big") + body


def certificate_verify_content_13(transcript_hash: bytes, side: str = "client") -> bytes:
    """TLS 1.3 的签名内容 = 64 个空格 || 上下文串 || 0x00 || Transcript-Hash"""
    return (b"\x20" * 64 + f"TLS 1.3, {side} CertificateVerify".encode()
            + b"\x00" + transcript_hash)


def certificate_12_body(chain_der: list[bytes]) -> bytes:
    """TLS 1.2 Certificate 的**消息体**(RFC 5246 §7.4.2), 交给调用方加握手头"""
    entries = b"".join(len(d).to_bytes(3, "big") + d for d in chain_der)
    return len(entries).to_bytes(3, "big") + entries


def certificate_verify_12_body(alg: int, signature: bytes) -> bytes:
    """TLS 1.2 CertificateVerify 的消息体: 显式 sigalg + 签名, 没有上下文串"""
    return struct.pack(">H", alg) + len(signature).to_bytes(2, "big") + signature
