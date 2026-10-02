"""ML-KEM-768 (FIPS 203) 纯 Python 实现 — 只为 Chrome 的 X25519MLKEM768 混合密钥共享服务。

Chrome 152 的 key_share 里第一个条目是 group 0x11ec (X25519MLKEM768):
    client_key_share = ML-KEM-768 encapsulation key (1184B) || X25519 public key (32B)
服务端 Encaps 后共享密钥 = ML-KEM shared_secret (32B) || X25519 shared_secret (32B)。

只用 stdlib (hashlib 提供 SHA3-256 / SHA3-512 / SHAKE-128 / SHAKE-256)。
正确性由 tests/test_mlkem.py 的 round-trip 验证(KeyGen → Encaps → Decaps 三方一致)。
"""

from __future__ import annotations

import hashlib
import os

Q = 3329
N = 256
K = 3          # ML-KEM-768
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4
POLY_BYTES = 384            # 12 bits * 256 / 8
EK_BYTES = 1184             # 384*K + 32
DK_BYTES = 1152             # 384*K
CT_BYTES = 1088             # DU*K*256/8 + DV*256/8 = 960 + 128

# ---------------------------------------------------------------- 基础工具

def _bitrev7(x: int) -> int:
    return int(f"{x:07b}"[::-1], 2)


ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]


def ntt(a: list[int]) -> list[int]:
    """FIPS 203 Algorithm 9"""
    a = list(a)
    i = 1
    length = 128
    while length >= 2:
        start = 0
        while start < N:
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = (zeta * a[j + length]) % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
            start += 2 * length
        length //= 2
    return a


def intt(a: list[int]) -> list[int]:
    """FIPS 203 Algorithm 10"""
    a = list(a)
    i = 127
    length = 2
    while length <= 128:
        start = 0
        while start < N:
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = (zeta * (a[j + length] - t)) % Q
            start += 2 * length
        length *= 2
    f = 3303  # 128^-1 mod q
    return [(x * f) % Q for x in a]


def _basemul(a: list[int], b: list[int]) -> list[int]:
    """NTT 域逐对乘法 (FIPS 203 Algorithm 11/12)"""
    r = [0] * N
    for i in range(64):
        z = ZETAS[64 + i]
        a0, a1, a2, a3 = a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]
        b0, b1, b2, b3 = b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]
        r[4 * i] = (a0 * b0 + z * (a1 * b1)) % Q
        r[4 * i + 1] = (a0 * b1 + a1 * b0) % Q
        r[4 * i + 2] = (a2 * b2 - z * (a3 * b3)) % Q
        r[4 * i + 3] = (a2 * b3 + a3 * b2) % Q
    return r


def _poly_add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def _poly_sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


# ---------------------------------------------------------------- 编解码

def byte_encode(d: int, f: list[int]) -> bytes:
    """FIPS 203 Algorithm 5"""
    bits = []
    for c in f:
        for j in range(d):
            bits.append((c >> j) & 1)
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def byte_decode(d: int, data: bytes) -> list[int]:
    """FIPS 203 Algorithm 6 (d=12 时结果 mod q)"""
    bits = []
    for byte in data:
        for j in range(8):
            bits.append((byte >> j) & 1)
    out = []
    for i in range(0, len(bits), d):
        val = 0
        for j in range(d):
            val |= bits[i + j] << j
        out.append(val % Q if d == 12 else val)
    return out


def compress(x: int, d: int) -> int:
    return ((x << d) + Q // 2) // Q % (1 << d)


def decompress(y: int, d: int) -> int:
    return (y * Q + (1 << (d - 1))) >> d


def encode_vec(vectors, d) -> bytes:
    return b"".join(byte_encode(d, v) for v in vectors)


def decode_vec(data: bytes, d: int, count: int):
    step = 32 * d
    return [byte_decode(d, data[i * step:(i + 1) * step]) for i in range(count)]


# ---------------------------------------------------------------- 采样

def sample_ntt(seed: bytes, i: int, j: int) -> list[int]:
    """FIPS 203 Algorithm 7: A[i][j] = SampleNTT(XOF(rho, j, i))

    拒绝采样必须消费 XOF 的**连续**字节流; 早期版本重复读 digest() 前缀,
    在候选值不足时会重复计入同一些值(约 1/8 概率), 导致矩阵错乱。
    """
    xof = hashlib.shake_128(seed + bytes([j, i]))
    need = 1
    while True:
        # digest(n) 返回流的前 n 字节, 逐步加长 = 顺序消费
        buf = xof.digest(3 * 168 * need)
        a: list[int] = []
        for k in range(0, len(buf) - 2, 3):
            d1 = buf[k] | ((buf[k + 1] & 0x0F) << 8)
            d2 = (buf[k + 1] >> 4) | (buf[k + 2] << 4)
            if d1 < Q:
                a.append(d1)
            if d2 < Q:
                a.append(d2)
        if len(a) >= N:
            return a[:N]
        need += 1


def _prf(eta: int, s: bytes, b: int) -> list[int]:
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def sample_poly_cbd(eta: int, b: bytes) -> list[int]:
    """FIPS 203 Algorithm 8"""
    bits = []
    for byte in b:
        for j in range(8):
            bits.append((byte >> j) & 1)
    f = []
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f


# ---------------------------------------------------------------- K-PKE

def _mat_vec_mul(a_hat, v_hat):
    """NTT 域矩阵乘向量; a_hat[i][j]"""
    out = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _poly_add(acc, _basemul(a_hat[i][j], v_hat[j]))
        out.append(acc)
    return out


def kpke_keygen(d: bytes):
    g = hashlib.sha3_512(d + bytes([K])).digest()
    rho, sigma = g[:32], g[32:]
    a_hat = [[sample_ntt(rho, i, j) for j in range(K)] for i in range(K)]
    n = 0
    s = []
    for _ in range(K):
        s.append(sample_poly_cbd(ETA1, _prf(ETA1, sigma, n)))
        n += 1
    e = []
    for _ in range(K):
        e.append(sample_poly_cbd(ETA1, _prf(ETA1, sigma, n)))
        n += 1
    s_hat = [ntt(p) for p in s]
    e_hat = [ntt(p) for p in e]
    t_hat = [_poly_add(x, y) for x, y in zip(_mat_vec_mul(a_hat, s_hat), e_hat)]
    ek = encode_vec(t_hat, 12) + rho
    dk = encode_vec(s_hat, 12)
    return ek, dk


def kpke_encrypt(ek: bytes, m: bytes, r: bytes) -> bytes:
    t_hat = decode_vec(ek[:POLY_BYTES * K], 12, K)
    rho = ek[POLY_BYTES * K:]
    a_hat = [[sample_ntt(rho, i, j) for j in range(K)] for i in range(K)]
    n = 0
    y = []
    for _ in range(K):
        y.append(sample_poly_cbd(ETA1, _prf(ETA1, r, n)))
        n += 1
    e1 = []
    for _ in range(K):
        e1.append(sample_poly_cbd(ETA2, _prf(ETA2, r, n)))
        n += 1
    e2 = sample_poly_cbd(ETA2, _prf(ETA2, r, n))
    y_hat = [ntt(p) for p in y]
    # u = A^T y + e1
    u = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _poly_add(acc, _basemul(a_hat[j][i], y_hat[j]))
        u.append(intt(acc))
    u = [_poly_add(x, y_) for x, y_ in zip(u, e1)]
    # v = t^T y + e2 + mu
    acc = [0] * N
    for i in range(K):
        acc = _poly_add(acc, _basemul(t_hat[i], y_hat[i]))
    v = intt(acc)
    mu = [decompress(b, 1) for b in byte_decode(1, m)]
    v = _poly_add(_poly_add(v, e2), mu)
    c1 = encode_vec([[compress(x, DU) for x in p] for p in u], DU)
    c2 = byte_encode(DV, [compress(x, DV) for x in v])
    return c1 + c2


def kpke_decrypt(dk: bytes, c: bytes) -> bytes:
    s_hat = decode_vec(dk[:POLY_BYTES * K], 12, K)
    c1 = c[:DU * K * 32]
    c2 = c[DU * K * 32:]
    u = [[decompress(x, DU) for x in p] for p in decode_vec(c1, DU, K)]
    v = [decompress(x, DV) for x in byte_decode(DV, c2)]
    u_hat = [ntt(p) for p in u]
    acc = [0] * N
    for i in range(K):
        acc = _poly_add(acc, _basemul(s_hat[i], u_hat[i]))
    w = _poly_sub(v, intt(acc))
    return byte_encode(1, [compress(x, 1) for x in w])


# ---------------------------------------------------------------- ML-KEM

def _h(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def _g(b: bytes) -> bytes:
    return hashlib.sha3_512(b).digest()


def _j(b: bytes) -> bytes:
    return hashlib.shake_256(b).digest(32)


def keygen(d: bytes | None = None) -> tuple[bytes, bytes]:
    """返回 (ek, dk)"""
    d = d if d is not None else os.urandom(32)
    return kpke_keygen(d)


def encaps(ek: bytes, m: bytes | None = None) -> tuple[bytes, bytes]:
    """返回 (shared_secret, ciphertext)"""
    m = m if m is not None else os.urandom(32)
    g = _g(m + _h(ek))
    key, r = g[:32], g[32:]
    c = kpke_encrypt(ek, m, r)
    return key, c


def decaps(dk: bytes, c: bytes, ek: bytes | None = None) -> bytes:
    m = kpke_decrypt(dk, c)
    if ek is None:
        # 从 dk 无法推出 ek(ML-KEM 的 dk 内包含 ek 版本才可); 调用方应传 ek
        raise ValueError("ek required")
    g = _g(m + _h(ek))
    key, r = g[:32], g[32:]
    c2 = kpke_encrypt(ek, m, r)
    if c2 != c:
        # 隐式拒绝: 需要 z, 从 dk 尾部取(本实现 dk = kpke_dk || ek || z)
        z = dk[DK_BYTES + EK_BYTES:]
        if z:
            return _j(z + c)
        raise ValueError("invalid ciphertext and no z available")
    return key


def keygen_full() -> tuple[bytes, bytes, bytes]:
    """返回 (ek, dk_ext, z) — dk_ext = kpke_dk || ek || z (FIPS 203 的 dk 格式)"""
    d = os.urandom(32)
    z = os.urandom(32)
    ek, dk = kpke_keygen(d)
    return ek, dk + ek + z, z
