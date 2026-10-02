"""TLS 层未实现功能的端到端测试(自带本地服务器, 不依赖外网)。

覆盖:
  * HelloRetryRequest(HRR) —— 服务器要求换 key_share 组 / 要 cookie 时的二次握手
  * TLS 1.2 CBC 密码套件
  * 客户端证书(mTLS)
"""

from __future__ import annotations

import os
import socket
import ssl
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def make_cert(dirpath: str, cn: str = "127.0.0.1", rsa_bits: int | None = None) -> tuple[str, str, str]:
    """自签证书, 返回 (cert, key, ca)。ca 就是 cert 本身(自签)。

    rsa_bits 给了就生成 RSA 证书 —— ECDHE-RSA-* / RSA-* 套件必须配 RSA 证书,
    否则 OpenSSL 直接 NO_SHARED_CIPHER。
    """
    import datetime as dt
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits) if rsa_bits \
        else ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName(cn), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(dirpath, "cert.pem")
    key_path = os.path.join(dirpath, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path, cert_path


def make_client_cert(dirpath: str) -> tuple[str, str]:
    """客户端证书(要带 clientAuth EKU, 否则服务端会拒)"""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "chrome-fp-test-client")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(dirpath, "client.pem")
    key_path = os.path.join(dirpath, "client.key")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path


class TLSServer:
    """最小 TLS 服务器: 收一个 HTTP 请求, 回一条固定响应。"""

    def __init__(self, ctx: ssl.SSLContext, require_client_cert: bool = False):
        self.ctx = ctx
        self.require_client_cert = require_client_cert
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.client_cert_cn: str | None = None
        self.error: str | None = None
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=3)

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, raw: socket.socket):
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except Exception as e:  # noqa: BLE001
            self.error = f"{type(e).__name__}: {e}"
            try:
                raw.close()
            except OSError:
                pass
            return
        try:
            peer = conn.getpeercert()
            if peer:
                self.client_cert_cn = next(
                    (v for t in peer.get("subject", ()) for k, v in t if k == "commonName"), None)
            conn.settimeout(5)
            conn.recv(65536)
            body = b"hello-from-tls-server"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            conn.close()
        except Exception as e:  # noqa: BLE001
            self.error = f"{type(e).__name__}: {e}"
            try:
                conn.close()
            except OSError:
                pass


class TestHelloRetryRequest(unittest.TestCase):
    """服务端 set_ecdh_curve('prime256v1') 会强制 HRR(客户端只发了 x25519 系的 key_share)"""

    def _server(self, tmp, extra=None):
        cert, key, _ = make_cert(tmp)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.set_ecdh_curve("prime256v1")      # 只留 P-256 -> 必须 HRR
        if extra:
            extra(ctx)
        return ctx

    def test_hrr_handshake_succeeds(self):
        from chrome_fp import Session
        from chrome_fp.hello import build_client_hello
        from chrome_fp import client as fp_client

        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._server(tmp)
            with TLSServer(ctx) as srv:
                with Session(verify=False, timeout=10) as s:
                    r = s.get(f"https://127.0.0.1:{srv.port}/")
                self.assertEqual(srv.error, None, f"服务端报错: {srv.error}")
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.text, "hello-from-tls-server")
                self.assertEqual(r.tls.get("tls_version"), "1.3")

    def test_hrr_client_hello2_shape(self):
        """CH2 必须只保留服务器点名的组, 且复用 CH1 的 random/session_id/扩展顺序"""
        from chrome_fp.hello import build_client_hello, rebuild_for_hrr
        from chrome_fp.fingerprint import parse_client_hello

        ch1 = build_client_hello("example.com")
        ch2 = rebuild_for_hrr(ch1, 0x0017, cookie=b"\x01\x02\x03")
        i1, i2 = parse_client_hello(ch1.record), parse_client_hello(ch2.record)

        self.assertEqual(i2["random"], i1["random"], "random 必须复用")
        self.assertEqual(i2["session_id"], i1["session_id"], "session_id 必须复用")
        s1, s2 = set(i1["ext_types"]), set(i2["ext_types"])
        self.assertEqual(s2 - s1, {0x002C}, "相对 CH1 只能多出 cookie 扩展")
        self.assertEqual(s1 - s2, set(), "不能丢掉 CH1 的扩展")

        d = dict(i2["extensions"])
        self.assertIn(0x002C, d, "必须带上 cookie 扩展")
        self.assertEqual(d[0x002C], b"\x00\x03\x01\x02\x03", "cookie 编码")
        groups = [g for g in i2["key_shares"] if g["group"] == "secp256r1"]
        self.assertEqual(len(groups), 1, f"key_share 里应该只有 P-256: {i2['key_shares']}")
        # HRR 的 CH2 里 key_share 必须恰好一个真实组(不能带 GREASE key share)
        self.assertEqual(len(i2["key_shares"]), 1,
                         f"CH2 的 key_share 必须恰好一项: {i2['key_shares']}")
        self.assertEqual(i2["supported_groups"], i1["supported_groups"],
                         "supported_groups 必须和 CH1 完全一样")
        self.assertEqual(d[0x000A], dict(i1["extensions"])[0x000A])

    def test_hrr_missing_group_raises(self):
        from chrome_fp.hello import build_client_hello, rebuild_for_hrr
        from chrome_fp.fingerprint import parse_client_hello

        ch2 = rebuild_for_hrr(build_client_hello("a.test"), 0x0018)
        info = parse_client_hello(ch2.record)
        real = [k["group"] for k in info["key_shares"] if k["group"] != "0xcaca"]
        self.assertEqual(real, ["secp384r1"])


class TestTls12Cbc(unittest.TestCase):
    """只允许 CBC 套件的 TLS 1.2 服务器(ECDHE-RSA-AES128-SHA / AES256-SHA)"""

    def _run(self, cipher: str):
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            # CBC-SHA 套件都是 ECDHE-RSA-* / RSA-*, 必须用 RSA 证书
            cert, key, _ = make_cert(tmp, rsa_bits=2048)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(cipher)
            with TLSServer(ctx) as srv:
                with Session(verify=False, timeout=10) as s:
                    r = s.get(f"https://127.0.0.1:{srv.port}/")
                self.assertEqual(srv.error, None, f"服务端报错({cipher}): {srv.error}")
                return r

    def test_ecdhe_rsa_aes128_cbc_sha(self):
        r = self._run("ECDHE-RSA-AES128-SHA")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "hello-from-tls-server")
        self.assertEqual(r.tls.get("tls_version"), "1.2")

    def test_ecdhe_rsa_aes256_cbc_sha(self):
        r = self._run("ECDHE-RSA-AES256-SHA")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "hello-from-tls-server")

    def test_cbc_sha256_suites_not_offered(self):
        """Chrome 只提供 *_CBC_SHA(不是 _SHA256), 这是指纹要求, 不能为了兼容偷偷加进去"""
        from chrome_fp import spec

        self.assertNotIn(0xC023, spec.CIPHER_SUITES)   # ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        self.assertNotIn(0xC027, spec.CIPHER_SUITES)   # ECDHE_RSA_WITH_AES_128_CBC_SHA256
        for s in (0xC013, 0xC014, 0x002F, 0x0035):
            self.assertIn(s, spec.CIPHER_SUITES)


class TestClientCertificate(unittest.TestCase):
    """mTLS: 服务器要求客户端证书"""

    def _server(self, tmp, require: bool, optional: bool = False, client_ca: str | None = None):
        cert, key, _ = make_cert(tmp)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.verify_mode = (ssl.CERT_OPTIONAL if optional else ssl.CERT_REQUIRED) if require else ssl.CERT_NONE
        if require and client_ca:
            ctx.load_verify_locations(client_ca)   # 信任客户端那张自签证书
        return ctx

    def test_mtls_with_client_cert(self):
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            ccert, ckey = make_client_cert(tmp)
            ctx = self._server(tmp, require=True, client_ca=ccert)
            with TLSServer(ctx) as srv:
                with Session(verify=False, timeout=10) as s:
                    r = s.get(f"https://127.0.0.1:{srv.port}/", cert=(ccert, ckey))
                self.assertEqual(srv.error, None, f"服务端报错: {srv.error}")
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.text, "hello-from-tls-server")
                self.assertEqual(srv.client_cert_cn, "chrome-fp-test-client")

    def test_mtls_combined_pem(self):
        """requests 也支持把证书和私钥写在同一个 PEM 里"""
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            ccert, ckey = make_client_cert(tmp)
            combined = os.path.join(tmp, "combined.pem")
            with open(combined, "wb") as out:
                for p in (ccert, ckey):
                    with open(p, "rb") as f:
                        out.write(f.read())
            ctx = self._server(tmp, require=True, client_ca=ccert)
            with TLSServer(ctx) as srv:
                with Session(verify=False, timeout=10) as s:
                    r = s.get(f"https://127.0.0.1:{srv.port}/", cert=combined)
                self.assertEqual(r.status_code, 200)
                self.assertEqual(srv.client_cert_cn, "chrome-fp-test-client")

    def test_mtls_without_cert_fails_clearly(self):
        """服务器要证书而客户端没有 -> 必须失败。

        失败形态有两种(都是合理的): 服务器发 fatal alert(certificate_required),
        或者直接 RST 连接。这里两种都接受, alert 文案的确定性验证放在下面单独一个用例。
        """
        from chrome_fp import Session
        from chrome_fp.exceptions import RequestException

        with tempfile.TemporaryDirectory() as tmp:
            ccert, _ = make_client_cert(tmp)
            ctx = self._server(tmp, require=True, client_ca=ccert)
            with TLSServer(ctx) as srv:
                with Session(verify=False, timeout=10) as s:
                    with self.assertRaises(RequestException) as err:
                        s.get(f"https://127.0.0.1:{srv.port}/")
                msg = str(err.exception)
                if "certificate_required" in msg:
                    self.assertIn("fatal", msg)

    def test_alert_text_is_readable(self):
        """alert 数字要翻成人看得懂的名字(不然报错只有一串十六进制)"""
        from chrome_fp.tls13 import alert_text

        self.assertEqual(alert_text(b"\x02\x74"), "fatal certificate_required(116)")
        self.assertEqual(alert_text(b"\x02\x28"), "fatal handshake_failure(40)")
        self.assertEqual(alert_text(b"\x01\x00"), "warning close_notify(0)")
        self.assertEqual(alert_text(b"\x02\x2f"), "fatal illegal_parameter(47)")

    def test_optional_client_cert_ok_without_cert(self):
        from chrome_fp import Session

        with tempfile.TemporaryDirectory() as tmp:
            ccert, _ = make_client_cert(tmp)
            ctx = self._server(tmp, require=True, optional=True, client_ca=ccert)
            with TLSServer(ctx) as srv:
                with Session(verify=False, timeout=10) as s:
                    r = s.get(f"https://127.0.0.1:{srv.port}/")
                self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
