"""把库的输出钉死在**真 Chrome 153 抓包**上(离线回归测试)。

数据来自本机真 Chrome 153.0.8010.48 的抓包(capture/chrome153/):
  hello/*.bin      真 Chrome 发出的 ClientHello 原始 record 字节
  h2_client.json   从解密后的 HTTP/2 帧解出的请求头(顺序+取值)

没有抓包数据时这些用例会自动跳过。

    python -m unittest tests.test_chrome153_fingerprint -v
"""

from __future__ import annotations

import glob
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from chrome_fp import Session, build_client_hello, ja4_from_hello   # noqa: E402
from chrome_fp import spec                                          # noqa: E402
from chrome_fp.fingerprint import parse_client_hello                # noqa: E402

CAPTURE = os.path.join(ROOT, "capture", "chrome153")
HELLO_GLOB = os.path.join(CAPTURE, "hello", "*.bin")
H2_JSON = os.path.join(CAPTURE, "h2_client.json")

GREASE = {0x0A0A + 0x1010 * i for i in range(16)}

CHROME_JA4_PREFIX = "t13d1517h2_8daaf6152771"


def load_hellos() -> list[tuple[str, dict]]:
    out = []
    for f in sorted(glob.glob(HELLO_GLOB)):
        with open(f, "rb") as fh:
            out.append((os.path.basename(f), parse_client_hello(fh.read())))
    return out


def no_grease_u16(blob: bytes, prefix: int = 2) -> list[int]:
    if not blob:
        return []
    n = int.from_bytes(blob[:2], "big") if prefix == 2 else blob[0]
    return [int.from_bytes(blob[prefix + i:prefix + i + 2], "big")
            for i in range(0, n, 2)
            if int.from_bytes(blob[prefix + i:prefix + i + 2], "big") not in GREASE]


@unittest.skipUnless(glob.glob(HELLO_GLOB), "缺少 capture/chrome153/hello/ 抓包数据")
class TestClientHelloVsChrome153(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hellos = load_hellos()

    def test_samples_present(self):
        self.assertGreaterEqual(len(self.hellos), 5)

    def test_ja4_prefix_matches_chrome(self):
        """真 Chrome 每一条样本的 JA4 前两段都必须等于库的目标值"""
        for name, info in self.hellos:
            with open(os.path.join(CAPTURE, "hello", name), "rb") as fh:
                ja4 = ja4_from_hello(fh.read())
            self.assertTrue(ja4.startswith(CHROME_JA4_PREFIX + "_"),
                            f"{name}: 抓到的是 {ja4}")
        lib = build_client_hello("local.test")
        self.assertTrue(ja4_from_hello(lib.record).startswith(CHROME_JA4_PREFIX + "_"))

    def test_cipher_suites(self):
        for name, info in self.hellos:
            got = [c for c in info["ciphers"] if int(c, 16) not in GREASE]
            self.assertEqual([f"{c:04x}" for c in spec.CIPHER_SUITES], got, name)

    def test_extension_set_and_count(self):
        want = sorted(spec.ACTIVE_EXTS)
        for name, info in self.hellos:
            exts = info["ext_types"]
            # 17 个真实扩展 + 2 个 GREASE(首尾各一)
            self.assertEqual(len(exts), len(spec.ACTIVE_EXTS) + 2, name)
            self.assertEqual(sorted(e for e in exts if e not in GREASE), want, name)
            self.assertIn(exts[0], GREASE, f"{name}: 第一个扩展必须是 GREASE")
            self.assertIn(exts[-1], GREASE, f"{name}: 最后一个扩展必须是 GREASE")

    def test_trust_anchors_28(self):
        want = sorted(spec.TRUST_ANCHOR_IDS)
        self.assertEqual(len(want), 28)
        for name, info in self.hellos:
            self.assertEqual(info.get("trust_anchor_count"), 28, name)
            self.assertEqual(info.get("trust_anchor_set"), want, name)

    def test_signature_algorithms_and_groups(self):
        d0 = dict(self.hellos[0][1]["extensions"])
        self.assertEqual(no_grease_u16(d0[0x000D]), spec.SIGNATURE_ALGORITHMS)
        self.assertEqual(len(no_grease_u16(d0[0x000D])), 11)
        self.assertEqual(set(no_grease_u16(d0[0x000A])), {0x11EC, 0x001D, 0x0017, 0x0018})
        self.assertEqual(set(no_grease_u16(d0[0x002B], 1)), {0x0304, 0x0303})

    def test_ech_grease_and_key_share_shape(self):
        for name, info in self.hellos:
            d = dict(info["extensions"])
            self.assertIn(len(d[0xFE0D]), {186, 218, 250, 282}, name)
            ks = d[0x0033]
            total = int.from_bytes(ks[0:2], "big")
            groups, q = [], 2
            while q < 2 + total:
                g = int.from_bytes(ks[q:q + 2], "big")
                kl = int.from_bytes(ks[q + 2:q + 4], "big")
                groups.append((g, kl))
                q += 4 + kl
            self.assertEqual([g for g, _ in groups if g not in GREASE],
                             [0x11EC, 0x001D])
            self.assertEqual(dict(groups).get(0x11EC), 1216, name)
            self.assertEqual(dict(groups).get(0x001D), 32, name)

    def test_key_share_private_matches_public(self):
        """回归: 每个 key_share 份额的公开字节必须和它自己的私钥配对。

        曾经踩过: X25519MLKEM768 混合份额里的 x25519 公钥取了**另一个** key share 的
        私钥对应值, 结果服务器封装出来的共享密钥和我们的私钥不匹配 —— 表现就是
        TLS 1.3 解密直接 InvalidTag(而且只在服务器选混合组时才复现)。
        """
        from chrome_fp.hello import build_client_hello
        from chrome_fp.fingerprint import parse_client_hello

        ch = build_client_hello("example.com")
        d = dict(parse_client_hello(ch.record)["extensions"])
        ks = d[0x0033]
        total = int.from_bytes(ks[0:2], "big")
        entries, q = {}, 2
        while q < 2 + total:
            g = int.from_bytes(ks[q:q + 2], "big")
            kl = int.from_bytes(ks[q + 2:q + 4], "big")
            entries[g] = ks[q + 4:q + 4 + kl]
            q += 4 + kl

        hybrid_pub = ch.key_shares[0x11EC].public_key().public_bytes_raw()
        self.assertEqual(entries[0x11EC][-32:], hybrid_pub,
                         "混合份额尾部的 x25519 公钥必须来自混合份额自己的私钥")
        x25519_pub = ch.key_shares[0x001D].public_key().public_bytes_raw()
        self.assertEqual(entries[0x001D], x25519_pub, "独立 x25519 份额必须自洽")
        # 真 Chrome 用的就是两把独立的 x25519 密钥(抓包实测两份份额尾 32B 不同)
        self.assertNotEqual(hybrid_pub, x25519_pub)

    def test_mlkem_ciphertext_length(self):
        """X25519MLKEM768 份额 = ML-KEM 公钥(1184B) + x25519 公钥(32B)"""
        from chrome_fp.hello import build_client_hello
        from chrome_fp.fingerprint import parse_client_hello

        ch = build_client_hello("example.com")
        d = dict(parse_client_hello(ch.record)["extensions"])
        ks = d[0x0033]
        total = int.from_bytes(ks[0:2], "big")
        q, lens = 2, {}
        while q < 2 + total:
            g = int.from_bytes(ks[q:q + 2], "big")
            lens[g] = int.from_bytes(ks[q + 2:q + 4], "big")
            q += 4 + lens[g]
        self.assertEqual(lens[0x11EC], 1184 + 32)
        self.assertEqual(lens[0x001D], 32)

    def test_library_hello_matches_sample_size(self):
        """同 SNI 下, 去掉随机 ECH 载荷后的长度必须和真 Chrome 完全一致"""
        for name, info in self.hellos:
            sni = info.get("sni")
            if not sni:
                continue
            ech_len = len(dict(info["extensions"])[0xFE0D])
            base = info["record_len"] - ech_len
            lib = build_client_hello(sni)
            lib_ech = len(dict(parse_client_hello(lib.record)["extensions"])[0xFE0D])
            self.assertEqual(lib.record.__len__() - lib_ech, base,
                             f"{sni}: 去掉 ECH 后的 ClientHello 长度不一致")


@unittest.skipUnless(os.path.exists(H2_JSON), "缺少 capture/chrome153/h2_client.json")
class TestHttp2VsChrome153(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(H2_JSON, encoding="utf-8") as fh:
            cls.h2 = json.load(fh)

    def test_akamai_fingerprint(self):
        got = {c["akamai"] for c in self.h2.values()}
        self.assertEqual(got, {spec.AKAMAI_FINGERPRINT})

    def test_no_priority_frames(self):
        for idx, c in self.h2.items():
            self.assertEqual(c["priority"], [], f"tunnel {idx} 出现了 PRIORITY 帧")
        self.assertEqual(spec.H2_SETTINGS,
                         [(0x1, 65536), (0x2, 0), (0x4, 6291456), (0x6, 262144)])
        self.assertEqual(spec.H2_WINDOW_UPDATE_INCREMENT, 15663105)

    def test_pseudo_header_order(self):
        for idx, c in self.h2.items():
            self.assertEqual(c["pseudo_order"], "m,a,s,p", f"tunnel {idx}")

    def _chrome_requests(self):
        for c in self.h2.values():
            for sid, r in c["requests"].items():
                h = dict(r["headers"])
                if not h.get(":authority", "").startswith(("local.test", "local2.test")):
                    continue          # 跳过 Chrome 自身的后台流量
                yield h

    def test_request_headers_match_capture(self):
        """用库重新构造同样的请求, 头顺序和取值必须与真 Chrome 完全一致"""
        checked = 0
        for h in self._chrome_requests():
            dest = h["sec-fetch-dest"]
            mode = h["sec-fetch-mode"]
            method = h[":method"]
            path = h[":path"]
            body_len = int(h.get("content-length") or 0)
            extra = {k: h[k] for k in ("content-type", "access-control-request-method",
                                       "access-control-request-headers") if k in h}
            kwargs = {"headers": extra}
            if "referer" in h:
                kwargs["referer"] = h["referer"]
            if "origin" in h:
                kwargs["origin"] = h["origin"]
            if body_len:
                kwargs["data"] = b"x" * body_len

            # sec-fetch-site 取决于"发起方页面"和"目标"的关系, 库无法自己推断,
            # 所以这里按抓到的真值显式传入(这是设计上就要用户提供的上下文)。
            s = Session(mode=mode, dest=dest, sec_fetch_site=h.get("sec-fetch-site"))
            p = s.prepare_request(method, f"https://local.test{path}", **kwargs)
            got = [(k, v) for k, v in p._h2_headers if not k.startswith(":")]
            want = [(k, v) for k, v in h.items() if not k.startswith(":")]

            self.assertEqual([k for k, _ in got], [k for k, _ in want],
                             f"{method} {path}: 头顺序不一致")
            for (gk, gv), (wk, wv) in zip(got, want):
                # image 的 priority 取决于元素可见性(<img>="i", favicon="u=1, i"),
                # 这里容忍两种真值, 其余必须逐字节相同
                if dest == "image" and wk == "priority":
                    self.assertIn(gv, ("i", "u=1, i"))
                    continue
                self.assertEqual(gv, wv, f"{method} {path}: {wk} 取值不一致")
            checked += 1
        self.assertGreaterEqual(checked, 8, "没有比对到足够的请求")


if __name__ == "__main__":
    unittest.main(verbosity=2)
