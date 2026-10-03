# -*- coding: utf-8 -*-
"""多版本 profile 回归测试(不需要抓包数据, 随时可跑)。

覆盖:
  * profile 注册表 / 版本号解析 / 旧模块级常量兼容
  * Session(chrome_version=...) 切换版本, 且 UA / sec-ch-ua / 高熵 hint 跟着变
  * 两个版本的 ClientHello JA4 前缀都能对上真机实测值
  * HEADERS 帧的 PRIORITY 前缀(2026-10 实抓修正)

    python -m pytest tests/test_profiles.py -v
"""

from __future__ import annotations

import os
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from chrome_fp import (  # noqa: E402
    DEFAULT_VERSION, PROFILES, Session, build_client_hello, get_profile, ja4_from_hello, spec,
)

# 真机实测值(本机 Windows x64 Stable)
REAL = {
    "153": {
        "version": "153.0.8010.48",
        "ja4_prefix": "t13d1517h2_8daaf6152771",
        "sec_ch_ua": '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
        "ua": "Chrome/153.0.0.0",
    },
    "154": {
        "version": "154.0.8037.98",
        "ja4_prefix": "t13d1517h2_8daaf6152771",
        "sec_ch_ua": '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"',
        "ua": "Chrome/154.0.0.0",
    },
}


class FakeTls:
    """够 Http2Connection 用的假 TLS 通道, 只记录写出的字节。"""

    def __init__(self):
        self.sent = bytearray()

    def send_app(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv_app(self, n: int = 65536) -> bytes:   # pragma: no cover - 测试里用不到
        return b""


class TestRegistry(unittest.TestCase):
    def test_profiles_registered(self):
        self.assertEqual(set(PROFILES), {"153", "154"})
        self.assertEqual(DEFAULT_VERSION, "154")
        self.assertIs(get_profile(None), PROFILES[DEFAULT_VERSION])

    def test_version_string_parsing(self):
        self.assertIs(get_profile("154"), PROFILES["154"])
        self.assertIs(get_profile("154.0.8037.98"), PROFILES["154"])
        self.assertIs(get_profile("153"), PROFILES["153"])
        self.assertIs(get_profile(PROFILES["153"]), PROFILES["153"])
        with self.assertRaises(ValueError):
            get_profile("999")

    def test_legacy_module_constants(self):
        """旧代码里的 spec.CHROME_VERSION / spec.DEFAULT_USER_AGENT 等必须继续可用。"""
        # 模块级常量反映"当前生效 profile"; 别的用例(或用户建 153 Session)会切走,
        # 所以这里显式切回默认版本再断言 —— 否则用例顺序一变就假失败。
        spec.activate(DEFAULT_VERSION)
        self.assertEqual(spec.CHROME_VERSION, REAL[DEFAULT_VERSION]["version"])
        self.assertIn(REAL[DEFAULT_VERSION]["ua"], spec.DEFAULT_USER_AGENT)
        self.assertEqual(len(spec.CIPHER_SUITES), 15)
        self.assertEqual(spec.NUM_EXT_SLOTS, len(spec.EXT_TABLE))
        self.assertEqual(len(spec.TRUST_ANCHOR_IDS), 28)
        self.assertIsInstance(spec.SUPPORTED_DESTS, tuple)
        self.assertTrue(spec.HIGH_ENTROPY_HINTS)
        self.assertIn("sec-ch-ua", spec.LOW_ENTROPY_HINTS)

    def test_tls_wire_format_same_across_versions(self):
        """153→154 的 TLS 线格式实测一致: 只有版本字符串/UA 品牌不一样。"""
        a, b = get_profile("153"), get_profile("154")
        self.assertEqual(a.cipher_suites, b.cipher_suites)
        self.assertEqual(a.supported_groups, b.supported_groups)
        self.assertEqual(a.signature_algorithms, b.signature_algorithms)
        self.assertEqual(sorted(a.active_exts), sorted(b.active_exts))
        self.assertEqual(a.trust_anchor_ids, b.trust_anchor_ids)
        self.assertEqual(a.h2_settings, b.h2_settings)
        self.assertEqual(a.h2_window_update_increment, b.h2_window_update_increment)
        self.assertNotEqual(a.chrome_version, b.chrome_version)
        self.assertNotEqual(a.default_headers["sec-ch-ua"], b.default_headers["sec-ch-ua"])


class TestProfiles(unittest.TestCase):
    def test_ja4_matches_real_chrome(self):
        for name, want in REAL.items():
            with self.subTest(version=name):
                spec.activate(name)
                try:
                    ch = build_client_hello("example.com")
                    self.assertTrue(ja4_from_hello(ch.record).startswith(want["ja4_prefix"]))
                finally:
                    spec.activate(DEFAULT_VERSION)

    def test_session_switches_version(self):
        s154 = Session(chrome_version="154")
        self.assertEqual(s154.profile.name, "154")
        self.assertIn(REAL["154"]["ua"], s154.user_agent)
        self.assertEqual(s154.client_hint_values["sec-ch-ua"], REAL["154"]["sec_ch_ua"])

        s153 = Session(chrome_version="153")
        self.assertEqual(s153.profile.name, "153")
        self.assertIn(REAL["153"]["ua"], s153.user_agent)
        self.assertEqual(s153.client_hint_values["sec-ch-ua"], REAL["153"]["sec_ch_ua"])
        # 用完切回默认, 免得影响同进程后面的用例(模块级常量跟着"当前 profile"走)
        spec.activate(DEFAULT_VERSION)

    def test_default_session_is_latest(self):
        self.assertEqual(Session().profile.name, DEFAULT_VERSION)

    def test_client_hint_values_override_still_wins(self):
        s = Session(chrome_version="154", client_hint_values={"device-memory": "4"})
        self.assertEqual(s.client_hint_values["device-memory"], "4")

    def test_bad_version_rejected(self):
        with self.assertRaises(ValueError):
            Session(chrome_version="999")


class TestH2PriorityPrefix(unittest.TestCase):
    """真机实测: HEADERS 带 PRIORITY 标志, weight = urgency 查表(256/220/147)。"""

    def test_urgency_mapping(self):
        self.assertEqual(spec.h2_priority_prefix("u=0, i")["weight"], 256)
        self.assertEqual(spec.h2_priority_prefix("u=1, i")["weight"], 220)
        self.assertEqual(spec.h2_priority_prefix("u=1")["weight"], 220)
        self.assertEqual(spec.h2_priority_prefix("i")["weight"], 147)      # 默认 u=3
        self.assertIsNone(spec.h2_priority_prefix(None))
        self.assertIsNone(spec.h2_priority_prefix(""))
        for hdr in ("u=0, i", "u=1, i", "i"):
            p = spec.h2_priority_prefix(hdr)
            self.assertTrue(p["exclusive"])
            self.assertEqual(p["depends_on"], 0)

    def test_headers_frame_carries_priority_prefix(self):
        from chrome_fp.http2 import FLAG_PRIORITY, H2Connection  # noqa: PLC0415

        tls = FakeTls()
        conn = H2Connection(tls)
        conn.send_headers(1, [(":method", "GET"), ("priority", "u=1, i")],
                          end_stream=True,
                          priority=spec.h2_priority_prefix("u=1, i"))
        blob = bytes(tls.sent)
        # frame header: len(3) type(1) flags(1) stream(4)
        length = int.from_bytes(blob[0:3], "big")
        ftype, flags = blob[3], blob[4]
        stream = int.from_bytes(blob[5:9], "big")
        self.assertEqual(ftype, 0x1)
        self.assertEqual(stream, 1)
        self.assertTrue(flags & FLAG_PRIORITY, "HEADERS 必须带 PRIORITY 标志(真机实测 0x25)")
        self.assertTrue(flags & 0x1)          # END_STREAM
        self.assertTrue(flags & 0x4)          # END_HEADERS
        prefix = blob[9:14]
        self.assertEqual(length, len(blob) - 9, "帧长应等于剩余字节数")
        self.assertEqual(int.from_bytes(prefix[0:4], "big"), 0x80000000)   # E=1, dep=0
        self.assertEqual(prefix[4], 220 - 1)                              # weight-1 on the wire


if __name__ == "__main__":
    unittest.main(verbosity=2)
