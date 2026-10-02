"""HPACK 编码必须与真 Chrome 逐字节一致(拿抓包的原始 HEADERS 载荷当基准)。

解码后头一样 ≠ 编码后字节一样。这里把抓包里 Chrome 发的请求头**解出来**,
再用本库的编码器**重新编码**, 要求和 Chrome 当时发出去的字节完全相同。
"""

from __future__ import annotations

import glob
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import hpack  # noqa: E402

from chrome_fp.hpack_chromium import (  # noqa: E402
    ChromiumHpackEncoder,
    _encode_int,
    _encode_string,
    huffman_encode,
)

CAPTURE = os.path.join(ROOT, "capture", "chrome153")


def parse_frames(data: bytes):
    if data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        data = data[len(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):]
    out, p = [], 0
    while p + 9 <= len(data):
        ln = int.from_bytes(data[p:p + 3], "big")
        typ, flags = data[p + 3], data[p + 4]
        sid = int.from_bytes(data[p + 5:p + 9], "big") & 0x7FFFFFFF
        if p + 9 + ln > len(data):
            break
        out.append((typ, flags, sid, data[p + 9:p + 9 + ln]))
        p += 9 + ln
    return out


def chrome_first_request_blocks():
    """-> [(连接名, 该连接第几个请求, 头列表, 原始 HPACK 字节)]"""
    out = []
    for path in sorted(glob.glob(os.path.join(CAPTURE, "streams", "*_c2s.h2"))):
        dec = hpack.Decoder()
        dec.max_allowed_table_size = 65536
        blocks: dict[int, list] = {}
        n = 0
        for typ, flags, sid, payload in parse_frames(open(path, "rb").read()):
            if typ not in (1, 9):
                continue
            blk = payload
            if typ == 1:
                if flags & 0x8:
                    blk = blk[1:len(blk) - 1 - blk[0]]
                if flags & 0x20:
                    blk = blk[5:]
                blocks[sid] = []
            blocks.setdefault(sid, []).append(blk)
            if not flags & 0x4:
                continue
            raw = b"".join(blocks.pop(sid))
            try:
                items = dec.decode(raw)
            except Exception:  # noqa: BLE001
                continue
            n += 1
            headers = [(k.decode() if isinstance(k, bytes) else k,
                        v.decode() if isinstance(v, bytes) else v) for k, v in items]
            if not any(k == ":status" for k, _ in headers):
                out.append((os.path.basename(path), n, headers, raw))
    return out


class TestHuffman(unittest.TestCase):
    def test_tie_prefers_raw(self):
        """/?n=0 的 Huffman 长度和原始一样 -> Chromium 用原始字节(抓包实证)"""
        raw = b"/?n=0"
        self.assertEqual(len(huffman_encode(raw)), len(raw))
        self.assertEqual(_encode_string("/?n=0"), b"\x05/?n=0")

    def test_shorter_uses_huffman(self):
        """能压短就用 Huffman"""
        txt = "https://local.test:8443/?n=0"
        self.assertLess(len(huffman_encode(txt.encode())), len(txt))
        self.assertTrue(_encode_string(txt)[0] & 0x80)

    def test_integer_prefix(self):
        self.assertEqual(_encode_int(2, 7, 0x80), b"\x82")
        self.assertEqual(_encode_int(61, 7, 0x80), b"\xbd")
        # 7 位前缀最大 127: 126 仍在一个字节里, 127 才需要续字节
        self.assertEqual(_encode_int(126, 7, 0x80), b"\xfe")
        self.assertEqual(_encode_int(127, 7, 0x80), b"\xff\x00")


class TestAgainstRealChrome(unittest.TestCase):
    @unittest.skipUnless(os.path.isdir(os.path.join(CAPTURE, "streams")),
                         "缺少 capture/chrome153 抓包")
    def test_first_request_on_each_connection_re_encodes_identically(self):
        """空动态表起步的第一个请求: 本库编码器必须复现 Chrome 的原始字节"""
        cases = [c for c in chrome_first_request_blocks() if c[1] == 1]
        self.assertGreaterEqual(len(cases), 3, "抓包里应有多个连接的首个请求")
        checked = 0
        for conn, _n, headers, raw in cases:
            enc = ChromiumHpackEncoder()
            got = enc.encode(headers)
            self.assertEqual(got, raw,
                             f"{conn} 的 HPACK 编码与真 Chrome 不一致\n"
                             f"  Chrome: {raw.hex()}\n  本库  : {got.hex()}")
            checked += 1
        self.assertGreaterEqual(checked, 3)

    @unittest.skipUnless(os.path.isdir(os.path.join(CAPTURE, "streams")),
                         "缺少 capture/chrome153 抓包")
    def test_without_indexing_names(self):
        """回归: :method(非静态命中) / :path 用 0x04; :authority 用 0x41 增量索引

        这是从 100+ 个真实请求里统计出来的(见 tools/_tally.py)。
        """
        enc = ChromiumHpackEncoder()
        self.assertEqual(enc.encode([(":path", "/style.css")])[0] & 0xF0, 0x00)
        enc = ChromiumHpackEncoder()
        self.assertEqual(enc.encode([(":method", "OPTIONS")])[0] & 0xF0, 0x00)
        enc = ChromiumHpackEncoder()
        self.assertEqual(enc.encode([(":authority", "local.test:1")])[0] & 0xC0, 0x40)
        enc = ChromiumHpackEncoder()
        self.assertEqual(enc.encode([("cookie", "a=b")])[0] & 0xC0, 0x40)
        # 静态精确命中必须是索引表示
        self.assertEqual(ChromiumHpackEncoder().encode([(":method", "GET")]), b"\x82")
        self.assertEqual(ChromiumHpackEncoder().encode([(":scheme", "https")]), b"\x87")
        self.assertEqual(ChromiumHpackEncoder().encode([(":path", "/")]), b"\x84")

    def test_dynamic_table_reuse_across_blocks(self):
        """第二个头块应复用第一个插入的动态表项(索引表示)"""
        enc = ChromiumHpackEncoder()
        first = enc.encode([(":authority", "a.test"), ("x-a", "1")])
        second = enc.encode([(":authority", "a.test")])
        self.assertEqual(len(first) > 0, True)
        self.assertEqual(second[0] & 0x80, 0x80, "第二次应命中动态表索引")

    @unittest.skipUnless(os.path.isdir(os.path.join(CAPTURE, "streams")),
                         "缺少 capture/chrome153 抓包")
    def test_dynamic_table_state_matches(self):
        """连续两个请求: 第二个请求依赖第一个留下的动态表, 也要字节一致"""
        for path in sorted(glob.glob(os.path.join(CAPTURE, "streams", "*_c2s.h2"))):
            data = open(path, "rb").read()
            frames = [(t, f, s, p) for t, f, s, p in parse_frames(data) if t in (1, 9)]
            if len([1 for t, f, _s, _p in frames if t == 1]) < 2:
                continue
            dec = hpack.Decoder()
            dec.max_allowed_table_size = 65536
            enc = ChromiumHpackEncoder()
            blocks: dict[int, list] = {}
            seq = []
            for typ, flags, sid, payload in frames:
                blk = payload
                if typ == 1:
                    if flags & 0x8:
                        blk = blk[1:len(blk) - 1 - blk[0]]
                    if flags & 0x20:
                        blk = blk[5:]
                    blocks[sid] = []
                blocks.setdefault(sid, []).append(blk)
                if not flags & 0x4:
                    continue
                raw = b"".join(blocks.pop(sid))
                try:
                    items = dec.decode(raw)
                except Exception:  # noqa: BLE001
                    continue
                headers = [(k.decode() if isinstance(k, bytes) else k,
                            v.decode() if isinstance(v, bytes) else v) for k, v in items]
                if any(k == ":status" for k, _ in headers):
                    continue
                seq.append((headers, raw))
            if len(seq) < 2:
                continue
            for i, (headers, raw) in enumerate(seq):
                got = enc.encode(headers)
                self.assertEqual(got, raw,
                                 f"{os.path.basename(path)} 第{i + 1}个请求不一致\n"
                                 f"  Chrome: {raw.hex()}\n  本库  : {got.hex()}")
            return
        self.skipTest("没有连接发了两个以上请求")


if __name__ == "__main__":
    unittest.main(verbosity=2)
