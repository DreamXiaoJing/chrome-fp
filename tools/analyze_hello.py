#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze_hello —— 解析 tap_probe 抓到的真机 ClientHello / HTTP2, 并与 spec.py 逐项对比。

用法:
    python tools/analyze_hello.py --dir capture/chrome154            # 只看抓到的东西
    python tools/analyze_hello.py --dir capture/chrome154 --diff     # 与当前 spec.py(153) 对比
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GREASE = {0x0A0A + 0x1010 * i for i in range(16)}

EXT_NAMES = {
    0x0000: "server_name", 0x0001: "max_fragment_length", 0x0005: "status_request",
    0x000A: "supported_groups", 0x000B: "ec_point_formats", 0x000D: "signature_algorithms",
    0x0010: "alpn", 0x0012: "signed_certificate_timestamp", 0x0013: "client_cert_type",
    0x0014: "server_cert_type", 0x0015: "padding", 0x0017: "extended_master_secret",
    0x001B: "compress_certificate", 0x0023: "session_ticket", 0x0029: "pre_shared_key",
    0x002A: "early_data", 0x002B: "supported_versions", 0x002C: "cookie",
    0x002D: "psk_key_exchange_modes", 0x002F: "certificate_authorities",
    0x0033: "key_share", 0x0039: "quic_transport_parameters", 0x4469: "application_settings_old",
    0x44CD: "application_settings", 0x754F: "channel_id", 0xCA34: "trust_anchors",
    0xFE0D: "encrypted_client_hello", 0xFF01: "renegotiate",
}

GROUP_NAMES = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519",
    0x001E: "x448", 0x11EC: "X25519MLKEM768", 0x6399: "X25519Kyber768Draft00",
    0x4588: "MLKEM768", 0x11EB: "MLKEM1024",
}


def name_of(ext_id: int) -> str:
    if ext_id in GREASE:
        return f"GREASE(0x{ext_id:04x})"
    return EXT_NAMES.get(ext_id, f"0x{ext_id:04x}")


# ------------------------------------------------------------------ 解析
def parse_client_hello(raw: bytes) -> dict:
    out: dict = {"raw_len": len(raw)}
    if len(raw) < 5 or raw[0] != 0x16:
        raise ValueError("不是 TLS handshake record")
    rec_len = int.from_bytes(raw[3:5], "big")
    body = raw[5:5 + rec_len]
    out["record_version"] = raw[1:3].hex()
    out["record_len"] = rec_len
    if body[0] != 0x01:
        raise ValueError(f"不是 ClientHello: {body[0]}")
    hs_len = int.from_bytes(body[1:4], "big")
    b = body[4:4 + hs_len]
    i = 0
    out["legacy_version"] = b[i:i + 2].hex()
    i += 2
    out["random"] = b[i:i + 32].hex()
    i += 32
    sid_len = b[i]
    i += 1
    out["session_id_len"] = sid_len
    out["session_id"] = b[i:i + sid_len].hex()
    i += sid_len
    cs_len = int.from_bytes(b[i:i + 2], "big")
    i += 2
    ciphers = [int.from_bytes(b[i + 2 * k:i + 2 * k + 2], "big") for k in range(cs_len // 2)]
    i += cs_len
    out["ciphers"] = ciphers
    out["ciphers_no_grease"] = [c for c in ciphers if c not in GREASE]
    comp_len = b[i]
    i += 1
    out["compression"] = list(b[i:i + comp_len])
    i += comp_len
    ext_total = int.from_bytes(b[i:i + 2], "big")
    i += 2
    exts: list[tuple[int, bytes]] = []
    end = i + ext_total
    while i < end:
        et = int.from_bytes(b[i:i + 2], "big")
        el = int.from_bytes(b[i + 2:i + 4], "big")
        data = b[i + 4:i + 4 + el]
        exts.append((et, data))
        i += 4 + el

    out["extensions"] = [{"type": t, "name": name_of(t), "len": len(d)} for t, d in exts]
    out["ext_types"] = [t for t, _ in exts]
    out["ext_types_no_grease"] = [t for t, _ in exts if t not in GREASE]
    out["grease_ext_positions"] = [k for k, (t, _) in enumerate(exts) if t in GREASE]

    parsed: dict = {}
    for t, d in exts:
        if t == 0x000A:
            n = int.from_bytes(d[0:2], "big")
            parsed["supported_groups"] = [int.from_bytes(d[2 + 2 * k:4 + 2 * k], "big")
                                          for k in range(n // 2)]
        elif t == 0x000D:
            n = int.from_bytes(d[0:2], "big")
            parsed["signature_algorithms"] = [int.from_bytes(d[2 + 2 * k:4 + 2 * k], "big")
                                              for k in range(n // 2)]
        elif t == 0x002B:
            n = d[0]
            parsed["supported_versions"] = [int.from_bytes(d[1 + 2 * k:3 + 2 * k], "big")
                                            for k in range(n // 2)]
        elif t == 0x0033:
            n = int.from_bytes(d[0:2], "big")
            ks, k = [], 2
            for _ in range(0 if n == 0 else 99):
                if k + 4 > len(d):
                    break
                g = int.from_bytes(d[k:k + 2], "big")
                kl = int.from_bytes(d[k + 2:k + 4], "big")
                ks.append({"group": g, "name": GROUP_NAMES.get(g, hex(g)), "len": kl})
                k += 4 + kl
            parsed["key_share"] = ks
        elif t == 0x0010:
            n = int.from_bytes(d[0:2], "big")
            alpn, k = [], 2
            while k < 2 + n:
                ln = d[k]
                alpn.append(d[k + 1:k + 1 + ln].decode("latin1"))
                k += 1 + ln
            parsed["alpn"] = alpn
        elif t == 0x44CD:
            parsed["alps_raw"] = d.hex()
        elif t == 0xCA34:
            parsed["trust_anchors_raw_len"] = len(d)
            ids, k = [], 0
            # 结构: list_len(2) 之后是一串 [id_len(1)][id]
            if len(d) >= 2:
                total = int.from_bytes(d[0:2], "big")
                k = 2
                while k < 2 + total and k < len(d):
                    ln = d[k]
                    ids.append(d[k + 1:k + 1 + ln].hex())
                    k += 1 + ln
            parsed["trust_anchors"] = ids
        elif t == 0xFE0D:
            parsed["ech_raw_len"] = len(d)
            parsed["ech_type"] = d[0] if d else None
        elif t == 0x0018:
            parsed["sct"] = True
    out["parsed"] = parsed

    # ---- JA4 (FoxIO)
    def h12(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()[:12]

    ver = max((v for v in parsed.get("supported_versions", []) if v not in GREASE),
              default=0x0303)
    ja4_a = (f"t{'13' if ver == 0x0304 else '12'}"
             f"{'d' if any(t == 0x0000 for t, _ in exts) else 'i'}"
             f"{min(len(out['ciphers_no_grease']), 99):02d}"
             f"{min(len(out['ext_types_no_grease']), 99):02d}"
             f"{parsed.get('alpn', [''])[0]}")
    cs_sorted = ",".join(f"{c:04x}" for c in sorted(out["ciphers_no_grease"]))
    ext_sorted = [t for t in sorted(out["ext_types_no_grease"]) if t not in (0x0000, 0x0010)]
    sigs = [f"{s:04x}" for s in parsed.get("signature_algorithms", [])]
    ext_str = ",".join(f"{t:04x}" for t in ext_sorted) + "_" + ",".join(sigs)
    sigs_ng = [f"{s:04x}" for s in parsed.get("signature_algorithms", []) if s not in GREASE]
    ext_str_ng = ",".join(f"{t:04x}" for t in ext_sorted) + "_" + ",".join(sigs_ng)
    out["ja4"] = f"{ja4_a}_{h12(cs_sorted)}_{h12(ext_str)}"
    out["ja4_c_ignore_grease"] = h12(ext_str_ng)
    out["ja4_r"] = f"{cs_sorted}_{ext_str}"
    out["ja4_a"] = ja4_a
    out["ja4_b"] = h12(cs_sorted)
    return out


def summarize(hellos: list[dict]) -> dict:
    def uniq(key, fn):
        c = Counter(json.dumps(fn(h), sort_keys=True) for h in hellos)
        return {"distinct": len(c), "values": [json.loads(k) for k, _ in c.most_common(3)],
                "counts": [v for _, v in c.most_common(3)]}

    return {
        "samples": len(hellos),
        "ja4": uniq("ja4", lambda h: h["ja4"]),
        "ja4_a": uniq("ja4_a", lambda h: h["ja4_a"]),
        "ja4_b": uniq("ja4_b", lambda h: h["ja4_b"]),
        "ja4_c": uniq("ja4_c", lambda h: h["ja4_c_ignore_grease"]),
        "ciphers": uniq("ciphers", lambda h: h["ciphers"]),
        "ciphers_no_grease": uniq("cng", lambda h: h["ciphers_no_grease"]),
        "ext_order": uniq("ext", lambda h: h["ext_types"]),
        "ext_types_no_grease": uniq("extng", lambda h: h["ext_types_no_grease"]),
        "groups": uniq("groups", lambda h: h["parsed"].get("supported_groups")),
        "sigalgs": uniq("sigs", lambda h: h["parsed"].get("signature_algorithms")),
        "keyshare": uniq("ks", lambda h: h["parsed"].get("key_share")),
        "trust_anchors": uniq("ta", lambda h: h["parsed"].get("trust_anchors")),
        "session_id_len": uniq("sid", lambda h: h["session_id_len"]),
        "ech": uniq("ech", lambda h: h["parsed"].get("ech_type")),
        "alps_len": uniq("alps", lambda h: len(h["parsed"].get("alps_raw", "")) // 2),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="capture/chrome154")
    ap.add_argument("--diff", action="store_true", help="与 chrome_fp.spec(当前版本) 对比")
    ap.add_argument("--json", default=None, help="把解析结果写成 json")
    args = ap.parse_args()

    d = ROOT / args.dir
    hellos = []
    for f in sorted((d / "hellos").glob("*.bin")):
        try:
            hellos.append(parse_client_hello(f.read_bytes()))
        except Exception as exc:                          # noqa: BLE001
            print(f"  !! {f.name}: {exc}")
    if not hellos:
        print("没有抓到 ClientHello")
        return 1

    s = summarize(hellos)
    print(f"=== ClientHello 样本 {s['samples']} 条 (去掉重复后) ===")
    print(f"JA4_a           : {s['ja4_a']['values'][0]}   (distinct={s['ja4_a']['distinct']})")
    print(f"JA4_b           : {s['ja4_b']['values'][0]}   (distinct={s['ja4_b']['distinct']})")
    print(f"JA4_c(去GREASE) : {s['ja4_c']['values'][0]}   (distinct={s['ja4_c']['distinct']})")
    print(f"JA4(含GREASE)   : distinct={s['ja4']['distinct']} (签名算法带 GREASE, 每条都可能不同)")
    print()
    print(f"cipher 数(去GREASE): {len(s['ciphers_no_grease']['values'][0])}  "
          f"distinct={s['ciphers_no_grease']['distinct']}")
    print("  " + ",".join(f"{c:04x}" for c in s["ciphers_no_grease"]["values"][0]))
    print(f"  GREASE 密码套件位置示例: {s['ciphers']['values'][0][:3]}...")
    print(f"extension 数(去GREASE): {len(s['ext_types_no_grease']['values'][0])} "
          f"distinct={s['ext_types_no_grease']['distinct']}   "
          f"(随机置换 distinct_order={s['ext_order']['distinct']})")
    print("  发出: " + ", ".join(name_of(t) for t in s["ext_types_no_grease"]["values"][0]))
    print(f"supported_groups: distinct={s['groups']['distinct']} -> "
          + ", ".join(GROUP_NAMES.get(g, hex(g)) for g in s["groups"]["values"][0]))
    print(f"key_share       : distinct={s['keyshare']['distinct']} -> "
          + ", ".join(f"{k['name']}({k['len']}B)" for k in s["keyshare"]["values"][0]))
    print(f"sig_algs        : distinct={s['sigalgs']['distinct']} n={len(s['sigalgs']['values'][0])}")
    print("  " + ",".join(f"{x:04x}" for x in s["sigalgs"]["values"][0]))
    ta = s["trust_anchors"]
    print(f"trust_anchors   : distinct={ta['distinct']} n={len(ta['values'][0])}")
    print("  " + " ".join(ta["values"][0]))
    print(f"session_id_len  : {s['session_id_len']['values'][0]}  "
          f"ech_type={s['ech']['values'][0]}  alps_len={s['alps_len']['values'][0]}B")

    if args.json:
        payload = {"samples": hellos, "summary": s}
        (ROOT / args.json).write_text(json.dumps(payload, ensure_ascii=False, indent=2))

    if args.diff:
        from chrome_fp import spec  # noqa: PLC0415
        print("\n=== 与 spec.py (当前 profile) 对比 ===")
        got_ciphers = s["ciphers_no_grease"]["values"][0]
        print(f"cipher 列表一致      : {got_ciphers == spec.CIPHER_SUITES}")
        if got_ciphers != spec.CIPHER_SUITES:
            print("    spec : " + ",".join(f"{c:04x}" for c in spec.CIPHER_SUITES))
            print("    chrome: " + ",".join(f"{c:04x}" for c in got_ciphers))
        got_groups = [g for g in s["groups"]["values"][0] if g not in GREASE]
        print(f"supported_groups 一致: {got_groups == spec.SUPPORTED_GROUPS}")
        if got_groups != spec.SUPPORTED_GROUPS:
            print(f"    spec : {[hex(g) for g in spec.SUPPORTED_GROUPS]}")
            print(f"    chrome: {[hex(g) for g in got_groups]}")
        got_sigs = s["sigalgs"]["values"][0]
        sigs_ng = [x for x in got_sigs if x not in GREASE]
        print(f"sig_algs 去GREASE一致: {sigs_ng == spec.SIGNATURE_ALGORITHMS}")
        if sigs_ng != spec.SIGNATURE_ALGORITHMS:
            print(f"    spec : {[hex(x) for x in spec.SIGNATURE_ALGORITHMS]}")
            print(f"    chrome: {[hex(x) for x in sigs_ng]}")
        got_ext = set(s["ext_types_no_grease"]["values"][0])
        print(f"ACTIVE_EXTS 一致     : {got_ext == set(spec.ACTIVE_EXTS)}")
        if got_ext != set(spec.ACTIVE_EXTS):
            print(f"    只在 chrome 里有: {sorted(hex(x) for x in got_ext - set(spec.ACTIVE_EXTS))}")
            print(f"    只在 spec 里有  : {sorted(hex(x) for x in set(spec.ACTIVE_EXTS) - got_ext)}")
        got_ta = set(ta["values"][0])
        spec_ta = set(spec.TRUST_ANCHOR_IDS)
        print(f"trust_anchors 一致   : {got_ta == spec_ta}  (chrome {len(got_ta)} / spec {len(spec_ta)})")
        if got_ta != spec_ta:
            print(f"    chrome 多出: {sorted(got_ta - spec_ta)}")
            print(f"    chrome 少了: {sorted(spec_ta - got_ta)}")
        print(f"JA4_b 对 153 文档值 8daaf6152771: "
              f"{s['ja4_b']['values'][0] == '8daaf6152771'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
