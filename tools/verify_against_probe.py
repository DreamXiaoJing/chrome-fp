# -*- coding: utf-8 -*-
"""把本库指向本机探针, 用同一套抓包工具验证: 本库发出的 ClientHello / HTTP2 帧
是否与真 Chrome 154 一致(库这一侧用作 capture/library154 的证据)。

    python tools/verify_against_probe.py --port 8443
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from chrome_fp import Session, spec  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--version", default="154")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    base = f"https://{args.host}:{args.port}"
    s = Session(chrome_version=args.version, verify=False, timeout=8)
    print(f"[library] profile={s.profile.name} UA={s.user_agent[:60]}")

    # 1) 导航(document)
    try:
        r = s.get(base + "/", mode="navigate", dest="document")
        print(f"[library] GET / -> {r.status_code} {len(r.content)}B  ja4={spec.active_profile().ja4_prefix}")
    except Exception as exc:                             # noqa: BLE001
        print(f"[library] GET / failed: {exc!r}")

    # 2) 子资源(image)
    for i in range(3):
        try:
            r = s.get(base + f"/p{i}.png", dest="image", mode="cors")
            print(f"[library] GET /p{i}.png -> {r.status_code} {len(r.content)}B")
        except Exception as exc:                         # noqa: BLE001
            print(f"[library] GET /p{i}.png failed: {exc!r}")
    s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
