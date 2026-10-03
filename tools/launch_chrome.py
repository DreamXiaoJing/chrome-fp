#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""启动本机 Chrome 打到 tap_probe 上, 抓真机指纹。

只做三件事: 关掉系统代理直连(否则会被本机的代理软件截走)、把 probe.test 解析到
127.0.0.1、用 SPKI 白名单放行自签证书。**不会碰你正在用的 Chrome 配置** —— 每次都用
临时 --user-data-dir。
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
]


def find_chrome(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("CHROME_PATH")
    if env and Path(env).exists():
        return Path(env)
    for c in CHROME_CANDIDATES:
        if Path(c).exists():
            return Path(c)
    raise SystemExit("找不到 chrome.exe, 用 --chrome 指定")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome")
    ap.add_argument("--host", default="probe.test")
    ap.add_argument("--probe-port", type=int, default=8443)
    ap.add_argument("--spki", help="SPKI sha256 base64; 默认读 capture/chrome154/spki.txt")
    ap.add_argument("--spki-only", action="store_true",
                    help="只用 --ignore-certificate-errors-spki-list(默认整包放行)")
    ap.add_argument("--capture-dir", default="capture/chrome154")
    ap.add_argument("--seconds", type=float, default=25.0, help="跑多久后关掉 Chrome")
    ap.add_argument("--headful", action="store_true", help="不用 headless(会用 UA 覆盖)")
    ap.add_argument("--user-agent", default=None, help="覆盖 UA(同时会让 UA 派生 hint 置空)")
    args = ap.parse_args()

    chrome = find_chrome(args.chrome)
    spki = args.spki
    if not spki:
        spki_file = ROOT / args.capture_dir / "spki.txt"
        if not spki_file.exists():
            raise SystemExit(f"缺少 SPKI, 先跑 tap_probe.py 生成 {spki_file}")
        spki = spki_file.read_text().strip()

    profile = Path(tempfile.mkdtemp(prefix="cfp-chrome-"))
    url = f"https://{args.host}:{args.probe_port}/"
    # SPKI 白名单在部分 Chrome 版本上不生效(握手直接被 abort), 默认用整包放行;
    # 探针是本地临时 profile, 不碰系统证书库, 所以这个开关是安全的。
    cert_flag = (f"--ignore-certificate-errors-spki-list={spki}"
                 if args.spki_only else "--ignore-certificate-errors")

    cmd = [
        str(chrome),
        f"--user-data-dir={profile}",
        f"--host-resolver-rules=MAP {args.host} 127.0.0.1",
        cert_flag,
        "--no-proxy-server",                 # 绕过本机代理软件, 直连探针
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        url,
    ]
    if not args.headful:
        cmd.insert(1, "--headless=new")
    if args.user_agent:
        cmd.insert(1, f"--user-agent={args.user_agent}")

    print("[launch] " + " ".join(cmd))
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=flags)
    try:
        time.sleep(args.seconds)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(profile, ignore_errors=True)
    print(f"[launch] chrome exited rc={proc.returncode}, profile cleaned: {profile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
