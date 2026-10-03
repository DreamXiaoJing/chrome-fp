#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_capture —— 一条命令完成 "起探针 + 拉真 Chrome + 收工"。

之所以要在一个进程里编排: Chrome 是 GUI 子系统程序, PowerShell 抓不到它的 stdout,
而且 --log-file 只有在 Chrome 正常退出时才落盘。这里用 subprocess 直接把 stderr 收进
文件, 并且等探针自己 idle 退出后再收 Chrome, 日志不会丢。

用法:
    python tools/run_capture.py --out capture/chrome154 --ports 8443-8462 --seconds 30
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


def free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="capture/chrome154")
    ap.add_argument("--ports", default="8443-8462")
    ap.add_argument("--host", default="probe.test")
    ap.add_argument("--chrome", default=None)
    ap.add_argument("--seconds", type=float, default=30.0, help="Chrome 最长跑多久")
    ap.add_argument("--wait", type=float, default=0.0, help="探针总等待(默认按 seconds 推算)")
    ap.add_argument("--idle", type=float, default=6.0)
    ap.add_argument("--headful", action="store_true")
    ap.add_argument("--user-agent", default=None)
    ap.add_argument("--unsafe-blanket-cert", action="store_true", default=True,
                    help="用 --ignore-certificate-errors(默认开; 探针用临时 profile)")
    ap.add_argument("--keep-chrome", action="store_true", help="调试用: 不杀 Chrome")
    ap.add_argument("--extra", action="append", default=[], help="追加 Chrome 参数(可重复)")
    args = ap.parse_args()

    out_dir = ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    first_port = int(args.ports.split("-")[0].split(",")[0])
    wait = args.wait or (args.seconds + 15)

    chrome_err = out_dir / "chrome_stderr.log"
    profile = Path(tempfile.mkdtemp(prefix="cfp-chrome-"))

    probe_cmd = [PYTHON, str(ROOT / "tools" / "tap_probe.py"),
                 "--ports", args.ports, "--out", str(out_dir),
                 "--host", args.host, "--wait", str(wait), "--idle", str(args.idle)]
    print("[run] probe:", " ".join(probe_cmd), flush=True)
    probe = subprocess.Popen(probe_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, encoding="utf-8", errors="replace")

    spki_file = out_dir / "spki.txt"
    for _ in range(100):
        if spki_file.exists() and not free(first_port):
            break
        time.sleep(0.1)
    else:
        probe.kill()
        raise SystemExit("探针没起来")

    from tools.launch_chrome import find_chrome  # noqa: PLC0415
    chrome = find_chrome(args.chrome)
    url = f"https://{args.host}:{first_port}/"
    cmd = [
        str(chrome), f"--user-data-dir={profile}",
        f"--host-resolver-rules=MAP {args.host} 127.0.0.1",
        "--ignore-certificate-errors", "--no-proxy-server",
        "--no-first-run", "--no-default-browser-check",
        "--disable-background-networking", "--disable-component-update",
        "--disable-sync", "--disable-gpu", "--disable-dev-shm-usage",
        "--enable-logging=stderr", "--v=1",
    ]
    if not args.headful:
        cmd.insert(1, "--headless=new")
    if args.user_agent:
        cmd.insert(1, f"--user-agent={args.user_agent}")
    cmd.extend(args.extra)
    cmd.append(url)

    print("[run] chrome:", " ".join(cmd), flush=True)
    with open(chrome_err, "w", encoding="utf-8", errors="replace") as errf:
        cflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0  # type: ignore[attr-defined]
        proc = subprocess.Popen(cmd, stdout=errf, stderr=subprocess.STDOUT, creationflags=cflags)

    t0 = time.time()
    while time.time() - t0 < args.seconds and probe.poll() is None:
        time.sleep(0.5)

    if not args.keep_chrome and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    try:
        out, _ = probe.communicate(timeout=wait)
    except subprocess.TimeoutExpired:
        probe.kill()
        out, _ = probe.communicate()
    shutil.rmtree(profile, ignore_errors=True)

    print(out or "", flush=True)
    print(f"[run] chrome stderr -> {chrome_err}", flush=True)
    lines = chrome_err.read_text(encoding="utf-8", errors="replace").splitlines()
    keys = ("ERR_", "probe.test", "SSL", "ssl", "TLS", "ALPN", "cert", "Cert", "handshake")
    print("[run] --- chrome stderr (filtered) ---")
    for ln in lines:
        if any(k in ln for k in keys):
            print("   ", ln[:200])
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
