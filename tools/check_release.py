#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_release —— 发版前的一致性/产物检查(CI 与本机共用, 不依赖 bash/tomllib 之外的库)。

检查项:
  1. tag(去掉 v) == pyproject.toml 的 version == chrome_fp/__init__.py 的 __version__
  2. dist/ 里恰好一个 wheel + 一个 sdist
  3. wheel 里 chrome_fp 模块数正常、METADATA 里的版本号与 tag 一致
  4. sdist 能正常解包、包含 README 与 LICENSE

用法:
    python tools/check_release.py --tag v0.6.0                 # 版本一致性
    python tools/check_release.py --tag v0.6.0 --dist dist     # 再检查产物
"""
from __future__ import annotations

import argparse
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def pyproject_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]["version"]


def package_version() -> str:
    text = (ROOT / "chrome_fp" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r"""__version__\s*=\s*["']([^"']+)["']""", text)
    if not m:
        raise SystemExit("chrome_fp/__init__.py 里找不到 __version__")
    return m.group(1)


def check_versions(tag: str | None) -> str:
    ver, pkg = pyproject_version(), package_version()
    print(f"pyproject.toml = {ver}\nchrome_fp/__init__.py = {pkg}")
    if tag:
        want = tag.removeprefix("v")
        print(f"tag = {tag} (-> {want})")
        if want != ver or pkg != ver:
            raise SystemExit("::error::tag / pyproject.toml / __init__.py 版本不一致")
    elif ver != pkg:
        raise SystemExit("::error::pyproject.toml 与 __init__.py 版本不一致")
    print("版本一致 OK")
    return ver


def check_dist(dist: Path, version: str) -> None:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(f"::error::dist/ 里应各有一个 wheel 与 sdist, 实际 {len(wheels)}/{len(sdists)}")
    wheel, sdist = wheels[0], sdists[0]
    print(f"wheel = {wheel.name} ({wheel.stat().st_size} B)")
    print(f"sdist = {sdist.name} ({sdist.stat().st_size} B)")

    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        mods = [n for n in names if n.startswith("chrome_fp/") and n.endswith(".py")]
        meta = [n for n in names if n.endswith(".dist-info/METADATA")]
        print(f"wheel: {len(mods)} 个模块, {len(names)} 个文件")
        if len(mods) < 15:
            raise SystemExit(f"::error::wheel 里 chrome_fp 模块只有 {len(mods)} 个, 明显不对")
        if not meta:
            raise SystemExit("::error::wheel 里没有 METADATA")
        text = z.read(meta[0]).decode("utf-8", "replace")
    m = re.search(r"^Version:\s*(\S+)", text, re.M)
    if not m or m.group(1) != version:
        raise SystemExit(f"::error::wheel METADATA 版本 {m and m.group(1)} != {version}")
    print(f"wheel METADATA 版本 = {m.group(1)} OK")

    with tarfile.open(sdist) as t:
        files = [m.name for m in t.getmembers() if not m.isdir()]
    print(f"sdist: {len(files)} 个文件")
    for want in ("README.md", "LICENSE"):
        if not any(f.endswith("/" + want) for f in files):
            raise SystemExit(f"::error::sdist 里缺少 {want}")
    print("产物检查 OK")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default=None, help="形如 v0.6.0; 给了就校验三者一致")
    ap.add_argument("--dist", default=None, help="dist 目录; 给了就检查产物")
    args = ap.parse_args()

    version = check_versions(args.tag)
    if args.dist:
        check_dist((ROOT / args.dist) if not Path(args.dist).is_absolute() else Path(args.dist),
                   version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
