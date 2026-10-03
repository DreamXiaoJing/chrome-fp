#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""release —— 一条命令发版: 改版本号 -> 跑测试 -> 提交 -> 打 tag -> push。

push 之后由 `.github/workflows/release.yml` 接管: 重新跑测试、构建 wheel/sdist、
校验 tag 与版本号一致, 再自动建 GitHub Release 并把产物和 SHA256SUMS 传上去。

用法:
    python tools/release.py patch                 # 0.6.0 -> 0.6.1
    python tools/release.py minor                 # 0.6.0 -> 0.7.0
    python tools/release.py 0.7.0                 # 指定版本
    python tools/release.py patch --dry-run        # 只打印要做什么, 不落盘
    python tools/release.py patch --no-push        # 提交+打 tag, 但不 push
    python tools/release.py patch --skip-tests

约定(与 release.yml 一致): pyproject.toml 的 version、chrome_fp/__init__.py 的
__version__、tag `vX.Y.Z` 三者必须一致。
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "chrome_fp" / "__init__.py"
VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.M)
INIT_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)
PYTHON = sys.executable


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    printable = " ".join(cmd)
    print(f"+ {printable}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, **kw)


def git(*args: str, capture: bool = True) -> str:
    res = subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=capture)
    if res.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} 失败:\n{res.stderr or res.stdout}")
    return (res.stdout or "").strip()


def current_version() -> str:
    m = VERSION_RE.search(PYPROJECT.read_text(encoding="utf-8"))
    if not m:
        raise SystemExit("pyproject.toml 里找不到 version")
    return m.group(1)


def bump(version: str, part: str) -> str:
    if re.fullmatch(r"\d+\.\d+\.\d+([.\-+].*)?", part):
        return part
    nums = version.split(".")
    if len(nums) < 3 or not all(n.isdigit() for n in nums[:3]):
        raise SystemExit(f"当前版本 {version} 不是 X.Y.Z, 请直接给目标版本")
    major, minor, patch = (int(x) for x in nums[:3])
    if part == "major":
        major, minor, patch = major + 1, 0, 0
    elif part == "minor":
        minor, patch = minor + 1, 0
    elif part == "patch":
        patch += 1
    else:
        raise SystemExit(f"不认识的参数 {part!r}: 用 major/minor/patch 或 X.Y.Z")
    return f"{major}.{minor}.{patch}"


def write_version(new: str, dry: bool) -> None:
    """把 pyproject.toml 与 chrome_fp/__init__.py 里的版本号都改成 new(保留原字段格式)。"""
    for path, regex, label in ((PYPROJECT, VERSION_RE, "pyproject.toml"),
                               (INIT, INIT_RE, "chrome_fp/__init__.py")):
        text = path.read_text(encoding="utf-8")
        m = regex.search(text)
        if not m:
            raise SystemExit(f"{label} 里找不到版本号")
        replaced = text[:m.start()] + m.group(0).replace(m.group(1), new) + text[m.end():]
        print(f"  {label}: {m.group(1)} -> {new}{'  (dry-run)' if dry else ''}")
        if not dry:
            path.write_text(replaced, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="major | minor | patch | X.Y.Z")
    ap.add_argument("--message", "-m", default=None, help="提交信息(默认 release vX.Y.Z)")
    ap.add_argument("--dry-run", action="store_true", help="只打印, 不改文件不提交")
    ap.add_argument("--no-push", action="store_true", help="提交+打 tag, 但不 push")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--branch", default="main", help="要求当前所在分支(默认 main)")
    args = ap.parse_args()

    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if branch != args.branch and not args.dry_run:
        raise SystemExit(f"当前在 {branch}, 期望 {args.branch}(用 --branch 覆盖)")
    dirty = git("status", "--porcelain")
    if dirty and not args.dry_run:
        raise SystemExit(f"工作树不干净, 先提交或 stash:\n{dirty}")

    old = current_version()
    new = bump(old, args.target)
    tag = f"v{new}"
    print(f"[release] {old} -> {new}  (tag {tag})")
    if not args.dry_run and git("tag", "-l", tag):
        raise SystemExit(f"本地已存在 tag {tag}")
    if not args.dry_run and f"refs/tags/{tag}" in git("ls-remote", "--tags", "origin"):
        raise SystemExit(f"远端已存在 tag {tag}")

    write_version(new, args.dry_run)

    if not args.skip_tests:
        print("[release] 跑测试 ...")
        res = run([PYTHON, "-m", "unittest", "discover", "-s", "tests"])
        if res.returncode != 0:
            if not args.dry_run:
                write_version(old, False)          # 回滚版本号
                print("! 测试失败, 已把版本号改回", old)
            raise SystemExit("测试没过, 不发版")
        print("[release] 测试通过")

    if args.dry_run:
        print("[release] dry-run: 到此为止(没改文件、没提交、没打 tag)")
        print(f"[release] 之后会是: git commit -> git tag -a {tag} -> git push origin {branch} {tag}")
        return 0

    msg = args.message or f"release {tag}"
    run(["git", "add", str(PYPROJECT.relative_to(ROOT)), str(INIT.relative_to(ROOT))])
    git("commit", "-m", msg)
    git("tag", "-a", tag, "-m", msg)
    print(f"[release] 已提交并打 tag {tag}")

    if args.no_push:
        print(f"[release] --no-push: 自己 push 一下才会触发自动发版:\n"
              f"    git push origin {branch} && git push origin {tag}")
        return 0

    git("push", "origin", branch)
    git("push", "origin", tag)
    print(f"[release] 已 push。GitHub Actions 会自动构建并发 Release:\n"
          f"    https://github.com/{git('remote', 'get-url', 'origin')}"
          f"/actions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
