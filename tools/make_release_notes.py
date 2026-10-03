#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_release_notes —— 按 dist/ 里的真实文件生成 GitHub Release 正文。

CI(tag 触发)与本机共用; 输出 markdown, 直接喂给 `gh release create --notes-file`。
内容: 版本说明 + pip 安装命令 + 产物表(大小/SHA256) + SHA256SUMS + 与上一个 tag 的 compare 链接。

用法:
    python tools/make_release_notes.py --version 0.6.0 --dist dist --out RELEASE_BODY.md \
        [--prev-tag v0.5.0] [--repo DreamXiaoJing/chrome-fp]
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HEADER = """## chrome-fp {version}

与真 Chrome 逐字节同指纹的纯 Python HTTP 请求库，支持多版本 profile：
`Session(chrome_version="154")`（默认）/ `Session(chrome_version="153")`。

```bash
pip install chrome-fp=={version}
```

### 产物

| 文件 | 大小 | SHA256 |
|---|---|---|
"""


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--out", default="RELEASE_BODY.md")
    ap.add_argument("--prev-tag", default=None, help="上一个 tag, 用来生成 compare 链接")
    ap.add_argument("--repo", default=None, help="owner/repo")
    args = ap.parse_args()

    dist = (ROOT / args.dist) if not Path(args.dist).is_absolute() else Path(args.dist)
    assets = sorted(list(dist.glob("*.whl")) + list(dist.glob("*.tar.gz")))
    if not assets:
        raise SystemExit(f"{dist} 里没有 wheel/sdist")

    lines = [HEADER.format(version=args.version).rstrip("\n")]
    sums = []
    for f in assets:
        digest = sha256(f)
        lines.append(f"| `{f.name}` | {f.stat().st_size:,} B | `{digest}` |")
        sums.append(f"{digest}  {f.name}")
    lines.append("")
    lines.append("### 校验")
    lines.append("")
    lines.append("```")
    lines.extend(sums)
    lines.append("```")
    if args.prev_tag and args.repo:
        lines.append("")
        lines.append(f"**完整对比**：https://github.com/{args.repo}/compare/"
                     f"{args.prev_tag}...v{args.version}")
    body = "\n".join(lines) + "\n"

    out = (ROOT / args.out) if not Path(args.out).is_absolute() else Path(args.out)
    out.write_text(body, encoding="utf-8", newline="\n")
    print(body)
    print(f"[make_release_notes] 已写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
