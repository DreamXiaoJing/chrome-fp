"""只读地看一眼 9222 上 Edge 的当前页面: URL / 标题 / 表单字段 / 按钮。

    python tools/cdp.py list
    python tools/cdp.py eval --match pypi "<js 表达式>"
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request

import websocket  # websocket-client


def endpoints(port: int = 9222) -> list[dict]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=10) as fh:
        return json.load(fh)


def pick(pages: list[dict], match: str | None) -> dict:
    cands = [p for p in pages if p.get("type") == "page" and p.get("webSocketDebuggerUrl")]
    if match:
        hit = [p for p in cands if match.lower() in (p.get("url", "") + p.get("title", "")).lower()]
        if not hit:
            raise SystemExit(f"没有匹配 {match!r} 的页面")
        return hit[0]
    return cands[0]


def browser_ws(port: int = 9222) -> str:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=10) as fh:
        return json.load(fh)["webSocketDebuggerUrl"]


def new_tab(url: str, port: int = 9222) -> str:
    """开一个新标签页(复用浏览器登录态), 返回它的 page WS 地址。"""
    ws = websocket.create_connection(browser_ws(port), timeout=15, suppress_origin=True)
    try:
        ws.send(json.dumps({"id": 1, "method": "Target.createTarget",
                            "params": {"url": url}}))
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == 1:
                target_id = msg["result"]["targetId"]
                break
    finally:
        ws.close()
    for _ in range(40):
        for p in endpoints(port):
            if p.get("id") == target_id and p.get("webSocketDebuggerUrl"):
                return p["webSocketDebuggerUrl"]
        import time
        time.sleep(0.25)
    raise SystemExit("新标签页没拿到 WS 地址")


def evaluate(ws_url: str, expression: str, timeout: float = 15.0):
    # suppress_origin: Chrome/Edge 默认拒绝带 Origin 头的 WebSocket(403),
    # 除非启动时加了 --remote-allow-origins; 不带 Origin 就能直连。
    ws = websocket.create_connection(ws_url, timeout=timeout, suppress_origin=True)
    try:
        ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                            "params": {"expression": expression, "returnByValue": True,
                                       "awaitPromise": True}}))
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == 1:
                res = msg.get("result", {})
                if "exceptionDetails" in res:
                    raise SystemExit("JS 出错: " + json.dumps(res["exceptionDetails"])[:400])
                return res.get("result", {}).get("value")
    finally:
        ws.close()


SUMMARY_JS = r"""
JSON.stringify({
  url: location.href,
  title: document.title,
  headings: [...document.querySelectorAll('h1,h2,h3')].map(h => h.textContent.trim()).slice(0, 15),
  forms: [...document.querySelectorAll('form')].map(f => ({
    action: f.action, method: f.method,
    fields: [...f.querySelectorAll('input,select,textarea,button')].map(i => ({
      tag: i.tagName.toLowerCase(), type: i.type || '', name: i.name || '', id: i.id || '',
      placeholder: i.placeholder || '', label: (i.labels && i.labels[0] && i.labels[0].textContent.trim()) || '',
      value: (['password','hidden'].includes(i.type) ? '' : (i.value || '').slice(0, 60))
    }))
  })),
  buttons: [...document.querySelectorAll('button, input[type=submit], a.button')]
             .map(b => (b.textContent || b.value || '').trim()).filter(Boolean).slice(0, 25),
  links: [...document.querySelectorAll('a')].map(a => ({t: a.textContent.trim().slice(0, 40), h: a.getAttribute('href')}))
            .filter(x => x.h && /manage|publishing|releases|settings/i.test(x.h)).slice(0, 25)
})
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["list", "eval", "summary", "open"])
    ap.add_argument("expr", nargs="?", help="eval 时的 JS 表达式 / open 时的 URL")
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--match", default=None, help="按 URL/标题子串挑页面")
    args = ap.parse_args()

    if args.cmd == "open":
        if not args.expr:
            raise SystemExit("open 需要给 URL")
        ws_url = new_tab(args.expr, args.port)
        import time
        time.sleep(2.5)                       # 等页面渲染
        print(f"# 已打开: {args.expr}\n{ws_url}")
        out = evaluate(ws_url, SUMMARY_JS)
        print(json.dumps(json.loads(out), ensure_ascii=False, indent=1)
              if isinstance(out, str) else out)
        return 0

    pages = endpoints(args.port)
    if args.cmd == "list":
        for i, p in enumerate(pages):
            if p.get("type") != "page":
                continue
            print(f"{i}: {p.get('title','')[:70]}\n   {p.get('url','')}")
        return 0

    page = pick(pages, args.match)
    print(f"# 目标页面: {page.get('title','')[:70]}\n# {page.get('url','')}\n", flush=True)
    expr = SUMMARY_JS if args.cmd == "summary" else (args.expr or "1")
    out = evaluate(page["webSocketDebuggerUrl"], expr)
    if isinstance(out, str):
        try:
            print(json.dumps(json.loads(out), ensure_ascii=False, indent=1))
        except json.JSONDecodeError:
            print(out)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
