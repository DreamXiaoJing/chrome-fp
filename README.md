# chrome-fp — 与真 Chrome 逐字节同指纹的纯 Python 请求库, 用法和 requests 一样

用 Python 发 HTTP 请求, 但 TLS/HTTP2 指纹跟本机真 Chrome（**默认 154.0.8037.98**，
可用 `chrome_version="153"` 切到 **153.0.8010.48**）一致：
JA4、HTTP/2 Akamai 指纹、请求头顺序与取值、扩展集合、GREASE、ALPS、trust_anchors、
PQ 混合密钥共享（X25519MLKEM768）全部对齐。

```python
import chrome_fp as requests            # 就当成 requests 用

r = requests.get("https://example.com/", params={"a": 1}, timeout=10)
print(r.status_code, r.headers["Content-Type"], r.elapsed)
print(r.text, r.json() if "json" in r.headers.get("content-type", "") else "")

with requests.Session() as s:
    s.headers.update({"x-token": "abc"})
    r = s.post("https://httpbin.org/post", json={"a": 1})
    r.raise_for_status()
```

## 版本 profile：Chrome 154（默认）/ 153

`Session(chrome_version=...)` 选版本，默认跟着最新 Stable（**154**，本机 154.0.8037.98）：

```python
from chrome_fp import Session
Session()                        # Chrome 154（默认）
Session(chrome_version="153")    # Chrome 153（153.0.8010.48）
```

2026-10-03 在本机做了 **153 ↔ 154 的 A/B 实抓**：Chrome for Testing 153.0.8010.47 与
本机 Stable 154.0.8037.98 各抓 20+ 条真实连接（`tools/run_capture.py` 起本地 TLS/HTTP2
探针 + 拉真 Chrome，`tools/analyze_hello.py` 解析）：

| 项目 | Chrome 153 | Chrome 154 | 结论 |
|---|---|---|---|
| JA4_a / JA4_b | `t13d1517h2` / `8daaf6152771` | 完全相同 | 不变 |
| cipher / supported_groups / sig_algs | — | 完全相同 | 不变 |
| 扩展集合（17 个） | — | 完全相同 | 不变 |
| `trust_anchors`(0xca34) | 28 个 ID | 同一集合 | 不变 |
| H2 SETTINGS / WINDOW_UPDATE / 帧序 | — | 完全相同 | 不变 |
| `sec-ch-ua` 品牌 | `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"` | `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"` | **随版本变** |
| UA / full-version | `Chrome/153.0.0.0` | `Chrome/154.0.0.0` | **随版本变** |

> **153 → 154 的 TLS/HTTP2 线格式没有变化**，差异只在版本字符串与 UA 品牌串。
> profile 以 `dataclasses.replace` 从 153 派生 154，`spec.PROFILES` 里继续加版本即可。

同一套探针也用来验证**本库自己**：把库指向探针抓一遍，与真 Chrome 154 逐项对比 ——
ClientHello 的 cipher / groups / sig_algs / 扩展集合 / trust_anchors / session_id /
key_share / ALPN **8 项全一致**，JA4（含去 GREASE 的 c 段）三处字符串完全相同。

本轮还修掉一处**旧实现与真机不符**的地方：真 Chrome 的 HEADERS 帧带 `PRIORITY` 标志
（flags `0x25`），前面有 5 字节 `E=1 / depends_on=0 / weight=按 RFC 9218 urgency 查表`
（`u=0→256`、`u=1→220`、`u=3→147`）。153/154 实测**都带**，之前实现少发这 5 字节。

## 本轮做了什么：拿真机抓包把库对齐

本机是非管理员，Npcap/dumpcap 直接拒绝抓包
（`You do not have permission to capture on device`）。所以改用**应用层旁路抓包**：

```
Chrome ──CONNECT──> tools/tap_proxy.py ──> 真实服务器 / 本地 h2 服务器
                          │
                          ├─ 原样录下双向字节（不改一个字节）
                          ├─ 合成 TCP 头写成 .pcap  ──> tshark / Wireshark 打开
                          └─ Chrome 的 SSLKEYLOGFILE ──> 解密看 HTTP/2 帧
```

产物在 `capture/chrome153/`（另有 `capture/library/` 是**本库**走同一流程的抓包，用来对比）：

| 文件 | 内容 |
|---|---|
| `chrome_tap.pcap` | 合成 TCP 的抓包文件，Wireshark 可直接打开（304 包 / 23 条隧道） |
| `sslkeylog.txt` | Chrome 自己写的 TLS 会话密钥 |
| `hello/*.bin` | 真 Chrome 发出的 ClientHello 原始字节（17 条样本） |
| `streams/*.bin` | 每条隧道双向的原始字节流 |
| `h2_client.json` | 解密后解出的请求头（顺序 + 取值） |
| `summary.txt` | 按资源类型归类的头顺序汇总 |
| `tls_diff.txt` | 与库的逐扩展对比结论（`完全一致`） |
| `report.json` | tshark 判定结果（JA4/JA3/扩展/key_share…） |

抓包自己也能复现：

```bash
python tools/run_capture.py --out capture/chrome153 --sites https://example.com/
python tools/analyze_capture.py --dir capture/chrome153      # tshark 出 JA4 等
python tools/tls13_decrypt.py   capture/chrome153            # 自己解密出 h2 明文
python tools/h2_frames.py       capture/chrome153            # 解 HTTP/2 帧与请求头
python tools/diff_fp.py --dir   capture/chrome153            # 与库逐扩展对比
```

> tshark 4.6 能把服务端方向的 TLS 解出来，但客户端方向一直停在
> `Encrypted Application Data`。抓包本身没问题（record 结构完整、密钥齐全），
> 所以 `tools/tls13_decrypt.py` 按 RFC 8446 自己解，并与 tshark 对服务端的判定互相印证。

### 在 Wireshark / tshark 里直接看

`capture/chrome153/chrome_tap.pcap` 是标准 pcap（以太网链路层 + 完整 TCP 三次握手，
tshark 能正常重组），双击就能用 Wireshark 打开：

```bash
# 1) 让 Wireshark 用 Chrome 的 keylog 解密
#    GUI:  编辑 → 首选项 → Protocols → TLS → (Pre)-Master-Secret log filename
#          选 capture/chrome153/sslkeylog.txt
#    tshark 等价写法: -o tls.keylog_file:capture/chrome153/sslkeylog.txt

# 2) 看真 Chrome 的 JA4（tshark 4.6 原生支持）
tshark -r capture/chrome153/chrome_tap.pcap \
       -o tls.keylog_file:capture/chrome153/sslkeylog.txt \
       -Y "tls.handshake.type==1" \
       -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ja4

# 3) 看解密后的 HTTP/2 请求头（顺序就是 Chrome 的真实顺序）
tshark -r capture/chrome153/chrome_tap.pcap \
       -o tls.keylog_file:capture/chrome153/sslkeylog.txt \
       -Y "http2.header.name" -T fields -e http2.streamid -e http2.header.name -e http2.header.value
```

> 本机是非管理员，`dumpcap.exe -i <任意网卡>` 会直接报
> `You do not have permission to capture on device ... Admin-only Mode`，
> 所以**抓包驱动用不了**（Npcap 的 NPCAP 组也不在当前令牌里，UAC 又不方便点）。
> 旁路代理拿到的字节和网卡抓包看到的完全一样，只是没有 TCP 重传之类的噪声；
> 如果你想要网卡级抓包，用管理员权限跑
> `dumpcap -i <网卡> -w out.pcapng` 即可，分析流程完全一样。

### 抓出来的差异（已全部修掉）

| # | 项目 | 真 Chrome 153 | 旧库 (0.2.3) | 处理 |
|---|---|---|---|---|
| 1 | `trust_anchors`(0xca34) ID 数量 | **28 个** | 32 个（152 的集合） | 去掉 `d6790902/03/09/0e` 四个 |
| 2 | HTTP/2 `PRIORITY` 帧 | **一个都不发** | 默认发 3/5/7/9 四帧 | `send_priority_tree` 默认关 |
| 3 | `HEADERS` 帧标志 | 不带 PRIORITY 前缀 | 带 5 字节 weight 前缀 | 默认不写 |
| 4 | Akamai 指纹第 3/4 段 | `0` / `m,a,s,p` | 会被 #2 改成 `00:256,...` | 修正；`m,a,s,p` 其实是**伪头顺序** |
| 5 | `sec-ch-ua` | `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"` | 152 的品牌、顺序也不同 | 更新 |
| 6 | `sec-ch-ua-platform` | `"Windows"` | `"Linux"` | 更新 |
| 7 | `user-agent` | Windows NT 10.0; Win64; x64 + Chrome/153 | X11; Linux x86_64 + Chrome/152 | 更新 |
| 8 | 请求头顺序 | **导航 / 子资源两套不同顺序** | 只有一套写死的顺序 | 按 `dest`/`mode` 选 profile |
| 9 | `accept` / `priority` / `referer` / `origin` | 随资源类型变 | 全部写死 | 按 dest 取值 |
| 10 | `sec-fetch-user` | 只有顶层 document 导航才有 | 导航一律带 | 修正 |

TLS 层其余部分（15 个密码套件、17 个扩展+2 GREASE、11 个签名算法、
4 个 group、ECH GREASE 结构、ALPS、compress_certificate、status_request、
EMS、session_id…）经逐字节比对**与 Chrome 153 完全一致**。

### 验证结果

```bash
python tools/verify_live.py
```

让**本库**走同一个代理访问同一个本地 h2 服务器，再和 Chrome 的抓包对比：

```
[2/4] TLS ClientHello 对比     密码套件/扩展集合/扩展数量/trust_anchors/groups/sigalgs/versions  全部 OK
[3/4] HTTP/2 指纹对比         Akamai = 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p   一致
                              PRIORITY 帧数量 = 0                                            一致
[4/4] 请求头逐条对比           document / style / font / script / image / iframe / fetch / xhr / POST
                              —— 9 类请求的头顺序与取值全部逐条相同
```

## 实测结果

| 项目 | 真 Chrome 153 | 本库 |
|---|---|---|
| JA4 | `t13d1517h2_8daaf6152771_<随机>` | **一致**（17/17 条样本） |
| HTTP/2 Akamai | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | **一致**（10/10 条连接） |
| 扩展数 | 17 真实 + 2 GREASE | **一致** |
| trust_anchors | 28 个 ID（集合固定、顺序随机） | **一致** |
| 请求头顺序/取值 | 导航与子资源各一套 | **一致**（逐条比对） |

实网站点：`python tools/live_sites.py` → 5/5
（example.com / taobao h2+TLS1.3，baidu / qq / sohu TLS1.2 回落 + HTTP/1.1）

## requests 兼容的用法

`Session` / `Response` 的属性与方法刻意对齐 requests：

```python
import chrome_fp as requests
from chrome_fp.exceptions import HTTPError, TooManyRedirects

s = requests.Session()
s.headers.update({"x-token": "abc"})      # 大小写不敏感, 单次请求头可覆盖
s.params = {"v": "1"}
s.cookies.set("sid", "x", domain="example.com")
s.auth = ("user", "pass")                 # 或 basic_auth/自定义可调用对象
s.proxies = {"https": "http://127.0.0.1:7892"}
s.max_redirects = 10

r = s.request("POST", "https://example.com/api",
              params={"p": 1}, json={"a": 1}, timeout=(5, 20),
              headers={"x-extra": "1"}, cookies={"k": "v"},
              allow_redirects=True, hooks={"response": [lambda r: None]})
r.status_code; r.reason; r.ok; r.headers["CONTENT-TYPE"]; r.text; r.json()
r.content; r.raw; r.url; r.encoding; r.apparent_encoding; r.elapsed; r.history
r.cookies; r.request; r.is_redirect; r.links; r.next
r.raise_for_status(); list(r.iter_content(4096)); list(r.iter_lines())
```

模块级 `chrome_fp.get/post/put/patch/delete/head/options/request` 与 requests 同名同签名。
异常层次在 `chrome_fp.exceptions`（`RequestException` / `HTTPError` / `Timeout` /
`TooManyRedirects` / `MissingSchema` / `InvalidURL` / `JSONDecodeError` …）。

**几处刻意的 requests 语义**（不是 bug）：

- `r.encoding` 按 requests 规则来：Content-Type 带 charset 就用它；`text/*` 没写 charset
  时是 `ISO-8859-1`；`application/json` 是 `utf-8`。想要正确的中文文本就
  `r.encoding = r.apparent_encoding`（用 charset_normalizer，和 requests 一样）。
- `r.json()` 解析失败抛 `chrome_fp.exceptions.JSONDecodeError`（同时是 `json.JSONDecodeError`）。
- `r.iter_lines()` 在 `decode_unicode=False` 时给 bytes。

### 指纹控制（requests 没有的额外关键字）

```python
Session(
    proxy="http://127.0.0.1:7892",     # 也支持 proxies={...} 和 HTTP(S)_PROXY 环境变量
    mode="cors",                       # navigate | cors | no-cors  —— 决定 sec-fetch-*
    dest="empty",                      # document|iframe|empty|script|style|image|font|preflight
    user_agent=None,                   # 覆盖 UA
    origin=None, referer=None,         # CORS / 子资源请求的上下文
    sec_fetch_site=None,               # none|same-origin|same-site|cross-site
    priority=None,                     # 覆盖 RFC 9218 priority 头
    send_priority_tree=False,          # 只有模拟 Chrome 152 才打开
    verify=True, ca_file=None, allow_tls12=True,
    timeout=30, max_redirects=30, trust_env=True,
    keylog_file=None,                  # 写 NSS key log, Wireshark 可直接解密本库流量
)
```

单次请求也能覆盖：`s.get(url, mode="navigate", dest="document", referer=..., origin=..., priority=...)`。

`sec-fetch-site` 需要调用方给上下文（库不知道"发起方页面"是谁），默认：
顶层 document 导航 = `none`，其余 = `same-origin`；跨站时显式传 `cross-site`。

底层构造单条 ClientHello（不含网络）：

```python
from chrome_fp import build_client_hello, ja4_from_hello
ch = build_client_hello("example.com")
print(ja4_from_hello(ch.record), len(ch.record))
ch.record          # 可直接写 socket 的原始字节
```

- `include_mlkem=False`：不发 X25519MLKEM768
- `grease_parts=()`：完全关闭 GREASE
- `permute_extensions=False`：关闭扩展随机置换（调试用）

## 协议实现覆盖

### TLS

| 能力 | 状态 |
|---|---|
| TLS 1.3 / 1.2（同一 ClientHello 自动分派） | ✅ |
| 密码套件：AES-GCM / ChaCha20-Poly1305 / **AES-CBC-SHA** | ✅ |
| RSA 密钥交换（009c/009d/002f/0035） | ✅ |
| X25519MLKEM768 混合密钥共享（纯 Python ML-KEM-768） | ✅ |
| **HelloRetryRequest**（换 key_share 组 / cookie） | ✅ |
| 证书链校验（交叉签名根、EKU 缺失放行、通配符） | ✅ |
| CertificateVerify 验签、压缩证书（brotli）、ALPS | ✅ |
| **客户端证书 mTLS**（`cert=`，TLS 1.3 与 1.2） | ✅ |
| KeyUpdate / NewSessionTicket 容忍 | ✅ |
| SSLKEYLOGFILE 导出（Wireshark 可解密本库流量） | ✅ |
| 会话恢复（PSK / session ticket）、0-RTT、ECH 真加密 | ❌ 见下 |

`cert=` 的用法和 requests 一致：

```python
s.get(url, cert="client.pem")                  # 证书+私钥在同一个 PEM
s.get(url, cert=("client.pem", "client.key"))  # 分开两个文件
Session(cert=...)                              # 会话级
```

### HTTP/2

| 能力 | 状态 |
|---|---|
| Chrome 帧序（preface/SETTINGS/WINDOW_UPDATE/HEADERS，153/154 一致） | ✅ |
| **HEADERS 的 PRIORITY 前缀**（`0x25` + `E=1/dep=0/weight=urgency` 查表，153/154 都带） | ✅ |
| **TLS 记录分帧**（preface+SETTINGS+WINDOW_UPDATE 合成一条 record） | ✅ |
| **HPACK 编码选择与 Chromium 一致**（见下） | ✅ |
| **请求体流控**（连接窗口 + 流窗口，等 WINDOW_UPDATE） | ✅ |
| **尊重对端 SETTINGS_MAX_FRAME_SIZE / INITIAL_WINDOW_SIZE** | ✅ |
| **PUSH_PROMISE**（回 RST_STREAM(CANCEL)） | ✅ |
| CONTINUATION / 1xx / trailer / GOAWAY / RST_STREAM | ✅ |
| 流式响应（`stream=True`）与流式请求体（生成器） | ✅ |

**HPACK 为什么重要**：头**解码后**一样 ≠ **编码后**一样。JA3/JA4/Akamai 都不看 HPACK，
但服务器/中间盒 dump 一下 HEADERS 帧的原始载荷，就能用编码方式把客户端区分开。
`hpack_chromium.py` 复刻了 Chromium 的选择规则，规则是从真机抓包里**统计**出来的
（`tools/diff_wire.py` 会复核）：

| 规则 | 证据（真 Chrome 153 抓包） |
|---|---|
| 静态表精确命中 → 索引表示 | `:method: GET`、`:scheme: https` |
| **`:method` / `:path` 命中不到精确项 → 字面量+不索引(0x04)** | OPTIONS 的 `:method`、所有 `:path` |
| 其余头 → 字面量+增量索引(0x40) | `cookie` / `referer` 实测都是 `0x44`（**不是**"从不索引"） |
| Huffman **择优，平局取原始字节** | `/?n=0` 平局→raw；`/style.css` 更短→Huffman |

验证方式是把抓包里每条连接上的请求**按原顺序重放**再逐块比字节（HPACK 动态表是连接级
状态，不按顺序重放比出来的差异是噪声）：真 Chrome 抓包 **32/32**、本库抓包 **11/11**
全部逐字节复现。

### Client Hints（Accept-CH）

网站用 `Accept-CH` 点单后，真 Chrome 会在**后续**请求里带上高熵 client hints。完全不发的话，
凡是下发过 `Accept-CH` 的站（不少 CDN 都发）一眼就能看出不是浏览器 —— 这比 JA3 更硬。
本库按规范跟踪每个源的 `Accept-CH`，命中后按 Chrome 的**内部固定顺序**回发
（顺序与取值来自探针抓包，用 `tools/run_capture.py --probe` + `CHROME_FP_ACCEPT_CH` 可复现）。

```python
Session(client_hints=True)                            # 默认开
Session(client_hints=False)                           # 完全不发
Session(client_hint_values={"device-memory": "4"})    # 覆盖取值
```

> ⚠️ 如实说明：探针抓包里 UA 派生那几个（`full-version` / `full-version-list` / `arch` /
> `bitness` / `platform-version`）是**空串** —— 因为抓包时为让 UA 逐字节一致加了
> `--user-agent`，Chrome 会把 UA 派生的高熵 hint 置空。正常 UA 下它们有真实值，本库按
> Chrome 153 / Windows x86_64 填。**这几个取值没有抓包直接验证**，需要精确对齐时逐项覆盖。

### HTTP/1.1

| 能力 | 状态 |
|---|---|
| 定长 / chunked 响应、gzip/deflate/br/zstd | ✅ |
| **chunked 请求体**（生成器/无长度文件对象） | ✅ |
| **真流式响应**（`stream=True` + `iter_content`，增量解压） | ✅ |
| 连接复用（响应头标题大小写按 Chrome 习惯） | ✅ |
| `Expect: 100-continue` | ❌ 未实现（极少见） |

### 连接层

DNS 返回多个地址（尤其 IPv6 排在前面）时会**自己遍历并 IPv4 优先**，每个地址限时
5 秒、整体不超过 `timeout`。踩过的坑：`socket.create_connection` 按 DNS 顺序逐个用
**完整 timeout** 尝试，两个黑洞 IPv6 地址就能烧光整个预算 —— 实测 example.com 要 12 秒
才连上、`timeout` 小一点直接失败，而同一时刻 requests 只要 0.6 秒。修好后 1.1 秒。

## 还能被检测出来吗（现状）

分三层看，别混为一谈：

| 层 | 现状 |
|---|---|
| TLS/HTTP2 **内容**指纹（JA3/JA4/Akamai/扩展集合/头顺序） | 对齐（见上面各表） |
| **线上字节细节**（TLS 记录分帧、HPACK 编码） | **已对齐**（`tools/diff_wire.py` 复核：32/32、11/11） |
| **Client Hints**（Accept-CH） | 机制已实现，UA 派生取值未直接抓包验证 |
| 行为 / JS / 跨层一致性 | **做不到**，见下 |

具体来说，下面这些仍然是"是不是浏览器"的硬伤，**不是指纹库能解决的**：

1. **不执行 JS**。Cloudflare / Akamai / DataDome / PerimeterX 最终都靠主动 JS 挑战 +
   行为判定；TLS 指纹只决定"别在门口就被拦"。
2. **行为不像人**。单发请求、无子资源、无缓存/条件请求、请求节奏固定、长期零会话恢复。
3. **跨层矛盾**：库声明 Windows 平台，但 TCP/IP 栈用的是宿主机 —— **在 Linux 上跑必然
   出现"Windows 浏览器 + Linux TCP 指纹"**，这一条比任何指纹都硬。（Windows 上自洽）
4. **Cookie 语义**仍未实现 `Secure` / `SameSite` / partitioned / `__Host-` 前缀与排序规则，
   服务器可以用一个 `Secure` cookie 测出来。
5. **无 HTTP 缓存**，从不发 `If-None-Match` / `If-Modified-Since`。
6. `sec-fetch-site` / `referer` / `origin` 依赖调用方给上下文，给错就与真实页面矛盾。

## 故意不实现的部分（附原因）

- **TLS 1.3 会话恢复（PSK / session ticket）**：恢复用的 ClientHello 会多出
  `pre_shared_key` 扩展，**JA4 与首次连接不同**。本库的真值来自 Chrome 5 次全新 profile
  的首次连接（17 条样本全是 19 扩展、无 PSK），没有抓到 Chrome 的恢复握手样本。
  在没有真值的情况下实现，只会让指纹从"确定对"变成"可能错"，所以宁可不做。
  需要的话可以先用 `tools/run_capture.py` 抓同一 profile 的第二次导航来拿真值。
- **0-RTT / early_data**：本库的 ClientHello 与真 Chrome 一样不带 `early_data`（0x002a），
  发早期数据会直接改变指纹。
- **ECH 真加密**：需要 DNS HTTPS 记录里的 ECHConfigList + HPKE。Chrome 只在站点发布
  ECH 时才真加密，本库一律发 ECH GREASE（与抓包一致）。
- **QUIC / HTTP/3**：要另写一整套 QUIC 传输（丢包恢复、拥塞控制、QPACK…），
  是另一个量级的工程；Chrome 走 TCP 时就是本库复刻的这套指纹。
- `Expect: 100-continue`：极少见，收益低。

## 测试

```bash
python -m unittest discover -s tests -v      # 86 个用例
python tools/verify_live.py                  # 端到端: 本库 vs 真 Chrome 抓包
python tools/diff_wire.py                    # 线级: TLS 记录分帧 + HPACK 编码字节
python tools/live_sites.py                   # 实网站点冒烟
```

| 测试文件 | 覆盖 |
|---|---|
| `test_chrome153_fingerprint.py` | 把 ClientHello / 请求头钉死在真机抓包上（含 key_share 私钥配对回归） |
| `test_hpack_chromium.py` | **HPACK 编码逐字节复现真 Chrome**（含动态表连续状态） |
| `test_client_hints.py` | Accept-CH 跟踪、高熵 hint 顺序/取值、cookie 位置 |
| `test_requests_api.py` | requests 语法、cookie jar、重定向、多地址连接 |
| `test_tls_features.py` | HRR、TLS1.2 CBC、mTLS（各自带本地 TLS 服务器） |
| `test_http2_features.py` | 请求体流控、MAX_FRAME_SIZE、PUSH_PROMISE（h2 库的流控检查当裁判） |
| `test_streaming.py` | chunked 上传、`stream=True` 真流式、增量解压 |

## 构建与发布

```bash
python -m pip install build wheel twine
python -m build                    # 产出 dist/chrome_fp-0.4.0-py3-none-any.whl 和 .tar.gz
python tools/verify_build.py       # 校验产物(清单/METADATA/隔离安装冒烟/sdist 自举)
python -m twine check dist/*       # README 渲染与元数据检查
python -m twine upload dist/*      # -u __token__ -p pypi-xxxx (建议用 TWINE_PASSWORD 环境变量)
python tools/verify_pypi.py        # 拉回 PyPI 比 sha256, 确认传上去的和本地逐字节一致
```

- 已发布：**chrome-fp 0.5.0**（<https://pypi.org/project/chrome-fp/0.5.0/>）
  —— Chromium 一致的 HPACK 编码 / TLS 记录分帧 / Accept-CH 高熵 hints
- 历史版本：**0.6.0（多版本 profile：新增 Chrome 154，153→154 A/B 实抓校对；
  修正 HEADERS 的 PRIORITY 前缀）**、0.4.0（HRR / TLS1.2 CBC / 客户端证书 /
  HTTP2 请求体流控 / 真流式）、0.3.0（Chrome 153 指纹对齐）、0.2.x（Chrome 152）

```bash
pip install chrome-fp             # 或者 pip install "chrome-fp[encoding]"
```

`verify_build.py` 会把 wheel 解到临时目录，用**那个副本**跑一遍真实功能
（拼 ClientHello、算 JA4、requests 风格 prepare_request），确保校验的不是源码树；
再确认 sdist 解包后能自己重新构建出 wheel。

- wheel 里只有 `chrome_fp` 包（16 个模块）+ LICENSE + METADATA
- sdist 额外带 `tests/`、`tools/`，但不含体积大的 `capture/` 抓包数据
- `chrome_fp.zip` 是同样内容的便携 zip（源码 + README + pyproject + LICENSE）

## 目录结构

```
chrome_fp/
  spec.py         多版本 profile（Profile 数据类 + PROFILES 注册表 + 153/154 常量 +
                  每种资源类型的头顺序，全部标注出处；旧的大写常量名继续可用）
  hello.py        按 BoringSSL ssl_add_clienthello_tlsext 规则拼 ClientHello
  fingerprint.py  解析 + JA3/JA4 计算
  tls13.py        纯 Python TLS 1.3 客户端（record 层/密钥调度/CV 校验/证书链校验/KeyUpdate/keylog）
  tls12.py        TLS 1.2 回落（ECDHE/RSA + GCM/ChaCha20/**CBC**, EMS, 客户端证书）
  clientcert.py   客户端证书加载 + 签名算法选择 + TLS1.2/1.3 证书消息构造
  client.py       发同一个 ClientHello, 按 ServerHello 自动分派 1.3 / 1.2
  mlkem.py        ML-KEM-768 (FIPS 203) 纯 Python
  http2.py        HTTP/2 客户端（帧序/SETTINGS/头顺序/请求体流控/推送/流式）
  hpack_chromium.py  HPACK 编码选择与 Chromium 一致(编码字节可逐字节复现)
  _huffman_table.py  RFC 7541 附录 B 的 Huffman 表(生成物, 不依赖 hpack 内部实现)
  http1.py        HTTP/1.1 客户端（Title-Case 头名 / chunked / 流式）
  session.py      requests 风格的 Session / Response / PreparedRequest
  api.py          模块级 get/post/...（与 requests 同名同签名）
  structures.py   CaseInsensitiveDict / RequestsCookieJar
  exceptions.py   与 requests.exceptions 对应的异常层次
tools/            抓包(代理/本地h2服务器/解密)、分析(tshark/HTTP2)、构建与发布校验
tests/            单元 + 与真机抓包的回归测试（71 个用例）
capture/          本轮真 Chrome 153 的抓包与判定结果
```

## 已知边界

- **`www.google.com` / `www.googleapis.com`**：握手能完成（JA4 一致），但 GFE 随后用
  `unexpected_message` 断链。本机到 Google 的 IP 被黑洞/污染（`tcp` 都连不上），
  暂时无法进一步定位。其余实测站点正常。
- **JA3 每次连接都不同**，这是真 Chrome 的行为（扩展顺序随机置换），不是 bug；
  稳定的标识是 **JA4**。
- 扩展顺序、GREASE 取值、ECH GREASE 长度、trust_anchors 顺序都是每次连接随机的
  （与 Chrome 相同分布）。
- 会话恢复 / 0-RTT / ECH 真加密 / QUIC-HTTP3 故意未实现，原因见上面「故意不实现的部分」。
- 连接策略是 **IPv4 优先**（Chrome 用 happy eyeballs 并发尝试）。对黑白洞 IPv6 的环境
  这是必要的取舍，但严格来说与 Chrome 的连接时序不同 —— 这不影响 TLS/HTTP2 指纹。

## 真值来源

1. 本机真 Chrome 的抓包：
   - **154.0.8037.98**（Windows x64, Stable）：22 条 ClientHello + 20 条 HTTP/2 连接，
     另有第二次启动复核 UA 品牌与 trust_anchors 顺序（`capture/chrome154*`）
   - **153.0.8010.48**（Windows x64, Stable）：22 条 ClientHello + 10 条 HTTP/2 连接
     （`capture/chrome153/`），JA4 由 tshark 4.6.4 判定
   - A/B 对照用的 Chrome for Testing **153.0.8010.47**（`capture/chrome153cft/`）；
     注意它是 Chromium 分支（`sec-ch-ua` 无 Google Chrome 品牌），且多一个构建特有的
     扩展 `0x12e0`，所以只用于对照 TLS/H2 线格式，不当作 Stable 153 的品牌基准
2. 抓包工具（本轮新增/重写，替代已删除的旧 tools）：
   - `tools/tap_probe.py` —— 本地 TLS/HTTP2 探针，记录 ClientHello 原字节 + 解密后的
     H2 帧与请求头（MemoryBIO 驱动，握手期的原始字节逐字节留档）
   - `tools/run_capture.py` —— 起探针 + 拉真 Chrome + 收日志的一条龙入口
   - `tools/analyze_hello.py` —— 解析 ClientHello/JA4/trust_anchors 并与 profile 逐项 diff
   - `tools/verify_against_probe.py` —— 把**本库**指向同一探针，和真 Chrome 对比字节
3. 本地 Chromium/BoringSSL 源码：
   - 扩展表顺序与置换：`boringssl/src/ssl/extensions.cc:4067-4295, 4306-4328`
   - GREASE 首尾与 padding 规则：`extensions.cc:4489-4560`
   - ECH GREASE 长度：`boringssl/src/ssl/encrypted_client_hello.cc:732-784`
   - trust_anchors(0xca34)：`include/openssl/tls1.h:141` + `extensions.cc:2948-2965`
   - 混合密钥共享拼接顺序：`boringssl/src/ssl/ssl_key_share.cc:308-346`
   - TLS 客户端配置：`net/socket/ssl_client_socket_impl.cc`
