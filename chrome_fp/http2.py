"""HTTP/2 客户端 —— 帧序/SETTINGS/伪头顺序都按真 Chrome 153 复刻。

真值(本轮真机抓包 + 解密, 见 capture/chrome153/):
  Akamai 指纹 = 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  1) SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=6291456,
     MAX_HEADER_LIST_SIZE=262144
  2) WINDOW_UPDATE(stream 0, +15663105)
  3) HEADERS(stream 1, flags = END_STREAM|END_HEADERS, **不带 PRIORITY 标志**)
  4) 头顺序: :method :authority :scheme :path ...(按资源类型不同, 见 spec.header_order)

与 Chrome 152 的两处差异(本轮抓包实测):
  * **没有 PRIORITY 帧** —— 10/10 条连接里 PRIORITY 帧数量都是 0。旧版库里为
    stream 3/5/7/9 发的优先级树会让 Akamai 指纹第 3 段从 "0" 变成 "00:256,00:256,..."。
    Akamai 指纹第 4 段 "m,a,s,p" 是**伪头顺序**(method/authority/scheme/path),
    不是优先级流 —— 旧注释理解错了。
  * HEADERS 帧不带 PRIORITY 标志, 也就没有 5 字节的 weight 前缀。
"""

from __future__ import annotations

from dataclasses import dataclass, field

import hpack

from . import spec
from .hpack_chromium import ChromiumHpackEncoder

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20


@dataclass
class H2Response:
    status: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    trailers: list[tuple[str, str]] = field(default_factory=list)
    body_iter = None      # stream=True 时给的是"按需读"的生成器


class H2Connection:
    def __init__(self, tls_conn, *, send_priority_tree: bool = False, max_frame: int = 16384):
        self.tls = tls_conn
        self.want_priority_tree = send_priority_tree
        self.max_frame = max_frame
        self.next_stream_id = 1
        # 我们 SETTINGS 里广告 HEADER_TABLE_SIZE=65536, 所以解码器要按这个上限配置,
        # 否则服务器调整动态表大小时会抛 InvalidTableSizeError。
        # 编码侧用 Chromium 兼容的实现(编码选择与真 Chrome 一致, 见 hpack_chromium.py),
        # 上限按**服务器**广告的 HEADER_TABLE_SIZE(未收到前是默认 4096)。
        self.encoder = ChromiumHpackEncoder()
        self.decoder = hpack.Decoder(max_header_list_size=spec.H2_SETTINGS[3][1])
        self.decoder.max_allowed_table_size = spec.H2_SETTINGS[0][1]
        self._preface_sent = False
        self.recv_buf = b""
        self.conn_window = spec.H2_SETTINGS[2][1]

        # ---- 对端(服务器)的流控参数, 决定我们**能发多少** ----
        # 默认值来自 RFC 9113 §6.5.2: INITIAL_WINDOW_SIZE=65535, MAX_FRAME_SIZE=16384
        self.peer_initial_window = 65535
        self.peer_max_frame = 16384
        self.conn_send_window = 65535          # 连接级发送窗口(服务器用 WINDOW_UPDATE 加)
        self.stream_send_window: dict[int, int] = {}
        self.pushed_streams: list[int] = []    # 服务器推送(我们广告 ENABLE_PUSH=0, 正常不该有)
        self.goaway: tuple[int, int] | None = None
        self._got_peer_settings = False

    # ------------------------------------------------------------ 发送

    def _frame_bytes(self, ftype: int, flags: int, stream_id: int,
                     payload: bytes = b"") -> bytes:
        return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
                + (stream_id & 0x7FFFFFFF).to_bytes(4, "big") + payload)

    def _send_frame(self, ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> None:
        self.tls.send_app(self._frame_bytes(ftype, flags, stream_id, payload))

    def _out_frame_size(self) -> int:
        """我们发帧时能用的最大长度: 不超过对端广告的 SETTINGS_MAX_FRAME_SIZE。

        RFC 9113 §6.5.2 规定对端给的 MAX_FRAME_SIZE 至少是 16384(默认值), 所以我们自己
        的 16384 永远合法; 对端给得更大时也没必要跟着变大。
        """
        return min(self.max_frame, self.peer_max_frame)

    def start(self) -> None:
        """preface + SETTINGS + WINDOW_UPDATE (帧序与 Chrome 完全一致)

        这三样必须**合成一次 write** —— 真 Chrome 把它们放在同一条 TLS record 里
        (抓包实测 87 字节 = 24 preface + 33 SETTINGS + 13 WINDOW_UPDATE + 5 头 + 16 tag),
        分三次 send_app 会变成三条 record(41/50/30), 记录层分帧就与 Chrome 不同, 而
        记录边界是明文可见的。
        """
        if self._preface_sent:
            return
        settings = b"".join(sid.to_bytes(2, "big") + val.to_bytes(4, "big")
                            for sid, val in spec.H2_SETTINGS)
        # 注: ALPS 协商时客户端 settings 已在 TLS 层经 ClientApplicationSettings
        # 消息(握手密钥加密)送达服务器, 但 RFC 9113 仍要求发 SETTINGS 帧, Chrome 亦如此。
        self.tls.send_app(
            PREFACE
            + self._frame_bytes(FRAME_SETTINGS, 0, 0, settings)
            + self._frame_bytes(FRAME_WINDOW_UPDATE, 0, 0,
                                spec.H2_WINDOW_UPDATE_INCREMENT.to_bytes(4, "big"))
        )
        self._preface_sent = True

    def send_priority_tree(self) -> None:
        """Chrome 152 的优先级树(stream 3/5/7/9) —— Chrome 153 已经不发, 默认关闭。

        打开它会让 Akamai 指纹第 3 段不再是 "0", 所以只在明确模拟旧版 Chrome 时用。
        """
        for sid in spec.H2_PRIORITY_STREAMS_LEGACY:
            self.send_priority(sid, depends_on=spec.H2_PRIORITY_DEPENDS_ON,
                               weight=spec.H2_PRIORITY_WEIGHT,
                               exclusive=bool(spec.H2_PRIORITY_EXCLUSIVE))

    def send_priority(self, stream_id: int, depends_on: int = 0, weight: int = 256,
                      exclusive: bool = False) -> None:
        dep = depends_on | (0x80000000 if exclusive else 0)
        payload = dep.to_bytes(4, "big") + bytes([max(0, min(255, weight - 1))])
        self._send_frame(FRAME_PRIORITY, 0, stream_id, payload)

    def send_headers(self, stream_id: int, headers: list[tuple[str, str]],
                     *, end_stream: bool = True, priority: dict | None = None) -> None:
        block = self.encoder.encode(headers)
        flags = FLAG_END_HEADERS
        prefix = b""
        if priority:
            flags |= FLAG_PRIORITY
            dep = priority.get("depends_on", 0) | (0x80000000 if priority.get("exclusive") else 0)
            prefix = dep.to_bytes(4, "big") + bytes([max(0, min(255, priority.get("weight", 256) - 1))])
        if end_stream:
            flags |= FLAG_END_STREAM
        # 按对端允许的帧长切分(首帧带 priority 前缀)
        size = self._out_frame_size()
        first = size - len(prefix)
        chunk, rest = block[:first], block[first:]
        self._send_frame(FRAME_HEADERS, flags, stream_id, prefix + chunk)
        while rest:
            chunk, rest = rest[:size], rest[size:]
            self._send_frame(FRAME_CONTINUATION, FLAG_END_HEADERS if not rest else 0, stream_id, chunk)

    def send_data(self, stream_id: int, data: bytes, *, end_stream: bool = False) -> None:
        if not data:
            if end_stream:
                self._send_frame(FRAME_DATA, FLAG_END_STREAM, stream_id, b"")
            return
        # 这是"不等流控"的直发版本, 只在对端窗口肯定够用时用; 请求体一律走
        # _send_body_with_flow_control()
        size = self._out_frame_size()
        while data:
            chunk, data = data[:size], data[size:]
            self._send_frame(FRAME_DATA, FLAG_END_STREAM if (end_stream and not data) else 0,
                             stream_id, chunk)

    # ------------------------------------------------------------ 请求体流控

    def _check_send_window(self, stream_id: int) -> int:
        """还能再发多少字节(受连接窗口和流窗口双重限制)"""
        return min(self.conn_send_window, self.stream_send_window.get(stream_id, 0))

    def send_body(self, stream_id: int, body, state: dict) -> None:
        """按 RFC 9113 §6.9 的流控发送请求体。

        body 可以是 bytes, 也可以是**逐块产出的可迭代对象**(生成器/文件对象),
        后者不会被整段读进内存。

        窗口用尽时必须停下等 WINDOW_UPDATE —— 但要继续处理收到的其它帧(服务器可能
        提前回响应、发 PING、甚至 RST 掉这条流), 所以这里复用同一个帧状态机。
        """
        # 先确保读到服务器的 SETTINGS: 它可能把 INITIAL_WINDOW_SIZE 调得很小,
        # 而默认窗口是 65535 —— 不等就直接发, 在对端看来就是超窗口(RST/GOAWAY)。
        while not self._got_peer_settings and not state["ended"] and not state.get("reset"):
            ftype, flags, sid, payload = self.read_frame()
            self._process_frame(ftype, flags, sid, payload, state)
        if state["ended"] or state.get("reset"):
            return

        size = self._out_frame_size()

        def emit(chunk: bytes, last: bool) -> bool:
            pos = 0
            while pos < len(chunk):
                while self._check_send_window(stream_id) <= 0:
                    ftype, flags, sid, payload = self.read_frame()
                    self._process_frame(ftype, flags, sid, payload, state)
                    if state["ended"] or state.get("reset"):
                        return False
                allowed = min(size, self._check_send_window(stream_id))
                piece = chunk[pos:pos + allowed]
                pos += len(piece)
                end = last and pos >= len(chunk)
                self._send_frame(FRAME_DATA, FLAG_END_STREAM if end else 0, stream_id, piece)
                self.conn_send_window -= len(piece)
                self.stream_send_window[stream_id] = \
                    self.stream_send_window.get(stream_id, 0) - len(piece)
            return True

        known = isinstance(body, (bytes, bytearray))
        # 生成器要"留一手"才知道哪块是最后一块(END_STREAM 得标在最后一个 DATA 上)
        pending: bytes | None = None
        for chunk in ([body] if known else body):
            if not chunk:
                continue
            if pending is not None and not emit(pending, known):
                return
            pending = bytes(chunk)
        if pending is not None:
            emit(pending, True)
        elif not known:
            # 空流: 补一个空 DATA 收尾
            self._send_frame(FRAME_DATA, FLAG_END_STREAM, stream_id, b"")

    # ------------------------------------------------------------ 接收

    def _read_exact(self, n: int) -> bytes:
        while len(self.recv_buf) < n:
            chunk = self.tls.recv_app(65536)
            if not chunk:
                # 对端关了连接。这里必须报错而不是继续循环, 否则就是死循环。
                raise ConnectionError("HTTP/2 连接被对端关闭")
            self.recv_buf += chunk
        out, self.recv_buf = self.recv_buf[:n], self.recv_buf[n:]
        return out

    def read_frame(self) -> tuple[int, int, int, bytes]:
        header = self._read_exact(9)
        length = int.from_bytes(header[0:3], "big")
        ftype, flags = header[3], header[4]
        stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
        payload = self._read_exact(length) if length else b""
        return ftype, flags, stream_id, payload

    def request(self, method: str, scheme: str, authority: str, path: str,
                headers: list[tuple[str, str]], body=None,
                timeout: float | None = None, *, send_priority: bool = False,
                stream: bool = False) -> H2Response:
        self.start()
        stream_id = self.next_stream_id
        self.next_stream_id += 2
        # 新流的发送窗口 = 对端广告的 INITIAL_WINDOW_SIZE(RFC 9113 §6.9.2)
        self.stream_send_window[stream_id] = self.peer_initial_window
        # RFC 9113 §8.2.1: HTTP/2 头名必须小写, 否则服务器会 RST(PROTOCOL_ERROR)
        headers = [(k.lower(), v) for k, v in headers]
        # RFC 9113 §8.2.2: HTTP/2 禁止 connection-specific 头, 真 Chrome 也会丢弃它们
        _CONN_HEADERS = frozenset(("connection", "keep-alive", "proxy-connection",
                                   "transfer-encoding", "upgrade"))
        headers = [(k, v) for k, v in headers if k not in _CONN_HEADERS]
        pseudo = [
            (":method", method),
            (":authority", authority),
            (":scheme", scheme),
            (":path", path),
        ]
        # 真 Chrome 153 的 HEADERS 不带 PRIORITY 标志(见模块 docstring), 默认不写优先级前缀
        priority = None
        if send_priority:
            priority = {"exclusive": spec.H2_PRIORITY_EXCLUSIVE,
                        "depends_on": spec.H2_PRIORITY_DEPENDS_ON,
                        "weight": spec.H2_PRIORITY_WEIGHT}
        self.send_headers(stream_id, pseudo + headers, end_stream=body is None,
                          priority=priority)

        resp = H2Response()
        state: dict = {"stream_id": stream_id, "header_block": [], "ended": False,
                       "got_headers": False, "body": bytearray(), "reset": False,
                       "goaway": None, "response": resp}

        if body:
            # 请求体按对端流控窗口发; 期间收到的帧由同一个状态机处理, 不会丢
            self.send_body(stream_id, body, state)

        # Chrome 153 不发 PRIORITY 帧; 只有显式要求模拟旧版时才补发
        if self.want_priority_tree:
            self.send_priority_tree()
            self.want_priority_tree = False

        while not state["ended"] and (not stream or not state["got_headers"]):
            ftype, flags, sid, payload = self.read_frame()
            self._process_frame(ftype, flags, sid, payload, state)
        if stream:
            # 流式: 响应头到手就返回, 响应体由调用方按需拉
            resp.body_iter = self._iter_response_body(stream_id, state)
            return resp
        resp.body = bytes(state["body"])
        return resp

    def _iter_response_body(self, stream_id: int, state: dict):
        """按需把 DATA 帧的内容吐出来(真流式, 不整段缓冲)"""
        while True:
            if state["body"]:
                chunk = bytes(state["body"])
                state["body"] = bytearray()
                yield chunk
            if state["ended"]:
                return
            ftype, flags, sid, payload = self.read_frame()
            self._process_frame(ftype, flags, sid, payload, state)

    # ------------------------------------------------------------ 帧状态机

    def _process_frame(self, ftype: int, flags: int, sid: int, payload: bytes,
                       state: dict) -> None:
        """处理一帧。发送请求体时和等响应时共用, 所以任何帧都只在这里消化一次。"""
        stream_id = state.get("stream_id", 0)
        resp: H2Response | None = state.get("response")

        if ftype == FRAME_SETTINGS:
            if not flags & FLAG_ACK:
                self._apply_peer_settings(payload)
                self._send_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")
            return

        if ftype == FRAME_PING:
            if not flags & FLAG_ACK:
                self._send_frame(FRAME_PING, FLAG_ACK, 0, payload)
            return

        if ftype == FRAME_WINDOW_UPDATE:
            inc = int.from_bytes(payload, "big") & 0x7FFFFFFF
            if sid == 0:
                self.conn_send_window += inc
            else:
                self.stream_send_window[sid] = self.stream_send_window.get(sid, 0) + inc
            return

        if ftype == FRAME_PUSH_PROMISE:
            # 我们广告了 ENABLE_PUSH=0, 规范服务器不该推; 真推了就拒掉, 免得流被拖住
            promised = int.from_bytes(payload[0:4], "big") & 0x7FFFFFFF
            self.pushed_streams.append(promised)
            self.stream_send_window.setdefault(promised, 0)
            self._send_frame(FRAME_RST_STREAM, 0, promised, (8).to_bytes(4, "big"))  # CANCEL
            return

        if ftype == FRAME_GOAWAY:
            self.goaway = (int.from_bytes(payload[0:4], "big") & 0x7FFFFFFF,
                           int.from_bytes(payload[4:8], "big"))
            if not state["ended"]:
                raise ConnectionError(f"服务器 GOAWAY: last_stream={self.goaway[0]} "
                                      f"code={self.goaway[1]}")
            return

        if ftype == FRAME_RST_STREAM:
            if sid == stream_id:
                state["reset"] = True
                raise ConnectionError(f"服务器重置流: code={int.from_bytes(payload, 'big')}")
            return

        if ftype in (FRAME_HEADERS, FRAME_CONTINUATION):
            if sid != stream_id:
                return                      # 推送流/别的流的头, 忽略
            data = payload
            if ftype == FRAME_HEADERS:
                if flags & FLAG_PADDED:
                    pad = data[0]
                    data = data[1:len(data) - pad]
                if flags & FLAG_PRIORITY:
                    data = data[5:]
                state["header_block"] = []
            state["header_block"].append(data)
            if not flags & FLAG_END_HEADERS:
                return
            block = b"".join(state["header_block"])
            state["header_block"] = []
            decoded = self.decoder.decode(block)
            items = [(k.decode() if isinstance(k, bytes) else k,
                      v.decode() if isinstance(v, bytes) else v) for k, v in decoded]
            status_val = next((int(v) for k, v in items if k == ":status"), 0)
            if not state["got_headers"] and 100 <= status_val < 200:
                # 1xx (如 103 Early Hints) 不是终响应, 丢掉继续等真正的响应头
                return
            if not state["got_headers"]:
                state["got_headers"] = True
                for k, v in items:
                    if k == ":status":
                        resp.status = int(v)
                    else:
                        resp.headers.append((k, v))
            else:
                resp.trailers.extend(items)
            if flags & FLAG_END_STREAM:
                state["ended"] = True
            return

        if ftype == FRAME_DATA:
            if sid != stream_id:
                return
            data = payload
            if flags & FLAG_PADDED:
                pad = data[0]
                data = data[1:len(data) - pad]
            state["body"] += data
            # 归还流控窗口(Chrome 行为: 消费多少补多少)
            if data:
                self._send_frame(FRAME_WINDOW_UPDATE, 0, 0, len(data).to_bytes(4, "big"))
                self._send_frame(FRAME_WINDOW_UPDATE, 0, stream_id, len(data).to_bytes(4, "big"))
            if flags & FLAG_END_STREAM:
                state["ended"] = True
            return

    def _apply_peer_settings(self, payload: bytes) -> None:
        """应用服务器的 SETTINGS: 编码表大小 + 流控/帧长参数"""
        self._got_peer_settings = True
        for i in range(0, len(payload) - 5, 6):
            sid = int.from_bytes(payload[i:i + 2], "big")
            val = int.from_bytes(payload[i + 2:i + 6], "big")
            if sid == 0x0001:                      # HEADER_TABLE_SIZE
                self.encoder.set_max_table_size(min(val, spec.H2_SETTINGS[0][1]))
            elif sid == 0x0004:                    # INITIAL_WINDOW_SIZE
                delta = val - self.peer_initial_window
                self.peer_initial_window = val
                # RFC 9113 §6.9.2: 改动 INITIAL_WINDOW_SIZE 要同步调整已有流的窗口
                for k in list(self.stream_send_window):
                    self.stream_send_window[k] += delta
            elif sid == 0x0005:                    # MAX_FRAME_SIZE
                if 16384 <= val <= 16777215:
                    self.peer_max_frame = val
