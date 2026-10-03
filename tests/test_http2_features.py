"""HTTP/2 未实现功能的测试: 请求体流控、MAX_FRAME_SIZE、PUSH_PROMISE。

端到端部分自带一个 TLS+h2 服务器, 用 h2 库自身的流控检查当裁判:
客户端一旦超窗口发 DATA, 服务器的 receive_data 会抛 FlowControlError。
"""

from __future__ import annotations

import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from test_tls_features import make_cert  # noqa: E402

# h2 只用于"独立裁判"式的服务端。缺了它时旧行为是: 服务线程抛 ModuleNotFoundError 挂掉,
# 客户端一直等响应 -> 整个用例挂死(CI 上就这么卡了 10 分钟)。这里改成显式跳过。
try:
    import h2  # noqa: F401
    HAVE_H2 = True
except ImportError:                                  # pragma: no cover
    HAVE_H2 = False

NEED_H2 = unittest.skipUnless(HAVE_H2, "需要 h2 作为独立 HTTP/2 裁判: pip install h2")


def settings_frame(payload: bytes = b"") -> bytes:
    """一个 SETTINGS 帧: 长度(3) || 类型(1) || 标志(1) || 流ID(4) || 载荷"""
    return (len(payload)).to_bytes(3, "big") + bytes([4, 0]) + (0).to_bytes(4, "big") + payload


def parse_frames(data: bytes) -> list[tuple[int, int, int, bytes]]:
    """解析发出的字节流 -> [(类型, 标志, 流ID, 载荷)]"""
    out, p = [], 0
    while p + 9 <= len(data):
        ln = int.from_bytes(data[p:p + 3], "big")
        out.append((data[p + 3], data[p + 4],
                    int.from_bytes(data[p + 5:p + 9], "big") & 0x7FFFFFFF,
                    data[p + 9:p + 9 + ln]))
        p += 9 + ln
    return out


class FakeTLS:
    """假 TLS 层: 记录发出去的字节, 按脚本喂回来的字节"""

    def __init__(self):
        self.sent = bytearray()
        self.incoming = bytearray()

    def send_app(self, data: bytes) -> None:
        self.sent += data

    def recv_app(self, n: int = 65536) -> bytes:
        out = bytes(self.incoming[:n])
        self.incoming = self.incoming[n:]
        return out

    def feed(self, data: bytes) -> None:
        self.incoming += data


class FlowControlServer:
    """TLS + h2 服务器: 只在累计消费到一定量后**延迟**补 WINDOW_UPDATE。

    连接级窗口初始固定 65535(RFC 9113), 所以只要请求体大于 65535, 客户端就必须
    真的停下来等窗口 —— 不等的话 h2 库会抛 FlowControlError, 测试直接失败。
    """

    def __init__(self, cert: str, key: str, ack_every: int = 16384, ack_delay: float = 0.02):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.ctx.set_alpn_protocols(["h2"])
        self.ack_every = ack_every
        self.ack_delay = ack_delay
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.received = 0
        self.max_data_frame = 0
        self.error: str | None = None
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=5)

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, raw: socket.socket):
        import h2.config
        import h2.connection
        import h2.events

        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except Exception as e:  # noqa: BLE001
            self.error = f"TLS: {type(e).__name__}: {e}"
            return
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        h2c = h2.connection.H2Connection(config=cfg)
        h2c.initiate_connection()
        conn.sendall(h2c.data_to_send())
        unacked = 0
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                for ev in h2c.receive_data(data):
                    if isinstance(ev, h2.events.DataReceived):
                        self.received += len(ev.data)
                        unacked += ev.flow_controlled_length
                        if unacked >= self.ack_every:
                            # 故意慢一点, 逼客户端真的等窗口
                            time.sleep(self.ack_delay)
                            h2c.acknowledge_received_data(unacked, ev.stream_id)
                            unacked = 0
                    elif isinstance(ev, h2.events.StreamEnded):
                        if unacked:
                            h2c.acknowledge_received_data(unacked, ev.stream_id)
                            unacked = 0
                        body = str(self.received).encode()
                        h2c.send_headers(ev.stream_id, [
                            (":status", "200"), ("content-length", str(len(body)))])
                        h2c.send_data(ev.stream_id, body, end_stream=True)
                out = h2c.data_to_send()
                if out:
                    conn.sendall(out)
        except Exception as e:  # noqa: BLE001
            # h2 库会在这里替我们抓住"对端超了流控"/"帧太大"
            self.error = f"{type(e).__name__}: {e}"
        finally:
            try:
                conn.close()
            except OSError:
                pass


@NEED_H2
class TestRequestBodyFlowControl(unittest.TestCase):
    def test_upload_larger_than_connection_window(self):
        """200KB POST: 连接窗口只有 65535, 必须按 WINDOW_UPDATE 节奏发, 且一个字节不丢"""
        from chrome_fp import Session

        size = 200 * 1024
        body = bytes(range(256)) * (size // 256)
        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with FlowControlServer(cert, key) as srv:
                with Session(verify=False, timeout=60) as s:
                    r = s.post(f"https://127.0.0.1:{srv.port}/upload", data=body)
                self.assertIsNone(srv.error, f"服务器报错(多半是流控被违反): {srv.error}")
                self.assertEqual(r.status_code, 200)
                self.assertEqual(int(r.text), size, "服务器收到的字节数不对")

    def test_upload_one_megabyte(self):
        """1MB 上传: 要等很多轮窗口更新"""
        from chrome_fp import Session

        size = 1024 * 1024
        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = make_cert(tmp)
            with FlowControlServer(cert, key, ack_every=32768, ack_delay=0.005) as srv:
                with Session(verify=False, timeout=120) as s:
                    r = s.post(f"https://127.0.0.1:{srv.port}/big", data=b"x" * size)
                self.assertIsNone(srv.error, f"服务器报错: {srv.error}")
                self.assertEqual(int(r.text), size)


class TestH2FlowControlUnit(unittest.TestCase):
    """不联网的单元测试: 直接喂帧给状态机"""

    def _conn(self):
        from chrome_fp.http2 import H2Connection

        tls = FakeTLS()
        c = H2Connection(tls)
        c.start()
        tls.sent.clear()
        return c, tls

    def test_peer_settings_applied(self):
        from chrome_fp import http2

        c, _ = self._conn()
        payload = b"".join([
            (0x0001).to_bytes(2, "big") + (8192).to_bytes(4, "big"),    # HEADER_TABLE_SIZE
            (0x0004).to_bytes(2, "big") + (200000).to_bytes(4, "big"),  # INITIAL_WINDOW_SIZE
            (0x0005).to_bytes(2, "big") + (32768).to_bytes(4, "big"),   # MAX_FRAME_SIZE
        ])
        c._apply_peer_settings(payload)
        self.assertEqual(c.peer_initial_window, 200000)
        self.assertEqual(c.peer_max_frame, 32768)
        self.assertEqual(c.encoder.header_table_size, 8192)
        # 我们自己的帧长仍然取 min(16384, 对端) —— 不超过对端即可
        self.assertEqual(c._out_frame_size(), 16384)

    def test_initial_window_change_shifts_existing_streams(self):
        c, _ = self._conn()
        c.stream_send_window[1] = 65535
        c.stream_send_window[3] = 65535
        c._apply_peer_settings((0x0004).to_bytes(2, "big") + (1000).to_bytes(4, "big"))
        self.assertEqual(c.stream_send_window[1], 65535 + (1000 - 65535))
        self.assertEqual(c.stream_send_window[3], 65535 + (1000 - 65535))

    def test_window_update_frames_feed_the_send_window(self):
        from chrome_fp import http2

        c, tls = self._conn()
        c.conn_send_window = 0
        c.stream_send_window[1] = 0
        # 连接级 +500, 流级 +700
        c._process_frame(http2.FRAME_WINDOW_UPDATE, 0, 0, (500).to_bytes(4, "big"), {})
        c._process_frame(http2.FRAME_WINDOW_UPDATE, 0, 1, (700).to_bytes(4, "big"), {})
        self.assertEqual(c.conn_send_window, 500)
        self.assertEqual(c.stream_send_window[1], 700)

    def test_push_promise_is_reset(self):
        from chrome_fp import http2

        c, tls = self._conn()
        payload = (2).to_bytes(4, "big")            # promised stream id = 2
        c._process_frame(http2.FRAME_PUSH_PROMISE, 0x4, 1, payload, {"stream_id": 1,
                                                                    "ended": False})
        self.assertEqual(c.pushed_streams, [2])
        # 必须回一条 RST_STREAM(CANCEL) 到推送流, 否则连接会被推送占住
        sent = bytes(tls.sent)
        self.assertIn((8).to_bytes(4, "big"), sent)
        self.assertEqual(sent[3], http2.FRAME_RST_STREAM)
        self.assertEqual(int.from_bytes(sent[5:9], "big") & 0x7FFFFFFF, 2)

    def test_send_body_stops_at_window(self):
        from chrome_fp import http2

        c, tls = self._conn()
        tls.feed(settings_frame())      # 先给一个空 SETTINGS, send_body 会等它
        c.stream_send_window[1] = 100
        c.conn_send_window = 100
        body = b"z" * 100
        # 窗口正好够 -> 发完就结束; 期间只读到了那个 SETTINGS
        c.send_body(1, body, {"stream_id": 1, "ended": False})
        self.assertEqual(c.conn_send_window, 0)
        self.assertEqual(c.stream_send_window[1], 0)
        data_frames = [f for f in parse_frames(bytes(tls.sent)) if f[0] == http2.FRAME_DATA]
        self.assertEqual(len(data_frames), 1, f"应该只有一个 DATA 帧: {data_frames}")
        self.assertEqual(len(data_frames[0][3]), 100)
        self.assertEqual(data_frames[0][1] & http2.FLAG_END_STREAM, http2.FLAG_END_STREAM)

    def test_send_body_waits_for_window_update(self):
        from chrome_fp import http2

        c, tls = self._conn()
        c.stream_send_window[1] = 10
        c.conn_send_window = 10

        def window_update(stream_id: int, inc: int) -> bytes:
            # 帧头 = 长度(3) || 类型(1) || 标志(1) || 流ID(4)
            return (4).to_bytes(3, "big") + bytes([http2.FRAME_WINDOW_UPDATE, 0]) \
                + stream_id.to_bytes(4, "big") + inc.to_bytes(4, "big")

        # 先塞 SETTINGS 和两个 WINDOW_UPDATE 进"网络":
        # 发送循环读到 SETTINGS 之后窗口仍是 10, 发 10 字节, 再读到两个更新才发完
        tls.feed(settings_frame() + window_update(0, 90) + window_update(1, 90))
        c.send_body(1, b"z" * 100, {"stream_id": 1, "ended": False})
        self.assertEqual(c.conn_send_window, 0)
        self.assertEqual(c.stream_send_window[1], 0)

    def test_read_exact_raises_on_closed_connection(self):
        """对端关闭时不能死循环(曾经真的会)"""
        c, _ = self._conn()
        with self.assertRaises(ConnectionError):
            c.read_frame()


if __name__ == "__main__":
    unittest.main(verbosity=2)
