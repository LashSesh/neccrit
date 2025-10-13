import io
import secrets
import struct
import time

import pytest

from spectralship_engine_duallayer import SpectralNode


class DummyConn:
    def __init__(self, payload: bytes):
        self._buffer = io.BytesIO(payload)
        self.sent = b""

    def recv(self, n: int) -> bytes:
        return self._buffer.read(n)

    def sendall(self, data: bytes) -> None:
        self.sent += data


@pytest.fixture
def node():
    return SpectralNode(
        name="tester",
        port=0,
        resonance_code="1",
        kappa=[1.0, 1.0, 1.0],
        theta=[0.1, 0.2, 0.3],
        crypto_pw="password123",
    )


def test_replay_rejection(node):
    peer = ("127.0.0.1", "peer")
    msg_id = secrets.token_hex(16)
    ts = int(time.time())

    assert node._record_message(peer, msg_id, ts)
    assert not node._record_message(peer, msg_id, ts)
    assert not node._record_message(peer, "newid" * 4, ts - (node.message_ttl + 1))


def test_oversize_frame_rejected(node):
    node.max_frame_size = 8
    conn = DummyConn(struct.pack(">I", node.max_frame_size + 1))
    with pytest.raises(ValueError):
        node._recv_frame(conn)

    conn_send = DummyConn(b"")
    with pytest.raises(ValueError):
        node._send_frame(conn_send, b"x" * (node.max_frame_size + 1))


def test_send_frame_within_limit(node):
    node.max_frame_size = 32
    payload = b"hello"
    conn = DummyConn(b"")
    node._send_frame(conn, payload)
    expected = struct.pack(">I", len(payload)) + payload
    assert conn.sent == expected
