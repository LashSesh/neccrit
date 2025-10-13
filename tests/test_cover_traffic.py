"""Tests for cover traffic adapter integration."""
import threading
import time

import pytest

import core.transport as transport
from addons.scorpiosync_adapter import (
    maybe_transform_plaintext,
    send_cover_once,
    start_cover_traffic,
)
from addons.scorpiosync_generators_complete import steganography_decode


@pytest.fixture(autouse=True)
def reset_transport_state():
    transport.clear_active_session()
    yield
    transport.clear_active_session()


def test_maybe_transform_plaintext_without_stegano():
    text = "hello world"
    assert maybe_transform_plaintext(text, use_stegano=False) == text


def test_maybe_transform_plaintext_with_stegano():
    text = "secret message"
    encoded = maybe_transform_plaintext(text, use_stegano=True)

    assert encoded != text
    assert "\u200B" in encoded or "\u200C" in encoded

    decoded = steganography_decode(encoded)
    assert decoded == f'"{text}"'


def test_send_cover_once_invokes_transport(monkeypatch):
    captured = {}

    def fake_send(frame):
        captured["frame"] = frame

    monkeypatch.setattr("addons.scorpiosync_adapter.send_encrypted_json", fake_send)
    monkeypatch.setattr("addons.scorpiosync_adapter.is_session_ready", lambda: True)

    send_cover_once(use_http_mimicry=False)

    assert "frame" in captured
    frame = captured["frame"]
    assert frame["type"] == "cover"
    assert "payload" in frame
    assert "ts" in frame


def test_send_cover_once_with_http_mimicry(monkeypatch):
    captured = {"http": False}

    def fake_http_builder(payload, include_length_prefix=False):
        captured["http"] = True
        return b"http"

    monkeypatch.setattr("addons.scorpiosync_adapter.http_builder_transformer", fake_http_builder)
    monkeypatch.setattr("addons.scorpiosync_adapter.send_encrypted_json", lambda frame: None)
    monkeypatch.setattr("addons.scorpiosync_adapter.is_session_ready", lambda: True)

    send_cover_once(use_http_mimicry=True)

    assert captured["http"] is True


def test_start_cover_traffic_sends_until_stopped(monkeypatch):
    frames = []
    statuses = [True, True, True, False]

    monkeypatch.setattr("addons.scorpiosync_adapter.send_encrypted_json", lambda frame: frames.append(frame))
    monkeypatch.setattr("addons.scorpiosync_adapter.is_session_ready", lambda: statuses.pop(0) if statuses else False)
    monkeypatch.setattr("addons.scorpiosync_adapter.fake_api_request_generator", lambda: {"endpoint": "/", "method": "GET", "body": {}, "headers": {}})

    stop_flag = threading.Event()
    thread = start_cover_traffic(min_s=0, max_s=0, use_http_mimicry=False, stop_flag=stop_flag)

    time.sleep(0.2)
    stop_flag.set()
    thread.join(timeout=1)

    assert len(frames) >= 1


def test_start_cover_traffic_no_ready_session(monkeypatch):
    monkeypatch.setattr("addons.scorpiosync_adapter.is_session_ready", lambda: False)
    monkeypatch.setattr(
        "addons.scorpiosync_adapter.send_encrypted_json",
        lambda frame: (_ for _ in ()).throw(RuntimeError("should not send")),
    )

    stop_flag = threading.Event()
    thread = start_cover_traffic(min_s=0, max_s=0, use_http_mimicry=False, stop_flag=stop_flag)

    time.sleep(0.1)
    stop_flag.set()
    thread.join(timeout=1)

    # If send_encrypted_json had been invoked it would have raised
    assert not thread.is_alive()
