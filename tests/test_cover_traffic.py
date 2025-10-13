"""
Tests for cover traffic integration with adapter.

Tests the scorpiosync_adapter module and its integration with the transport layer.
"""
import threading
import time
import pytest

from addons.scorpiosync_adapter import (
    set_active_node,
    is_session_ready,
    maybe_transform_plaintext,
    send_cover_once,
    start_cover_traffic,
)
from addons.scorpiosync_generators_complete import steganography_decode


class MockNode:
    """Mock SpectralNode for testing."""
    
    def __init__(self):
        self.running = True
        self.sent_messages = []
    
    def send_fragment(self, msg, peer_ip, peer_port, peer_name):
        """Mock send_fragment that records messages."""
        self.sent_messages.append({
            "msg": msg,
            "peer_ip": peer_ip,
            "peer_port": peer_port,
            "peer_name": peer_name,
        })


def test_session_not_ready_initially():
    """Test that session is not ready before configuration."""
    # Reset global state by importing fresh
    import addons.scorpiosync_adapter as adapter
    adapter._active_node = None
    adapter._peer_config = None
    
    assert not is_session_ready()


def test_set_active_node_enables_session():
    """Test that setting active node makes session ready."""
    node = MockNode()
    set_active_node(node, "127.0.0.1", 5555, "test_peer")
    
    assert is_session_ready()


def test_set_active_node_not_ready_when_not_running():
    """Test that session is not ready if node is not running."""
    node = MockNode()
    node.running = False
    set_active_node(node, "127.0.0.1", 5555, "test_peer")
    
    assert not is_session_ready()


def test_maybe_transform_plaintext_without_stegano():
    """Test plaintext transformation without steganography."""
    text = "hello world"
    result = maybe_transform_plaintext(text, use_stegano=False)
    
    assert result == text


def test_maybe_transform_plaintext_with_stegano():
    """Test plaintext transformation with steganography."""
    text = "secret message"
    result = maybe_transform_plaintext(text, use_stegano=True)
    
    # Should be transformed
    assert result != text
    
    # Should contain zero-width characters
    assert "\u200B" in result or "\u200C" in result
    
    # Should be decodable
    decoded = steganography_decode(result)
    assert decoded == f'"{text}"'  # JSON encoding adds quotes


def test_send_cover_once_requires_session():
    """Test that send_cover_once raises error without session."""
    import addons.scorpiosync_adapter as adapter
    adapter._active_node = None
    adapter._peer_config = None
    
    with pytest.raises(RuntimeError, match="No active session"):
        send_cover_once(use_http_mimicry=False)


def test_send_cover_once_with_session():
    """Test sending cover traffic with active session."""
    node = MockNode()
    set_active_node(node, "192.168.1.1", 8080, "peer1")
    
    # Clear previous messages
    node.sent_messages.clear()
    
    send_cover_once(use_http_mimicry=False)
    
    # Should have sent one message
    assert len(node.sent_messages) == 1
    sent = node.sent_messages[0]
    
    # Check routing
    assert sent["peer_ip"] == "192.168.1.1"
    assert sent["peer_port"] == 8080
    assert sent["peer_name"] == "peer1"
    
    # Message should indicate cover traffic
    assert "[COVER:" in sent["msg"]


def test_send_cover_once_with_http_mimicry():
    """Test sending cover traffic with HTTP mimicry enabled."""
    node = MockNode()
    set_active_node(node, "10.0.0.1", 9999, "peer2")
    
    node.sent_messages.clear()
    send_cover_once(use_http_mimicry=True)
    
    # Should still send (mimicry is applied internally)
    assert len(node.sent_messages) == 1


def test_start_cover_traffic_thread():
    """Test starting cover traffic background thread."""
    node = MockNode()
    set_active_node(node, "127.0.0.1", 5555, "test")
    
    stop_flag = threading.Event()
    node.sent_messages.clear()
    
    # Start with very short intervals for testing
    thread = start_cover_traffic(min_s=0, max_s=1, use_http_mimicry=False, stop_flag=stop_flag)
    
    # Thread should be alive
    assert thread.is_alive()
    
    # Wait a bit for some messages
    time.sleep(2.5)
    
    # Stop the thread
    stop_flag.set()
    thread.join(timeout=2)
    
    # Should have sent some messages (at least 2 in 2.5 seconds with 0-1s interval)
    assert len(node.sent_messages) >= 2


def test_start_cover_traffic_stops_on_flag():
    """Test that cover traffic stops when flag is set."""
    node = MockNode()
    set_active_node(node, "127.0.0.1", 5555, "test")
    
    stop_flag = threading.Event()
    node.sent_messages.clear()
    
    thread = start_cover_traffic(min_s=0, max_s=1, use_http_mimicry=False, stop_flag=stop_flag)
    
    # Let it run briefly
    time.sleep(0.5)
    
    # Stop immediately
    stop_flag.set()
    thread.join(timeout=2)
    
    # Record count
    count_after_stop = len(node.sent_messages)
    
    # Wait more and ensure no new messages
    time.sleep(1.5)
    
    # Should not have increased
    assert len(node.sent_messages) == count_after_stop


def test_cover_traffic_handles_session_not_ready():
    """Test that cover traffic gracefully handles session not being ready."""
    import addons.scorpiosync_adapter as adapter
    adapter._active_node = None
    adapter._peer_config = None
    
    stop_flag = threading.Event()
    
    # Start cover traffic without session
    thread = start_cover_traffic(min_s=0, max_s=1, use_http_mimicry=False, stop_flag=stop_flag)
    
    # Should start without error
    assert thread.is_alive()
    
    # Let it try to send (should silently fail)
    time.sleep(1)
    
    # Stop
    stop_flag.set()
    thread.join(timeout=2)
    
    # Should not crash
    assert not thread.is_alive()
