"""
Adapter for integrating scorpiosync generators with n'éccrit transport layer.

This module provides a bridge between the cover traffic generators and the
existing spectralship_engine_duallayer transport mechanisms.
"""
import json, random, threading, time
from typing import Optional
from .scorpiosync_generators_complete import fake_api_request_generator, http_builder_transformer, steganography_transformer


# Global state for session tracking (to be set by the application)
_active_node = None
_peer_config = None


COVER_SIGNAL_PREFIX = "[COVER:"
COVER_SIGNAL_SUFFIX = "]"


def format_cover_signal(frame_type: Optional[str]) -> str:
    """Return a compact marker string used for cover-traffic fragments."""
    sanitized = str(frame_type or "cover")
    return f"{COVER_SIGNAL_PREFIX}{sanitized}{COVER_SIGNAL_SUFFIX}"


def is_cover_signal(message: Optional[str]) -> bool:
    """Return True when ``message`` represents a cover-traffic marker."""
    return isinstance(message, str) and message.startswith(COVER_SIGNAL_PREFIX) and message.endswith(COVER_SIGNAL_SUFFIX)


def set_active_node(node, peer_ip: str, peer_port: int, peer_name: str):
    """
    Configure the active node and peer for cover traffic transmission.
    
    Args:
        node: SpectralNode instance
        peer_ip: Peer IP address
        peer_port: Peer port
        peer_name: Peer name
    """
    global _active_node, _peer_config
    _active_node = node
    _peer_config = {"ip": peer_ip, "port": peer_port, "name": peer_name}


def is_session_ready() -> bool:
    """Check if a session is ready for cover traffic transmission."""
    return _active_node is not None and _peer_config is not None and _active_node.running


def send_encrypted_json(frame: dict):
    """
    Send a cover traffic frame via the active session.
    
    The frame is sent as a regular spectralship message with type='cover'.
    This maintains compatibility with the existing transport layer.
    """
    if not is_session_ready():
        raise RuntimeError("No active session available for cover traffic")
    
    # Convert the cover frame to a message that can be sent via spectralship
    # We use a minimal signal to encode just the type information
    cover_msg = format_cover_signal(frame.get('type', 'cover'))
    _active_node.send_fragment(
        cover_msg,
        _peer_config["ip"],
        _peer_config["port"],
        _peer_config["name"]
    )


def maybe_transform_plaintext(plaintext: str, use_stegano: bool) -> str:
    """
    Optionally apply steganographic transformation to plaintext.
    
    Args:
        plaintext: Input text
        use_stegano: Whether to apply zero-width steganography
        
    Returns:
        Transformed or original plaintext
    """
    return steganography_transformer(plaintext) if use_stegano else plaintext


def send_cover_once(use_http_mimicry: bool):
    """
    Send a single cover traffic packet.
    
    Args:
        use_http_mimicry: Whether to format as HTTP request
    """
    payload = fake_api_request_generator()
    frame = {"type": "cover", "payload": payload, "ts": int(time.time())}
    if use_http_mimicry:
        # Generate HTTP-formatted bytes (for potential future use/logging)
        _ = http_builder_transformer(payload, include_length_prefix=False)
    send_encrypted_json(frame)


def start_cover_traffic(min_s: int, max_s: int, use_http_mimicry: bool, stop_flag: threading.Event) -> threading.Thread:
    """
    Start a background thread that sends periodic cover traffic.
    
    Args:
        min_s: Minimum interval between cover packets (seconds)
        max_s: Maximum interval between cover packets (seconds)
        use_http_mimicry: Whether to use HTTP-mimicking format
        stop_flag: Threading event to signal stop
        
    Returns:
        Thread handle for the cover traffic generator
    """
    def _loop():
        while not stop_flag.is_set():
            if is_session_ready():
                try:
                    send_cover_once(use_http_mimicry)
                except Exception:
                    pass  # Silently ignore errors to avoid disrupting main communication
            time.sleep(random.randint(min_s, max_s))
    
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t
