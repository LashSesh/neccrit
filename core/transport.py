"""Session utilities bridging ScorpioSync cover traffic to the core transport."""
from __future__ import annotations
from typing import Optional

_active_node = None
_peer_config = None

COVER_SIGNAL_PREFIX = "[COVER:"
COVER_SIGNAL_SUFFIX = "]"


def set_active_session(node, peer_ip: str, peer_port: int, peer_name: str) -> None:
    """Register the active SpectralNode session used for cover traffic."""
    global _active_node, _peer_config
    _active_node = node
    _peer_config = {"ip": peer_ip, "port": peer_port, "name": peer_name}


def clear_active_session() -> None:
    """Clear any active session information."""
    global _active_node, _peer_config
    _active_node = None
    _peer_config = None


def is_session_ready() -> bool:
    """Return True when an active, running SpectralNode session is available."""
    return (
        _active_node is not None
        and _peer_config is not None
        and getattr(_active_node, "running", False)
    )


def format_cover_signal(frame_type: Optional[str]) -> str:
    """Return a marker string representing a cover traffic frame."""
    sanitized = str(frame_type or "cover")
    return f"{COVER_SIGNAL_PREFIX}{sanitized}{COVER_SIGNAL_SUFFIX}"


def is_cover_signal(message: Optional[str]) -> bool:
    """Return True when ``message`` appears to be a cover traffic marker."""
    return (
        isinstance(message, str)
        and message.startswith(COVER_SIGNAL_PREFIX)
        and message.endswith(COVER_SIGNAL_SUFFIX)
    )


def send_encrypted_json(frame: dict) -> None:
    """Send a cover traffic frame via the active SpectralNode session."""
    if not is_session_ready():
        raise RuntimeError("No active session available for cover traffic")

    cover_msg = format_cover_signal(frame.get("type", "cover"))
    _active_node.send_fragment(
        cover_msg,
        _peer_config["ip"],
        _peer_config["port"],
        _peer_config["name"],
    )


__all__ = [
    "set_active_session",
    "clear_active_session",
    "is_session_ready",
    "format_cover_signal",
    "is_cover_signal",
    "send_encrypted_json",
]
