from __future__ import annotations

from cryptography.fernet import Fernet


def _as_bytes(key: bytes | bytearray) -> bytes:
    if isinstance(key, bytearray):
        return bytes(key)
    if isinstance(key, bytes):
        return key
    raise TypeError("key must be bytes")


def fernet_encrypt(data: bytes, key: bytes | bytearray) -> bytes:
    return Fernet(_as_bytes(key)).encrypt(data)


def fernet_decrypt(token: bytes, key: bytes | bytearray) -> bytes:
    return Fernet(_as_bytes(key)).decrypt(token)


__all__ = ["fernet_encrypt", "fernet_decrypt"]
