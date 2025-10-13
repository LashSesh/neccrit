"""crypto_layer.py - Sichere Verschlüsselungsschicht (Fernet/AES)."""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32
SALT_SIZE = 16
HANDSHAKE_LABEL = b"neccrit-handshake-psk"


def _zeroize(buffer: bytearray) -> None:
    for i in range(len(buffer)):
        buffer[i] = 0


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key using scrypt with the provided salt."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes long")
    kdf = Scrypt(salt=salt, length=SCRYPT_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    derived = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def derive_handshake_psk(password: str) -> bytes:
    """Derive a deterministic PSK used to salt the HKDF during handshakes."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    digest = hashlib.sha256(password.encode("utf-8") + HANDSHAKE_LABEL).digest()
    salt = digest[:SALT_SIZE]
    kdf = Scrypt(salt=salt, length=SCRYPT_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt *data* with a password using Fernet and prepend the salt."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    salt = os.urandom(SALT_SIZE)
    key_material = bytearray(derive_key(password, salt))
    try:
        token = Fernet(bytes(key_material)).encrypt(data)
    finally:
        _zeroize(key_material)
    return salt + token


def decrypt_bytes(token: bytes, password: str) -> bytes:
    """Decrypt *token* that has the salt prefixed."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(token) <= SALT_SIZE:
        raise ValueError("Ciphertext is too short to contain salt and data")
    salt = token[:SALT_SIZE]
    ciphertext = token[SALT_SIZE:]
    key_material = bytearray(derive_key(password, salt))
    try:
        plaintext = Fernet(bytes(key_material)).decrypt(ciphertext)
    finally:
        _zeroize(key_material)
    return plaintext
