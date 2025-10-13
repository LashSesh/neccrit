"""
crypto_layer.py - Sichere Verschlüsselungsschicht (Fernet/AES)
"""
from cryptography.fernet import Fernet
import base64
import hashlib

def derive_key(password: str):
    # Leitet Fernet-Key von Passwort ab (SHA256 -> base64)
    h = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(h)

def encrypt_bytes(data: bytes, key: bytes):
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_bytes(token: bytes, key: bytes):
    f = Fernet(key)
    return f.decrypt(token)
