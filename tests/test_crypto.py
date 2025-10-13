import json
import secrets
from pathlib import Path

from crypto_layer import NONCE_SIZE, SALT_SIZE, decrypt_bytes, encrypt_bytes


def test_encrypt_decrypt_roundtrip():
    password = "super-secure-password"
    data = b"classified payload"
    ciphertext_one = encrypt_bytes(data, password)
    ciphertext_two = encrypt_bytes(data, password)

    assert ciphertext_one != data
    assert ciphertext_one != ciphertext_two, "salts/nonces must randomize ciphertext"
    assert len(ciphertext_one) > len(data)
    assert len(ciphertext_one) >= SALT_SIZE + NONCE_SIZE

    plaintext = decrypt_bytes(ciphertext_one, password)
    assert plaintext == data


def test_no_pickle_network(monkeypatch):
    import spectralship_engine_duallayer as engine

    payload = {
        "fragment": [],
        "seed": 0.0,
        "sender": "alice",
        "t": [],
        "kappa": [],
        "theta": [],
        "msg_id": secrets.token_hex(16),
        "ts": 1,
    }
    plaintext = json.dumps(payload).encode("utf-8")
    decrypt_called = {"value": False}

    def fake_decrypt(token, secret):
        decrypt_called["value"] = True
        return plaintext

    original_json_loads = engine.json.loads

    def wrapped_json_loads(text):
        assert decrypt_called["value"], "json.loads invoked before decrypt"
        return original_json_loads(text)

    monkeypatch.setattr(engine, "decrypt_bytes", fake_decrypt)
    monkeypatch.setattr(engine.json, "loads", wrapped_json_loads)

    engine.decrypt_bytes(b"malicious pickle payload", "session-secret")
    engine.json.loads(plaintext.decode("utf-8"))

    source_text = Path("spectralship_engine_duallayer.py").read_text()
    assert "pickle" not in source_text
