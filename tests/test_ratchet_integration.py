from core.ratchet import hkdf
from core.ratchet_integration import RatchetSession
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def test_encrypt_decrypt_frame():
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    root_alice = hkdf(alice_priv.exchange(bob_priv.public_key()), length=32)
    root_bob = hkdf(bob_priv.exchange(alice_priv.public_key()), length=32)

    bob_pub_bytes = bob_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    alice_pub_bytes = alice_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    alice_priv_bytes = alice_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    bob_priv_bytes = bob_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    alice_session = RatchetSession(root_alice, True, bob_pub_bytes, alice_priv_bytes)
    bob_session = RatchetSession(root_bob, False, alice_pub_bytes, bob_priv_bytes)

    frame = alice_session.encrypt_frame({"msg": "hi"})
    plain = bob_session.decrypt_frame(frame)
    assert plain["msg"] == "hi"

    reply = bob_session.encrypt_frame({"msg": "pong"})
    roundtrip = alice_session.decrypt_frame(reply)
    assert roundtrip["msg"] == "pong"
