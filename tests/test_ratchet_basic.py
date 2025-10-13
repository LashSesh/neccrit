from core.ratchet import DoubleRatchet, hkdf
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def test_ratchet_roundtrip():
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    shared_ab = alice_priv.exchange(bob_priv.public_key())
    shared_ba = bob_priv.exchange(alice_priv.public_key())
    root_a = hkdf(shared_ab, length=32)
    root_b = hkdf(shared_ba, length=32)

    bob_pub_bytes = bob_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    alice_pub_bytes = alice_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    alice_priv_bytes = alice_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    bob_priv_bytes = bob_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    alice_ratchet = DoubleRatchet(
        root_a,
        is_initiator=True,
        peer_dh_pub=bob_pub_bytes,
        local_dh_priv=alice_priv_bytes,
    )
    bob_ratchet = DoubleRatchet(
        root_b,
        is_initiator=False,
        peer_dh_pub=alice_pub_bytes,
        local_dh_priv=bob_priv_bytes,
    )

    header1, key1 = alice_ratchet.next_sending_key()
    key1_bob = bob_ratchet.receive(header1)
    assert key1 == key1_bob

    header2, key2 = bob_ratchet.next_sending_key()
    key2_alice = alice_ratchet.receive(header2)
    assert key2 == key2_alice
