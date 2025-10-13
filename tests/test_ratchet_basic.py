import pytest

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


def test_receive_handles_out_of_order_across_ratchet():
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

    header_b0, key_b0 = bob_ratchet.next_sending_key()
    header_b1, key_b1 = bob_ratchet.next_sending_key()

    # Alice sends a message so Bob advances his sending ratchet.
    header_a0, _ = alice_ratchet.next_sending_key()
    bob_ratchet.receive(header_a0)

    header_b2, key_b2 = bob_ratchet.next_sending_key()

    # Deliver the new ratchet message first.
    key_b2_alice = alice_ratchet.receive(header_b2)
    assert key_b2_alice == key_b2

    # Old chain messages can still be decrypted from the skipped cache.
    key_b1_alice = alice_ratchet.receive(header_b1)
    key_b0_alice = alice_ratchet.receive(header_b0)

    assert key_b1_alice == key_b1
    assert key_b0_alice == key_b0

    # Replaying a consumed skipped message is rejected.
    with pytest.raises(ValueError):
        alice_ratchet.receive(header_b1)


def test_receive_rejects_duplicate_messages():
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

    header, key = bob_ratchet.next_sending_key()
    assert alice_ratchet.receive(header) == key

    with pytest.raises(ValueError):
        alice_ratchet.receive(header)
