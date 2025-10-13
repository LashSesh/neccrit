from __future__ import annotations
import base64
import os
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf(
    ikm: bytes,
    length: int = 64,
    info: bytes = b"neccrit-ratchet",
    salt: Optional[bytes] = None,
) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def kdf_root(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    okm = hkdf(root_key + dh_out, length=64, info=b"root")
    return okm[:32], okm[32:]


def kdf_initial(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes, bytes]:
    okm = hkdf(root_key + dh_out, length=96, info=b"root-init")
    return okm[:32], okm[32:64], okm[64:96]


def kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
    okm = hkdf(chain_key, length=64, info=b"chain")
    return okm[:32], okm[32:]


def fernet_key_from_mk(mk: bytes) -> bytes:
    return base64.urlsafe_b64encode(mk)


@dataclass
class Header:
    dh_pub: bytes
    pn: int
    n: int


@dataclass
class State:
    root_key: bytes
    dh_priv: X25519PrivateKey
    dh_pub: bytes
    dh_remote: Optional[bytes]
    CKs: bytes
    CKr: bytes
    Ns: int = 0
    Nr: int = 0
    PNs: int = 0
    skipped: Dict[Tuple[bytes, int], bytes] = field(default_factory=dict)
    max_skipped: int = 2000
    processed: Set[Tuple[bytes, int]] = field(default_factory=set)


class DoubleRatchet:
    def __init__(
        self,
        root_key0: bytes,
        is_initiator: bool,
        peer_dh_pub: Optional[bytes] = None,
        local_dh_priv: Optional[bytes] = None,
    ):
        self.state = self._init_state(root_key0, is_initiator, peer_dh_pub, local_dh_priv)

    def _init_state(
        self,
        root_key0: bytes,
        is_initiator: bool,
        peer_dh_pub: Optional[bytes],
        local_dh_priv: Optional[bytes],
    ) -> State:
        if local_dh_priv is not None:
            dh_priv = X25519PrivateKey.from_private_bytes(local_dh_priv)
        else:
            dh_priv = X25519PrivateKey.generate()
        dh_pub = dh_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        CKs = os.urandom(32)
        CKr = os.urandom(32)
        st = State(
            root_key=root_key0,
            dh_priv=dh_priv,
            dh_pub=dh_pub,
            dh_remote=peer_dh_pub,
            CKs=CKs,
            CKr=CKr,
        )
        if peer_dh_pub is not None:
            dh_out = dh_priv.exchange(X25519PublicKey.from_public_bytes(peer_dh_pub))
            new_root, send_ck, recv_ck = kdf_initial(root_key0, dh_out)
            st.root_key = new_root
            if is_initiator:
                st.CKs = send_ck
                st.CKr = recv_ck
            else:
                st.CKs = recv_ck
                st.CKr = send_ck
        return st

    def ratchet_step(self, peer_dh_pub: bytes) -> None:
        dh_out = self.state.dh_priv.exchange(X25519PublicKey.from_public_bytes(peer_dh_pub))
        self.state.root_key, self.state.CKr = kdf_root(self.state.root_key, dh_out)
        self.state.PNs = self.state.Ns
        self.state.Ns = 0
        self.state.Nr = 0
        self.state.dh_remote = peer_dh_pub
        self.state.dh_priv = X25519PrivateKey.generate()
        self.state.dh_pub = self.state.dh_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        dh_out2 = self.state.dh_priv.exchange(X25519PublicKey.from_public_bytes(peer_dh_pub))
        self.state.root_key, self.state.CKs = kdf_root(self.state.root_key, dh_out2)

    def next_sending_key(self) -> Tuple[Header, bytes]:
        self.state.CKs, mk = kdf_chain(self.state.CKs)
        header = Header(dh_pub=self.state.dh_pub, pn=self.state.PNs, n=self.state.Ns)
        self.state.Ns += 1
        return header, fernet_key_from_mk(mk)

    def _skip_message_keys(self, until: int, peer_dh_pub: bytes) -> None:
        while self.state.Nr < until:
            self.state.CKr, mk = kdf_chain(self.state.CKr)
            if len(self.state.skipped) < self.state.max_skipped:
                self.state.skipped[(peer_dh_pub, self.state.Nr)] = mk
            self.state.Nr += 1

    def receive(self, header: Header) -> bytes:
        key = (header.dh_pub, header.n)
        if key in self.state.skipped:
            mk = self.state.skipped.pop(key)
            self.state.processed.add(key)
            return fernet_key_from_mk(mk)
        if key in self.state.processed:
            raise ValueError("Duplicate message received")
        if self.state.dh_remote != header.dh_pub:
            if self.state.dh_remote is not None:
                if header.pn < self.state.Nr:
                    raise ValueError("Duplicate message received")
                self._skip_message_keys(header.pn, self.state.dh_remote)
            self.ratchet_step(header.dh_pub)
        if header.n < self.state.Nr:
            raise ValueError("Duplicate message received")
        self._skip_message_keys(header.n, header.dh_pub)
        self.state.CKr, mk = kdf_chain(self.state.CKr)
        self.state.Nr += 1
        self.state.processed.add(key)
        return fernet_key_from_mk(mk)
