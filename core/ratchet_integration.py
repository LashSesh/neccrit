from __future__ import annotations

import json
import time
from typing import Optional

from core.ratchet import DoubleRatchet, Header
from core.crypto_layer import fernet_decrypt, fernet_encrypt


class RatchetSession:
    def __init__(
        self,
        root_key0: bytes,
        is_initiator: bool,
        peer_dh_pub: Optional[bytes] = None,
        local_dh_priv: Optional[bytes] = None,
    ):
        self.dr = DoubleRatchet(root_key0, is_initiator, peer_dh_pub, local_dh_priv)

    def encrypt_frame(self, payload: dict) -> dict:
        header, fkey = self.dr.next_sending_key()
        ciphertext = fernet_encrypt(json.dumps(payload).encode("utf-8"), fkey)
        return {
            "header": {
                "dh_pub": header.dh_pub.hex(),
                "pn": header.pn,
                "n": header.n,
                "ts": int(time.time()),
            },
            "ct": ciphertext.hex(),
        }

    def decrypt_frame(self, frame: dict) -> dict:
        hdr = frame["header"]
        header = Header(bytes.fromhex(hdr["dh_pub"]), hdr["pn"], hdr["n"])
        fkey = self.dr.receive(header)
        plaintext = fernet_decrypt(bytes.fromhex(frame["ct"]), fkey)
        return json.loads(plaintext.decode("utf-8"))
