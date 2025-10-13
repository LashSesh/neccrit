
import nacl.signing
import nacl.encoding

class EphemeralSessionKeyManager:
    def __init__(self):
        self.session_sk = None
        self.session_vk = None
        self.peer_session_vk = None

    def generate_session_keypair(self):
        self.session_sk = nacl.signing.SigningKey.generate()
        self.session_vk = self.session_sk.verify_key

    def export_session_pubkey(self):
        if self.session_vk is None:
            return None
        return self.session_vk.encode(encoder=nacl.encoding.Base64Encoder).decode("utf-8")

    def import_peer_session_pubkey(self, peer_pubkey_b64):
        self.peer_session_vk = nacl.signing.VerifyKey(peer_pubkey_b64.encode("utf-8"), encoder=nacl.encoding.Base64Encoder)

    def sign_with_session(self, msg_bytes):
        if self.session_sk is None:
            raise Exception("Session key not generated")
        signed = self.session_sk.sign(msg_bytes)
        return signed.signature

    def verify_with_peer_session(self, msg_bytes, sig_bytes):
        if self.peer_session_vk is None:
            raise Exception("Peer session key not set")
        try:
            self.peer_session_vk.verify(msg_bytes, sig_bytes)
            return True
        except Exception:
            return False

    def destroy_session_keys(self):
        self.session_sk = None
        self.session_vk = None
        self.peer_session_vk = None
