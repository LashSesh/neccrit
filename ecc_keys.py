
import nacl.signing
import nacl.encoding
import os

KEYDIR = os.path.expanduser("~/.spectralship_keys")
PRIVFILE = os.path.join(KEYDIR, "ecc_private.key")
PUBFILE = os.path.join(KEYDIR, "ecc_public.key")

def ensure_keypair():
    if not os.path.exists(KEYDIR):
        os.makedirs(KEYDIR)
    if not os.path.exists(PRIVFILE):
        sk = nacl.signing.SigningKey.generate()
        with open(PRIVFILE, "wb") as f:
            f.write(sk.encode())
        with open(PUBFILE, "wb") as f:
            f.write(sk.verify_key.encode())
    else:
        with open(PRIVFILE, "rb") as f:
            sk = nacl.signing.SigningKey(f.read())
    with open(PUBFILE, "rb") as f:
        vk = nacl.signing.VerifyKey(f.read())
    return sk, vk

def get_pubkey_b64():
    _, vk = ensure_keypair()
    return vk.encode(encoder=nacl.encoding.Base64Encoder).decode("utf-8")

def sign_message(msg_bytes):
    sk, _ = ensure_keypair()
    signed = sk.sign(msg_bytes)
    return signed.signature

def verify_signature(msg_bytes, sig_bytes, pubkey_b64):
    vk = nacl.signing.VerifyKey(pubkey_b64.encode("utf-8"), encoder=nacl.encoding.Base64Encoder)
    try:
        vk.verify(msg_bytes, sig_bytes)
        return True
    except Exception:
        return False
