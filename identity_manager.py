
import os
import json
import nacl.signing
import nacl.encoding

IDENTITY_DIR = os.path.expanduser("~/.spectralship_identities")
os.makedirs(IDENTITY_DIR, exist_ok=True)

def list_identities():
    return [f[:-4] for f in os.listdir(IDENTITY_DIR) if f.endswith(".key")]

def create_identity(name):
    key = nacl.signing.SigningKey.generate()
    path = os.path.join(IDENTITY_DIR, name + ".key")
    with open(path, "wb") as f:
        f.write(key.encode())

def load_identity(name):
    path = os.path.join(IDENTITY_DIR, name + ".key")
    with open(path, "rb") as f:
        sk = nacl.signing.SigningKey(f.read())
        return sk, sk.verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode("utf-8")
