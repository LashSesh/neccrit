"""
entropy_seed.py - Generiert Seeds für sichere Tunnel-Kommunikation
"""
import os
def generate_seed(length=16):
    """Erzeugt einen sicheren zufälligen Seed als Byte-String."""
    return os.urandom(length)
def seed_to_int(seed):
    """Wandelt Seed (bytes) in int um."""
    return int.from_bytes(seed, 'big')
