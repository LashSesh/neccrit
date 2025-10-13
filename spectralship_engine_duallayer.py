"""
spectralship_engine_duallayer.py - Tripolar+AES PrivacyChat-Engine
"""
import base64
import json
import secrets
import socket
import struct
import threading
import time
from collections import OrderedDict, defaultdict, deque

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from oscillator_core import OscillatorCore
from entropy_seed import generate_seed
from tripolar_mask import tripolar_mask, tripolar_unmask
from crypto_layer import decrypt_bytes, derive_handshake_psk, encrypt_bytes

class SpectralNode:
    def __init__(self, name, port, resonance_code, kappa, theta, crypto_pw):
        self.name = name
        self.port = port
        self.resonance_code = resonance_code  # Shared Secret
        self.kappa = kappa
        self.theta = theta
        self.crypto_pw = crypto_pw
        self.osc = OscillatorCore([1,2,3,4,5,6,7,8,9,10,11])
        self.history = []
        self.running = False
        self.message_ttl = 300
        self.max_seen_ids = 10_000
        self._seen_msg_ids = defaultdict(OrderedDict)
        self._seen_lock = threading.Lock()
        self.max_frame_size = 256 * 1024
        self.socket_timeout = 10
        self.connection_window = 30
        self.max_connections_per_window = 20
        self._connection_history = defaultdict(deque)
        self._rate_lock = threading.Lock()

    @staticmethod
    def _wipe(buffer: bytearray) -> None:
        for i in range(len(buffer)):
            buffer[i] = 0

    def _send_frame(self, conn: socket.socket, payload: bytes) -> None:
        if len(payload) > self.max_frame_size:
            raise ValueError("Zu großer Frame zum Senden")
        frame = struct.pack(">I", len(payload)) + payload
        conn.sendall(frame)

    def _recv_exact(self, conn: socket.socket, length: int) -> bytes:
        data = b""
        remaining = length
        while remaining > 0:
            chunk = conn.recv(remaining)
            if not chunk:
                raise ValueError("Unvollständige Daten empfangen")
            data += chunk
            remaining -= len(chunk)
        return data

    def _recv_frame(self, conn: socket.socket) -> bytes:
        length_prefix = self._recv_exact(conn, 4)
        (frame_length,) = struct.unpack(">I", length_prefix)
        if frame_length > self.max_frame_size:
            raise ValueError("Empfangener Frame überschreitet Limit")
        return self._recv_exact(conn, frame_length)

    def _allow_connection(self, ip: str) -> bool:
        now = time.time()
        with self._rate_lock:
            history = self._connection_history[ip]
            while history and now - history[0] > self.connection_window:
                history.popleft()
            if len(history) >= self.max_connections_per_window:
                return False
            history.append(now)
        return True

    def _derive_session_secret(self, shared_secret: bytes) -> str:
        psk_material = bytearray(derive_handshake_psk(self.crypto_pw))
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=bytes(psk_material),
                info=b"neccrit session",
            )
            session_key = hkdf.derive(shared_secret)
            return base64.urlsafe_b64encode(session_key).decode("ascii")
        finally:
            self._wipe(psk_material)

    def _record_message(self, peer_id, msg_id, timestamp) -> bool:
        if not isinstance(msg_id, str) or not isinstance(timestamp, int):
            return False
        now = time.time()
        if abs(now - timestamp) > self.message_ttl:
            return False
        with self._seen_lock:
            store = self._seen_msg_ids[peer_id]
            to_remove = []
            for key, stored_ts in list(store.items()):
                if now - stored_ts > self.message_ttl:
                    to_remove.append(key)
                else:
                    break
            for key in to_remove:
                del store[key]
            if msg_id in store:
                return False
            store[msg_id] = timestamp
            store.move_to_end(msg_id)
            while len(store) > self.max_seen_ids:
                store.popitem(last=False)
        return True

    def _handshake_initiator(self, conn: socket.socket) -> str:
        private_key = X25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        nonce = secrets.token_bytes(16)
        handshake_init = {
            "type": "handshake_init",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "public_key": base64.b64encode(public_bytes).decode("ascii"),
            "version": 1,
        }
        self._send_frame(conn, json.dumps(handshake_init).encode("utf-8"))
        response = json.loads(self._recv_frame(conn).decode("utf-8"))
        if response.get("type") != "handshake_ack":
            raise ValueError("Ungültige Handshake-Antwort")
        if response.get("nonce") != handshake_init["nonce"]:
            raise ValueError("Handshake Nonce stimmt nicht überein")
        peer_pub = base64.b64decode(response["public_key"])
        shared_secret = private_key.exchange(X25519PublicKey.from_public_bytes(peer_pub))
        return self._derive_session_secret(shared_secret)

    def _handshake_responder(self, conn: socket.socket) -> str:
        message = json.loads(self._recv_frame(conn).decode("utf-8"))
        if message.get("type") != "handshake_init":
            raise ValueError("Unerwarteter Handshake-Start")
        peer_pub = base64.b64decode(message["public_key"])
        nonce = message.get("nonce")
        private_key = X25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared_secret = private_key.exchange(X25519PublicKey.from_public_bytes(peer_pub))
        handshake_ack = {
            "type": "handshake_ack",
            "nonce": nonce,
            "public_key": base64.b64encode(public_bytes).decode("ascii"),
            "version": 1,
        }
        self._send_frame(conn, json.dumps(handshake_ack).encode("utf-8"))
        return self._derive_session_secret(shared_secret)

    def _resonant(self, fragment):
        s = sum(fragment)
        try:
            return int(s) % int(self.resonance_code) == 0
        except Exception:
            return False

    def start_listening(self, on_receive=None):
        def server():
            self.running = True
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", self.port))
                s.listen(5)
                print(f"[{self.name}] Lauscht auf Port {self.port}...")
                while self.running:
                    try:
                        conn, addr = s.accept()
                        if not self._allow_connection(addr[0]):
                            print(f"[{self.name}] Verbindung von {addr[0]} aufgrund Rate-Limit verworfen.")
                            conn.close()
                            continue
                        conn.settimeout(self.socket_timeout)
                        with conn:
                            session_secret = self._handshake_responder(conn)
                            ciphertext = self._recv_frame(conn)
                            try:
                                payload_raw = decrypt_bytes(ciphertext, session_secret)
                                payload = json.loads(payload_raw.decode("utf-8"))
                                peer_id = (addr[0], payload.get("sender"))
                                if not self._record_message(peer_id, payload.get("msg_id"), payload.get("ts")):
                                    print(f"[{self.name}] Replay oder zu alte Nachricht von {payload.get('sender')}.")
                                    continue
                                masked = payload["fragment"]
                                seed = payload["seed"]
                                sender = payload["sender"]
                                t = payload["t"]
                                kappa = payload["kappa"]
                                theta = payload["theta"]
                                frag = tripolar_unmask(masked, kappa, theta, seed, t)
                                if self._resonant(frag):
                                    text = "".join([chr(int(round(x))) for x in frag if x>0 and x<1114111])
                                    self.history.append((sender, text))
                                    print(f"[{self.name}] Von {sender}: {text}")
                                    if on_receive: on_receive(sender, text)
                                else:
                                    print(f"[{self.name}] Nicht resonant: Nachricht von {sender} ignoriert.")
                            except Exception as e:
                                print(f"[{self.name}] Fehler beim Entpacken: {e}")
                    except Exception as e:
                        print(f"[{self.name}] Socket-Fehler: {e}")
        threading.Thread(target=server, daemon=True).start()

    def send_fragment(self, msg, peer_ip, peer_port, peer_name):
        signal = [ord(c) for c in msg]
        profile = self.osc.spectral_profile(signal)
        seed = generate_seed(length=2)
        seed_float = int.from_bytes(seed, "big") / 5000.0 + 1
        t = list(range(len(profile)))
        masked = tripolar_mask(profile, self.kappa, self.theta, seed_float, t)
        payload = {
            "fragment": masked,
            "seed": seed_float,
            "sender": self.name,
            "t": t,
            "kappa": self.kappa,
            "theta": self.theta,
            "msg_id": secrets.token_hex(16),
            "ts": int(time.time()),
        }
        payload_json = json.dumps(payload).encode("utf-8")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.socket_timeout)
            s.connect((peer_ip, peer_port))
            session_secret = self._handshake_initiator(s)
            ciphertext = encrypt_bytes(payload_json, session_secret)
            self._send_frame(s, ciphertext)
        print(f"[{self.name}] Nachricht an {peer_name} gesendet!")

    def show_history(self):
        print(f"\n--- Verlauf für {self.name} ---")
        for sender, msg in self.history:
            print(f"  {sender} → {self.name}: {msg}")
        print("-"*30)

    def stop(self):
        self.running = False
