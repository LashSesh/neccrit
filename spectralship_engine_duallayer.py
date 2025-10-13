"""
spectralship_engine_duallayer.py - Tripolar+AES PrivacyChat-Engine
"""
import socket, threading, pickle
from oscillator_core import OscillatorCore
from entropy_seed import generate_seed
from tripolar_mask import tripolar_mask, tripolar_unmask
from crypto_layer import derive_key, encrypt_bytes, decrypt_bytes

class SpectralNode:
    def __init__(self, name, port, resonance_code, kappa, theta, crypto_pw):
        self.name = name
        self.port = port
        self.resonance_code = resonance_code  # Shared Secret
        self.kappa = kappa
        self.theta = theta
        self.crypto_pw = crypto_pw
        self.crypto_key = derive_key(crypto_pw)
        self.osc = OscillatorCore([1,2,3,4,5,6,7,8,9,10,11])
        self.history = []
        self.running = False

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
                        with conn:
                            data = b""
                            while True:
                                chunk = conn.recv(4096)
                                if not chunk: break
                                data += chunk
                            try:
                                enc_payload = pickle.loads(data)
                                payload_raw = decrypt_bytes(enc_payload["payload"], self.crypto_key)
                                payload = pickle.loads(payload_raw)
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
            "theta": self.theta
        }
        payload_bytes = pickle.dumps(payload)
        enc_payload = {"payload": encrypt_bytes(payload_bytes, self.crypto_key)}
        data = pickle.dumps(enc_payload)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((peer_ip, peer_port))
            s.sendall(data)
        print(f"[{self.name}] Nachricht an {peer_name} gesendet!")

    def show_history(self):
        print(f"\n--- Verlauf für {self.name} ---")
        for sender, msg in self.history:
            print(f"  {sender} → {self.name}: {msg}")
        print("-"*30)

    def stop(self):
        self.running = False
