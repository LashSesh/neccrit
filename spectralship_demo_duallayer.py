"""
spectralship_demo_duallayer.py - Dual-Layer Tripolar PrivacyChat CLI-Demo
"""
from spectralship_engine_duallayer import SpectralNode
import threading, time

def input_peer():
    ip = input("Peer-IP (127.0.0.1 für lokal): ").strip() or "127.0.0.1"
    port = int(input("Peer-Port (z.B. 55555): ").strip() or "55555")
    name = input("Peer-Name: ").strip() or "Peer"
    return ip, port, name

def input_kappa_theta(n=3):
    print(f"Kopplungsstärken kappa (für {n} Pole, Komma-separiert, z.B. 2.5,3.1,4.7):")
    kappa = [float(x) for x in input("kappa: ").split(",")[:n]]
    print(f"Phasen theta (für {n} Pole, Komma-separiert, z.B. 0.1,1.3,2.1):")
    theta = [float(x) for x in input("theta: ").split(",")[:n]]
    return kappa, theta

if __name__ == "__main__":
    print("Dual-Layer SPECTRALSHIP PrivacyChat-Demo\n")
    name = input("Dein Name: ").strip() or "User"
    port = int(input("Dein Port (z.B. 55555): ").strip() or "55555")
    code = input("Resonanzcode (gemeinsames Secret/Zahl): ").strip() or "1337"
    n_pole = int(input("Anzahl Pole für Tripolar-Maske (mind. 3): ").strip() or "3")
    kappa, theta = input_kappa_theta(n_pole)
    crypto_pw = input("AES-256-GCM Passwort (Secret, beide Seiten gleich!): ").strip()
    node = SpectralNode(name, port, code, kappa, theta, crypto_pw)
    node.start_listening()
    print("\nStarte weiteren Node im anderen Terminal/auf anderem Gerät und verbinde euch gegenseitig!")
    print("Befehl: /exit zum Beenden, /hist für Verlauf, /peer für Peer-Wechsel")
    peer_ip, peer_port, peer_name = input_peer()
    while True:
        msg = input(f"{name} > ").strip()
        if msg == "/exit":
            node.stop()
            print("Bye!")
            break
        if msg == "/hist":
            node.show_history()
            continue
        if msg == "/peer":
            peer_ip, peer_port, peer_name = input_peer()
            continue
        if msg:
            try:
                node.send_fragment(msg, peer_ip, peer_port, peer_name)
            except Exception as e:
                print(f"[Fehler beim Senden: {e}]")
        time.sleep(0.05)
