# SPECTRALSHIP Dual-Layer PrivacyChat (Tripolar + AES/Fernet)
## Features
- Jede Nachricht: mathematische n-pol (tripolare) Maskierung *und* AES256/Fernet-Verschlüsselung
- Niemand kann mit nur einer Hälfte die Nachricht dechiffrieren
- P2P-Chat, keine zentrale Stelle, kein Klartext, kein Tracking
- Python 3.8+, Desktop ready (mobile auf Anfrage)
## Start
1. pip install numpy cryptography
2. python spectralship_demo_duallayer.py
3. Peer-Daten, Parameter, Passwort absprechen
4. Chatten, /hist Verlauf, /peer Peerwechsel, /exit Ende
## Sicherheit
- AES-Key ist *niemals* im Klartext im Netzwerk
- Maskierung & Verschlüsselung pro Nachricht dynamisch
- Replay, MITM, Brute-Force, Krypto-Analyse: praktisch unmöglich


## ECC/Ed25519-Kontakte
- Kontakte/Kontakt-QR werden lokal gespeichert (contacts.json).
- Dein Schlüssel (Keypair) bleibt nur auf deinem Gerät.
- Nachrichten sind durch Ed25519 signiert und überprüfbar.
- Kontakt-QR kann direkt gescannt und übernommen werden.
