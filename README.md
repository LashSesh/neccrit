# n'éccrit – Spectralship Dual-Layer Privacy Chat

n'éccrit is an experimental peer-to-peer (P2P) secure messaging stack that mixes
mathematical signal masking with modern cryptography, system camouflage, and
traffic obfuscation. The project bundles a production-ready PyQt6 desktop GUI, a
command-line demo, reusable crypto/transport primitives, and optional addons for
surveillance awareness and cover traffic.

> **Disclaimer**
> This code base is provided for educational and research purposes. It has not
> been audited by professional cryptographers. Use strong secrets, understand
> the risks, and assess legal constraints in your jurisdiction before deploying
> outside of controlled environments.

---

## Table of Contents
- [Core Capabilities](#core-capabilities)
- [System Overview](#system-overview)
  - [Layered Security Pipeline](#layered-security-pipeline)
  - [Major Components](#major-components)
  - [Optional Subsystems](#optional-subsystems)
- [Installation](#installation)
- [Running the Applications](#running-the-applications)
  - [PyQt6 Desktop Client](#pyqt6-desktop-client)
  - [Command-Line Demo](#command-line-demo)
  - [Sharing Parameters via QR Codes](#sharing-parameters-via-qr-codes)
- [Critical Session Parameters](#critical-session-parameters)
- [Cover Traffic & HTTP Mimicry](#cover-traffic--http-mimicry)
- [AngelCore Surveillance Detection](#angelcore-surveillance-detection)
- [Troubleshooting](#troubleshooting)
- [Development Guide](#development-guide)
- [Project Structure](#project-structure)
- [License & Support](#license--support)
- [Deutsche Kurzfassung](#deutsche-kurzfassung)

---

## Core Capabilities
- 🔐 **Dual-layer protection** – Tripolar spectral masking plus AES-256-GCM
  authenticated encryption for every message.
- 🛰️ **Peer-to-peer networking** – Direct TCP connections, connection guarding,
  and replay protection with per-peer message histories.
- 🧠 **Surveillance awareness (optional)** – AngelCore heuristic sensor fusion to
  visually hide the chat when suspicious activity is detected.
- 🕵️ **Cover traffic (optional)** – ScorpioSync generators craft dummy payloads,
  variable intervals, and HTTP-mimicking envelopes.
- 💻 **Modern desktop UX** – PyQt6 interface with dark cyber theme, QR code
  parameter sharing, and runtime toggles for addons.
- 🧪 **Tested primitives** – Unit coverage for encryption, frame guards, addon
  generators, and rate-limit protections.

## System Overview
n'éccrit revolves around `SpectralNode`, a transport engine that converts text
into spectral fragments, adds tripolar masks, and wraps the payload inside a
cryptographically secure handshake. The GUI, CLI, and addon layers all build on
this node abstraction.

### Layered Security Pipeline
```
Plaintext input
    ↓ (FFT via OscillatorCore)
Spectral profile
    ↓ (tripolar_mask)
Masked fragment
    ↓ (JSON serialization)
Structured payload
    ↓ (X25519 + HKDF handshake → AES-256 session key)
AES-256-GCM authenticated ciphertext
    ↓ (Length-prefixed TCP frame)
Network transport
    ↓ (Peer decrypts & validates resonance code)
Recovered plaintext
```
Key safeguards include:
- **X25519 + HKDF handshake** to derive an ephemeral session secret salted by a
  deterministic PSK derived from the shared password.
- **Length-prefixed frames** with maximum size guards and replay tracking for
  each peer (`message_ttl`, `_seen_msg_ids`).
- **Tripolar resonance validation** so mismatched parameter sets are rejected
  before text is reconstructed.

### Major Components
| Module | Responsibility |
| --- | --- |
| `spectralship_engine_duallayer.py` | `SpectralNode` networking core, X25519 handshake, replay defense, tripolar masking integration. |
| `oscillator_core.py` | FFT-based spectral profile generator. |
| `tripolar_mask.py` | n-pole sinusoidal masking/unmasking utilities. |
| `crypto_layer.py` | Scrypt-based key derivation, AES-256-GCM authenticated encryption, HKDF PSK derivation. |
| `neccrit_pyqt6.py` | Production GUI with tabs for chat, settings, QR tooling, AngelCore controls. |
| `spectralship_demo_duallayer.py` | Minimal CLI workflow for headless testing. |
| `addons/scorpiosync_*.py` | Cover traffic generators and adapters. |
| `angelcore_spectralwatch.py` | Heuristic surveillance scoring and status classification. |
| `qr_utils.py` | QR code generation/decoding helpers. |
| `config.py` | Toggle cover-traffic behaviour (intervals, HTTP mimicry, steganography). |

### Optional Subsystems
- **AngelCore** – Fusion of CPU/RAM/mouse/microphone heuristics to report
  `SAFE`, `UNCERTAIN`, or `ALERT`. In GUI alert mode the interface hides text
  and disables inputs.
- **ScorpioSync** – Periodic dummy traffic using `ENABLE_COVER_TRAFFIC`,
  `ENABLE_HTTP_MIMICRY`, and optional zero-width steganography (off by default).
- **QR utilities** – Export/import of session parameters to reduce transcription
  errors when aligning peers.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/LashSesh/neccrit.git
   cd neccrit
   ```
2. Create a virtual environment (recommended) and install runtime dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
   Core dependencies include **numpy**, **PyQt6**, **cryptography**, **qrcode**,
   **Pillow**, and **pyzbar** for QR scanning.
3. Optional development extras:
   ```bash
   pip install -r requirements-dev.txt
   ```

## Running the Applications
### PyQt6 Desktop Client
```bash
python neccrit_pyqt6.py
```
1. Configure **Local Settings**: name, listening port, resonance code, kappa and
   theta vectors, and the shared crypto password.
2. Configure **Peer Settings**: remote IP, remote port, and display name.
3. (Optional) Enable **AngelCore** and/or cover traffic before starting the
   listener.
4. Click **Start Chat** to begin listening and use **Send** to transmit messages.

### Command-Line Demo
```bash
python spectralship_demo_duallayer.py
```
Follow the interactive prompts to set up both peers. The demo uses the same
`SpectralNode` engine and is handy for automation or headless hosts.

### Sharing Parameters via QR Codes
- Use **Show My QR Code** in the GUI to export the active configuration.
- Use **Load from QR Image** to import parameters captured from a partner.
- QR codes contain resonance code, kappa/theta arrays, ports, and passwords, so
  share only through trusted channels.

## Critical Session Parameters
All peers must align on:
- **Resonance code** – Integer used for tripolar resonance validation.
- **Kappa vector** – Coupling strengths for the tripolar mask (comma-separated
  floats, e.g. `2.5,3.1,4.7`).
- **Theta vector** – Phase offsets for the mask (e.g. `0.1,1.3,2.1`).
- **Crypto password** – Basis for Scrypt key derivation and handshake PSK.
- **Ports/IPs** – Each peer listens on their local port while connecting to the
  other's IP and port.

A mismatch in any of the above will lead to decryption failures or messages being
silently dropped as non-resonant.

## Cover Traffic & HTTP Mimicry
The ScorpioSync addon produces configurable dummy payloads:
- Enable by editing `config.py`:
  ```python
  ENABLE_COVER_TRAFFIC = True
  COVER_MIN_INTERVAL_S = 20
  COVER_MAX_INTERVAL_S = 45
  ENABLE_HTTP_MIMICRY = True
  ENABLE_ZW_STEGANO = False  # Off by default for responsible use
  ```
- `addons/scorpiosync_generators_complete.py` contains packet templates and
  schedulers.
- `example_cover_traffic_integration.py` demonstrates embedding the generators
  into a custom transport loop.

All fake traffic still traverses the cryptographic layer, blending with genuine
messages while obscuring observable timing and volume patterns.

## AngelCore Surveillance Detection
AngelCore evaluates CPU load, RAM idle percentage, mouse entropy, timing deltas,
and microphone noise floor to label the environment:
- `SAFE` – Normal metrics; chat operates normally.
- `UNCERTAIN` – Suspicious signals; GUI highlights caution but remains usable.
- `ALERT` – High risk; GUI blacks out history, disables input, and displays
  camouflage to deter shoulder surfing.

The feature is disabled by default and can be toggled from the GUI Settings tab.
No system-level hooks are installed unless you opt in.

## Troubleshooting
- **Port already in use** – Select a new port or terminate the conflicting
  process (`lsof -i :<port>` on Unix).
- **Cannot connect to peer** – Confirm IP/port, ensure the listener is active,
  and check firewall rules. For local testing use `127.0.0.1`.
- **Message not resonant** – Double-check resonance code, kappa, theta, and
  password alignment across peers.
- **GUI fails to launch (Linux)** – Install missing Qt dependencies:
  ```bash
  sudo apt-get install libxcb-cursor0 libxcb-xinerama0
  ```

## Development Guide
- Run automated tests:
  ```bash
  python -m pytest tests/
  ```
- Code layout highlights:
  - Networking safeguards live inside `SpectralNode` (`_allow_connection`,
    `_record_message`, `_send_frame`, `_recv_frame`).
  - Cryptographic hygiene zeroizes derived keys after use.
  - Tests cover encryption round-trips, frame limits, replay detection, and
    cover-traffic generator behaviour.
- Suggested workflow:
  1. Install dev requirements.
  2. Use the CLI demo for deterministic scenarios.
  3. Launch the GUI for UX validation and addon toggles.

## Project Structure
```
neccrit/
├── neccrit_pyqt6.py                 # PyQt6 GUI application
├── run_neccrit.py                   # Convenience launcher
├── spectralship_engine_duallayer.py # P2P engine & security pipeline
├── spectralship_demo_duallayer.py   # CLI demo
├── oscillator_core.py               # FFT spectrum helper
├── tripolar_mask.py                 # Tripolar masking math
├── crypto_layer.py                  # Encryption helpers & handshake PSK
├── angelcore_spectralwatch.py       # Surveillance heuristics
├── qr_utils.py                      # QR encode/decode utilities
├── entropy_seed.py                  # Entropy helpers
├── config.py                        # Addon configuration switches
├── addons/                          # ScorpioSync cover-traffic modules
├── docs/ADDON_SCORPIOSYNC.md        # Detailed addon documentation
├── tests/                           # Pytest suite
└── QUICKSTART.md                    # GUI-oriented quick start guide
```

## License & Support
- Licensed under the terms specified in [`LICENSE`](LICENSE).
- See [`SECURITY.md`](SECURITY.md) for vulnerability reporting guidance.
- Use GitHub issues for bug reports and feature discussions.

---

## Deutsche Kurzfassung

### Überblick
n'éccrit ist ein experimentelles P2P-Chat-System, das Tripolar-Maskierung mit
AES-256-GCM-Authentifizierungsverschlüsselung kombiniert. Es bietet eine
PyQt6-Oberfläche,
Kommandozeilen-Demo, optionale Cover-Traffic-Generatoren (ScorpioSync) und das
Surveillance-Monitoring AngelCore.

### Hauptfunktionen
- Duale Sicherheitslage: Spektrale Tripolar-Maskierung + kryptografische
  Verschlüsselung pro Nachricht.
- Direkte Peer-zu-Peer-Verbindungen mit Ratenbegrenzung, Replay-Schutz und
  Resonanzprüfung.
- Optionale Tarnmodule: Cover-Traffic mit HTTP-Mimikry sowie AngelCore zur
  Erkennung verdächtiger Systemaktivitäten.
- QR-Codes zum sicheren Austausch der Sitzungsparameter.

### Installation & Start
1. Repository klonen und Abhängigkeiten installieren:
   ```bash
   git clone https://github.com/LashSesh/neccrit.git
   cd neccrit
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. GUI starten:
   ```bash
   python neccrit_pyqt6.py
   ```
3. Parameter beider Peers abstimmen (Resonanzcode, Kappa/Theta-Vektoren,
   Passwort, Ports/IP).
4. Optional AngelCore aktivieren und Cover-Traffic über `config.py`
   konfigurieren.

### Fehlerbehebung
- Port belegt → neuen Port wählen oder Prozess beenden.
- Keine Verbindung → IP/Port prüfen, Firewall freischalten, Listener starten.
- "Message not resonant" → Parameter erneut vergleichen, identische Passwörter
  verwenden.
- GUI startet nicht (Linux) → `sudo apt-get install libxcb-cursor0 libxcb-xinerama0`.

### Entwicklung
- Tests über `python -m pytest tests/` ausführen.
- Kernlogik befindet sich in `spectralship_engine_duallayer.py`, die Kryptofunktionen
  in `crypto_layer.py`, Maskierung in `tripolar_mask.py`.
- Detaillierte Anleitung zum Cover-Traffic im Ordner `docs/`.

Weitere Informationen, Lizenzhinweise und Supportoptionen siehe oben in der
englischen Hauptdokumentation.
