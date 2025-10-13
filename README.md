# n'éccrit - SPECTRALSHIP Dual-Layer Privacy Chat

A secure P2P chat application with dual-layer encryption (Tripolar masking + AES/Fernet) and integrated surveillance detection (AngelCore).

## 🌟 Features

### Security Features
- **Dual-Layer Encryption**: Mathematical n-pole (tripolar) masking AND AES-256/Fernet encryption
- **Impossible to decrypt with only one layer**: Both cryptographic and mathematical obfuscation required
- **P2P Architecture**: No central server, no plaintext transmission, no tracking
- **Resonance Codes**: Shared secrets for message validation
- **Dynamic Encryption**: Each message has unique masking and encryption parameters

### Application Features
- **Modern PyQt6 GUI**: Professional, user-friendly dark crypto-themed interface
- **AngelCore Monitoring (Optional)**: Real-time surveillance detection
  - **NOW OPTIONAL**: Enable/disable via checkbox in Settings tab
  - Monitors CPU load, RAM usage, mouse activity
  - Automatic visual camouflage when surveillance detected
  - Three states: SAFE (green), UNCERTAIN (yellow), ALERT (red)
  - ⚠️ **Note**: When enabled, may block chat during suspicious activity detection
- **ScorpioSync Cover Traffic (Optional)**: Traffic camouflage and pattern obfuscation addon
  - Periodic cover traffic to hide communication patterns
  - HTTP mimicry for better blending
  - Zero-width steganography (disabled by default)
- **QR Code Support**: Easy parameter sharing between peers
- **Real-time Messaging**: Instant P2P message delivery
- **Message History**: Full conversation history during session

## 📋 Requirements

- Python 3.8 or higher
- Operating System: Linux, macOS, or Windows

## 🚀 Installation

1. **Clone the repository** (or download the source):
```bash
git clone https://github.com/LashSesh/neccrit.git
cd neccrit
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

Required packages:
- numpy >= 1.24.0
- PyQt6 >= 6.9.0
- cryptography >= 41.0.0
- qrcode >= 7.4.0
- pillow >= 10.0.0
- pyzbar >= 0.1.9

## 🎯 Quick Start

### Using the Production GUI (Recommended)

1. **Start the application**:
```bash
python neccrit_pyqt6.py
```

2. **Configure your settings** (Settings tab):
   - Set your name
   - Choose a port (default: 55555)
   - Set resonance code (must match peer's code)
   - Set kappa values (e.g., 2.5,3.1,4.7)
   - Set theta values (e.g., 0.1,1.3,2.1)
   - Set a strong crypto password (must match peer's password)

3. **Share parameters with your peer**:
   - Click "Show My QR Code" to generate a QR code
   - Share the QR image with your peer (via secure channel)
   - OR manually share all parameters

4. **Configure peer connection**:
   - Enter peer's IP address
   - Enter peer's port number
   - Enter peer's name

5. **Start chatting**:
   - Click "Start Chat" to begin listening
   - Your peer should do the same with their settings
   - Type messages and press Enter or click Send

### Using the CLI Demo

For testing or headless servers:

```bash
python spectralship_demo_duallayer.py
```

Follow the prompts to configure your node and connect to a peer.

## 🔒 Security Configuration

### Critical Parameters (Must Match Between Peers)

1. **Resonance Code**: A shared secret number for message validation
2. **Kappa Values**: Tripolar masking coupling strengths (comma-separated floats)
3. **Theta Values**: Tripolar masking phase angles (comma-separated floats)
4. **Crypto Password**: Strong password for AES-256 key derivation

### Example Configuration

**Peer 1:**
```
Name: Alice
Port: 55555
Resonance Code: 1337
Kappa: 2.5,3.1,4.7
Theta: 0.1,1.3,2.1
Crypto Password: my_super_secret_password_2024
```

**Peer 2:**
```
Name: Bob
Port: 55556
Resonance Code: 1337  (same as Alice)
Kappa: 2.5,3.1,4.7    (same as Alice)
Theta: 0.1,1.3,2.1    (same as Alice)
Crypto Password: my_super_secret_password_2024  (same as Alice)
```

**Connection:**
- Alice connects to Bob: IP = Bob's IP, Port = 55556
- Bob connects to Alice: IP = Alice's IP, Port = 55555

## 🎭 ScorpioSync Cover Traffic (Optional Addon)

**NEW**: Optional addon for traffic-level camouflage and cover traffic generation.

### Features
- **Cover Traffic Generation**: Periodic dummy packets to obfuscate communication patterns
- **HTTP Mimicry**: Format traffic to resemble normal API requests
- **Zero-Width Steganography**: Optional data hiding in Unicode characters (disabled by default)

### Configuration

Enable in `config.py`:
```python
ENABLE_COVER_TRAFFIC = True
COVER_MIN_INTERVAL_S = 20
COVER_MAX_INTERVAL_S = 45
ENABLE_HTTP_MIMICRY = True
ENABLE_ZW_STEGANO = False  # Disabled by default
```

### Documentation

See [docs/ADDON_SCORPIOSYNC.md](docs/ADDON_SCORPIOSYNC.md) for complete API reference, usage examples, and integration guide.

**⚠️ Note**: All cover traffic is still encrypted through the standard crypto layer. Steganography is disabled by default for responsible use.

## 🛡️ AngelCore Surveillance Detection (Optional)

**NEW**: AngelCore is now optional and can be enabled/disabled via checkbox in the Settings tab.

When enabled, AngelCore continuously monitors system metrics to detect potential surveillance:

- **SAFE (🛡️)**: Normal operation, all features enabled
- **UNCERTAIN (⚠️)**: Suspicious activity detected, restricted mode
- **ALERT (⚠️)**: High probability of surveillance, visual camouflage activated

When in ALERT mode:
- Message display is hidden (black on black)
- Input is disabled
- All content is obscured from observers

**Important**: AngelCore is disabled by default. To enable it:
1. Go to the Settings tab
2. Check the "Enable AngelCore" checkbox under "Surveillance Detection"
3. The AngelCore status bar will appear in the Chat tab

**Note**: When AngelCore detects suspicious activity, it may block the chat interface for security reasons. If you experience frequent false positives, you can disable AngelCore and rely solely on the dual-layer encryption for security.

## 🎨 Architecture

### Core Components

1. **spectralship_engine_duallayer.py**: Core P2P chat engine with encryption
2. **oscillator_core.py**: Spectral profile generation using FFT
3. **tripolar_mask.py**: N-pole mathematical masking functions
4. **crypto_layer.py**: AES-256/Fernet encryption layer
5. **angelcore_spectralwatch.py**: Surveillance detection system
6. **qr_utils.py**: QR code generation and parsing
7. **neccrit_pyqt6.py**: Production PyQt6 GUI application
8. **addons/scorpiosync_***: Optional cover traffic and traffic camouflage (see docs/ADDON_SCORPIOSYNC.md)

### Security Layers

```
Plaintext Message
    ↓
[Oscillator Core] - Convert to spectral profile
    ↓
[Tripolar Masking] - Apply n-pole mathematical obfuscation
    ↓
[Pickle Serialization] - Prepare for transmission
    ↓
[AES-256/Fernet] - Cryptographic encryption
    ↓
[Network Transmission] - Send to peer
    ↓
[AES-256/Fernet] - Cryptographic decryption
    ↓
[Pickle Deserialization] - Unpack data
    ↓
[Tripolar Unmasking] - Remove mathematical obfuscation
    ↓
[Resonance Validation] - Verify shared secret
    ↓
Plaintext Message
```

## 📁 File Structure

```
neccrit/
├── neccrit_pyqt6.py              # Production PyQt6 GUI
├── run_neccrit.py                 # Application launcher
├── spectralship_engine_duallayer.py  # Core chat engine
├── spectralship_demo_duallayer.py    # CLI demo
├── oscillator_core.py             # Spectral profile generation
├── tripolar_mask.py               # Tripolar masking functions
├── crypto_layer.py                # Encryption layer
├── angelcore_spectralwatch.py     # Surveillance detection
├── qr_utils.py                    # QR code utilities
├── entropy_seed.py                # Entropy generation
├── config.py                      # Configuration for optional addons
├── example_cover_traffic_integration.py  # Usage example
├── addons/                        # Optional addons
│   ├── scorpiosync_generators_complete.py  # Cover traffic generators
│   └── scorpiosync_adapter.py     # Transport layer adapter
├── docs/                          # Documentation
│   └── ADDON_SCORPIOSYNC.md       # ScorpioSync addon guide
├── tests/                         # Test suite
│   ├── test_crypto.py
│   ├── test_network_guards.py
│   ├── test_addons_generators.py  # Addon generator tests
│   └── test_cover_traffic.py      # Cover traffic integration tests
├── requirements.txt               # Python dependencies
├── requirements-dev.txt           # Development dependencies
├── README.md                      # This file
└── QUICKSTART.md                  # Quick start guide
```

## 🔧 Troubleshooting

### "Port already in use"
- Choose a different port number
- Close any other applications using that port
- On Linux/Mac: `lsof -i :<port>` to find the process

### "Cannot connect to peer"
- Verify peer's IP address is correct
- Ensure peer has started their chat node
- Check firewall settings allow the port
- For local testing, use 127.0.0.1 (localhost)

### "Message not resonant"
- Ensure both peers have identical resonance codes
- Verify kappa and theta values match exactly
- Check that crypto passwords are identical

### GUI doesn't start (Linux)
Install required system libraries:
```bash
sudo apt-get install libxcb-cursor0 libxcb-xinerama0
```

## 🚧 Development

### Running Tests
```bash
python -m pytest tests/  # If tests exist
```

### Alternative Versions
- `spectralship_demo_duallayer.py`: CLI version for testing or headless servers

## ⚠️ Security Disclaimer

This is an experimental privacy chat system. While it implements multiple layers of security:

- Use at your own risk
- Not audited by professional cryptographers
- Intended for educational and experimental purposes
- For production use, consider additional security measures
- Always use strong, unique passwords
- Keep your resonance codes and parameters confidential

## 📜 License

See repository license file for details.

## 🤝 Contributing

Contributions welcome! Please test thoroughly before submitting pull requests.

## 📧 Support

For issues and questions, please use the GitHub issue tracker.

---

**n'éccrit** - Privacy through mathematical obfuscation and cryptographic security.
