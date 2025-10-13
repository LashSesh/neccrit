# ADDON: ScorpioSync Cover Traffic Generators

## 🎯 Overview

The ScorpioSync addon provides **optional traffic-level camouflage** capabilities for n'éccrit, adding cover traffic generation, HTTP-mimicking, and zero-width steganography features. These functions operate **on top of the existing cryptographic layer** without modifying any core security mechanisms.

**All cover traffic is still encrypted** through n'éccrit's standard Fernet-AEAD + X25519/HKDF protocol.

---

## 🔒 Security Architecture

### What This Addon Does

✅ **Traffic Pattern Obfuscation**: Sends periodic "cover" packets to obscure communication patterns  
✅ **HTTP Mimicry**: Formats payloads to resemble HTTP API requests  
✅ **Zero-Width Steganography**: Optional embedding of data in zero-width Unicode characters (disabled by default)

### What This Addon Does NOT Do

❌ Does **not** replace or weaken core cryptography  
❌ Does **not** bypass authentication or key derivation  
❌ Does **not** modify the Tripolar masking or resonance validation  
❌ Does **not** alter replay/DoS protection mechanisms

**All cover traffic passes through the same encryption pipeline as regular messages.**

---

## 📁 File Structure

```
addons/
├── __init__.py                          # Package marker
├── scorpiosync_generators_complete.py   # Core generator functions
└── scorpiosync_adapter.py               # Integration with n'éccrit transport

config.py                                # Configuration flags

docs/
└── ADDON_SCORPIOSYNC.md                 # This file

tests/
├── test_addons_generators.py            # Unit tests for generators
└── test_cover_traffic.py                # Integration tests
```

---

## ⚙️ Configuration

Configuration is managed via `config.py`:

```python
# Enable/disable cover traffic
ENABLE_COVER_TRAFFIC = True

# Interval between cover packets (seconds)
COVER_MIN_INTERVAL_S = 20
COVER_MAX_INTERVAL_S = 45

# Format as HTTP requests
ENABLE_HTTP_MIMICRY = True

# Zero-width steganography (DISABLED by default)
ENABLE_ZW_STEGANO = False
```

### Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `ENABLE_COVER_TRAFFIC` | `True` | Master switch for cover traffic generation |
| `COVER_MIN_INTERVAL_S` | `20` | Minimum seconds between cover packets |
| `COVER_MAX_INTERVAL_S` | `45` | Maximum seconds between cover packets |
| `ENABLE_HTTP_MIMICRY` | `True` | Format packets as HTTP API requests |
| `ENABLE_ZW_STEGANO` | `False` | Enable zero-width character steganography |

---

## 🔧 API Reference

### Generator Functions

#### `fake_api_request_generator(seed=None)`

Generates fake API request payloads that mimic common REST endpoints.

```python
from addons.scorpiosync_generators_complete import fake_api_request_generator

payload = fake_api_request_generator()
# Returns: {
#   "method": "POST",
#   "endpoint": "/v1/users/login",
#   "headers": {"Host": "api.example.com", "User-Agent": "neccrit/1.0"},
#   "body": {"sample": "aB3xK9", "ts": "2025-10-13T05:00:00Z"},
#   "generated_at": "2025-10-13T05:00:00Z"
# }
```

**Parameters:**
- `seed` (optional): Integer seed for deterministic output

**Returns:** Dictionary with HTTP-like request structure

---

#### `http_builder_transformer(payload, host="api.example.com", include_length_prefix=True)`

Converts a payload into an HTTP/1.1 request format.

```python
from addons.scorpiosync_generators_complete import http_builder_transformer

payload = {"endpoint": "/api/v1/test", "data": "value"}
http_bytes = http_builder_transformer(payload)
# Returns: b'\x00\x00\x00\x85POST /api/v1/test HTTP/1.1\r\n...'
```

**Parameters:**
- `payload`: Dictionary to convert
- `host`: Target hostname for Host header
- `include_length_prefix`: Whether to prepend 4-byte length

**Returns:** Bytes representing HTTP request

---

#### `steganography_transformer(payload)`

Encodes a payload into zero-width Unicode characters.

```python
from addons.scorpiosync_generators_complete import steganography_transformer

payload = {"secret": "data"}
hidden = steganography_transformer(payload)
# Returns: "\u200B\u200C\u200B..." (invisible characters)
```

**⚠️ USE RESPONSIBLY**: This is a dual-use technology. Only use for legitimate research, QA, or defensive privacy work.

**Parameters:**
- `payload`: Any JSON-serializable object

**Returns:** String of zero-width characters encoding the payload

---

#### `steganography_decode(zws)`

Decodes zero-width character steganography back to JSON.

```python
from addons.scorpiosync_generators_complete import steganography_decode

hidden = "\u200B\u200C..."  # Zero-width encoded string
decoded = steganography_decode(hidden)
# Returns: '{"secret":"data"}'
```

**Parameters:**
- `zws`: String containing zero-width characters

**Returns:** JSON string of decoded payload

---

### Adapter Functions

#### `set_active_node(node, peer_ip, peer_port, peer_name)`

Configure the active SpectralNode and peer for cover traffic.

```python
from addons.scorpiosync_adapter import set_active_node

set_active_node(my_node, "192.168.1.100", 5555, "peer_alice")
```

---

#### `is_session_ready()`

Check if a session is available for cover traffic transmission.

```python
from addons.scorpiosync_adapter import is_session_ready

if is_session_ready():
    print("Ready to send cover traffic")
```

---

#### `start_cover_traffic(min_s, max_s, use_http_mimicry, stop_flag)`

Start background thread for periodic cover traffic generation.

```python
import threading
from addons.scorpiosync_adapter import start_cover_traffic

stop_flag = threading.Event()
thread = start_cover_traffic(
    min_s=20,
    max_s=45,
    use_http_mimicry=True,
    stop_flag=stop_flag
)

# Later, to stop:
stop_flag.set()
```

**Parameters:**
- `min_s`: Minimum interval (seconds)
- `max_s`: Maximum interval (seconds)
- `use_http_mimicry`: Enable HTTP formatting
- `stop_flag`: Threading event to stop the loop

**Returns:** Thread handle

---

## 🧪 Testing

Run the addon tests:

```bash
# All addon tests
pytest tests/test_addons_generators.py tests/test_cover_traffic.py -v

# Just generator tests
pytest tests/test_addons_generators.py -v

# Just integration tests
pytest tests/test_cover_traffic.py -v
```

---

## 🚀 Usage Example

### Basic Integration

```python
from spectralship_engine_duallayer import SpectralNode
from addons.scorpiosync_adapter import set_active_node, start_cover_traffic
import threading

# Create node
node = SpectralNode(
    name="Alice",
    port=5555,
    resonance_code="1337",
    kappa=[2.5, 3.1, 4.7],
    theta=[0.1, 1.3, 2.1],
    crypto_pw="secure_password"
)

# Start listening
node.start_listening()

# Configure cover traffic
set_active_node(node, "192.168.1.100", 5556, "Bob")

# Start cover traffic thread
stop_flag = threading.Event()
cover_thread = start_cover_traffic(
    min_s=20,
    max_s=45,
    use_http_mimicry=True,
    stop_flag=stop_flag
)

# ... application runs ...

# Cleanup
stop_flag.set()
cover_thread.join()
```

---

## ⚖️ Responsible Use Notice

The functions in this addon can be dual-use technologies. They are provided for:

✅ **Legitimate Research**: Academic study of traffic analysis and privacy  
✅ **Quality Assurance**: Testing privacy-preserving systems  
✅ **Defensive Privacy**: Protecting against traffic analysis attacks

**Steganography is DISABLED by default** and should only be enabled for lawful purposes.

Users are responsible for ensuring their use complies with applicable laws and regulations.

---

## 🔐 Cryptographic Integrity

**This addon maintains all core security properties:**

- ✅ Fernet-AEAD encryption still active
- ✅ Scrypt KDF with salt still used
- ✅ X25519/HKDF PFS still enforced
- ✅ Replay protection still active
- ✅ DoS guards still operational
- ✅ Tripolar masking + resonance validation unchanged

Cover traffic payloads are treated as regular messages and pass through the full encryption pipeline.

---

## 📊 Performance Considerations

- Cover traffic adds minimal CPU overhead (random number generation, JSON serialization)
- Network impact: ~1 packet every 20-45 seconds (configurable)
- Memory footprint: <1 MB for background thread
- No impact on message latency (cover traffic is asynchronous)

---

## 🛠️ Troubleshooting

### Cover traffic not sending

✅ Check `ENABLE_COVER_TRAFFIC = True` in config.py  
✅ Ensure `set_active_node()` was called with valid peer info  
✅ Verify node is running (`node.running = True`)  
✅ Check network connectivity to peer

### Steganography encoding/decoding fails

✅ Ensure payload is JSON-serializable  
✅ Check for Unicode handling issues (use UTF-8)  
✅ Verify zero-width characters not stripped by intermediate systems

### Tests failing

✅ Install dev dependencies: `pip install -r requirements-dev.txt`  
✅ Run from repository root: `pytest tests/ -v`  
✅ Check Python version (3.8+ required)

---

## 🔄 Version History

- **v1.0.0** (2025-10-13): Initial integration
  - Cover traffic generation
  - HTTP mimicry transformer
  - Zero-width steganography (disabled by default)
  - Full test coverage
  - Documentation

---

## 📧 Support

For issues specific to this addon:
1. Check this documentation
2. Review test cases for usage examples
3. Open an issue on the GitHub repository

For core n'éccrit issues, refer to the main README.md.

---

**n'éccrit + ScorpioSync** - Privacy through cryptographic security and traffic-level camouflage.
