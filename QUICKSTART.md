# Quick Start Guide - n'éccrit

## Installation (3 minutes)

### Step 1: Install Python
Make sure you have Python 3.8+ installed:
```bash
python3 --version
```

### Step 2: Install Dependencies
```bash
cd neccrit
pip install -r requirements.txt
```

### Step 3: Launch Application
```bash
python neccrit_pyqt6.py
```
Or use the launcher:
```bash
python run_neccrit.py
```

## First Time Setup (5 minutes)

### For Both Users

1. **Launch the application**
2. **Go to Settings tab**
3. **Configure Local Settings:**
   - Name: Your display name (e.g., "Alice")
   - Port: A unique port number (e.g., 55555 for User 1, 55556 for User 2)
   - Keep other defaults for testing

4. **IMPORTANT - Agree on shared secrets:**
   Both users MUST use identical:
   - Resonance Code (default: 1337)
   - Kappa values (default: 2.5,3.1,4.7)
   - Theta values (default: 0.1,1.3,2.1)
   - Crypto Password (default: secret_password - CHANGE THIS!)

### Easy Method: Using QR Codes

**User 1:**
1. Configure all settings
2. Click "Show My QR Code"
3. Share screenshot with User 2 (via secure channel)

**User 2:**
1. Save User 1's QR code image
2. Click "Load from QR Image"
3. Select the QR code file
4. Only change: Your own port number (must be different!)

### Manual Method

**User 1 (Alice):**
- Your Port: 55555
- Peer IP: [User 2's IP address or 127.0.0.1 for local]
- Peer Port: 55556
- Peer Name: Bob

**User 2 (Bob):**
- Your Port: 55556
- Peer IP: [User 1's IP address or 127.0.0.1 for local]
- Peer Port: 55555
- Peer Name: Alice

## Testing Locally (Same Computer)

**Terminal 1 (Alice):**
```bash
python neccrit_pyqt6.py
```
- Name: Alice
- Port: 55555
- Peer IP: 127.0.0.1
- Peer Port: 55556

**Terminal 2 (Bob):**
```bash
python neccrit_pyqt6.py
```
- Name: Bob
- Port: 55556
- Peer IP: 127.0.0.1
- Peer Port: 55555

## Starting a Chat Session

1. **Both users**: Click "▶️ Start Chat" button
   - Status should show "🟢 Connected & Encrypted"
   - Message input should become enabled

2. **(Optional) Enable AngelCore**
   - In Settings tab, check "Enable AngelCore" checkbox
   - AngelCore status bar will appear in Chat tab
   - ⚠️ Warning: May block chat if suspicious activity detected

3. **Send a test message**
   - Type "Hello!" in the message box
   - Press Enter or click 🔐 Send

4. **Verify reception**
   - The message should appear in both chat windows
   - Format: `[HH:MM:SS] Name: Message`

## Understanding AngelCore Status (Optional Feature)

**NEW**: AngelCore is now disabled by default. Enable it via checkbox in Settings tab.

When enabled, the colored bar shows surveillance detection status:

- **🛡️ AngelCore: Secure** (Green)
  - Normal operation
  - All features active

- **⚠️ AngelCore: Restricted mode** (Yellow)
  - Unusual system activity detected
  - Limited functionality

- **⚠️ ANGELCORE: Visual camouflage activated!** (Red)
  - High probability of surveillance
  - Messages hidden (black on black)
  - Input disabled

*Note: AngelCore uses simulated metrics in the current version. If you experience frequent false positives or chat blocking, simply disable AngelCore in Settings. The dual-layer encryption still provides strong security.*

## Troubleshooting

### Messages not appearing
✓ Check that BOTH users clicked "Start Chat"
✓ Verify resonance code, kappa, theta, and password are IDENTICAL
✓ Check peer IP and port are correct
✓ Try sending from the other direction

### "Port already in use"
✓ Change your port number (e.g., 55557)
✓ Close other instances of the application
✓ On Linux/Mac: Run `lsof -i :55555` to find conflicting process

### Cannot connect
✓ Verify IP address (use `ipconfig` on Windows or `ifconfig` on Linux/Mac)
✓ Check firewall allows the port
✓ For remote connections, ensure port forwarding is configured
✓ For local testing, always use 127.0.0.1

### GUI won't start (Linux)
```bash
sudo apt-get install python3-pyqt6 libxcb-cursor0
```

## Security Best Practices

1. **Change default password** - Never use "secret_password" in production
2. **Use strong resonance codes** - Random large numbers work best
3. **Keep parameters secret** - Only share with intended peer via secure channel
4. **Use unique values** - Don't reuse same parameters for multiple conversations
5. **Test locally first** - Verify everything works before remote connections

## Need Help?

- Check the main README.md for detailed documentation
- Review error messages in the status bar
- Try the CLI demo (`python spectralship_demo_duallayer.py`) for debugging
- Report issues on GitHub

---

**Ready to chat securely!** 🔒
