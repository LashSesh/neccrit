# neccrit

**neccrit** is an end-to-end encrypted, peer-to-peer messenger for people who
know each other. There are no servers, no accounts and no phone numbers: two
people exchange invite codes, compare a safety number once, and talk directly
– optionally over Tor so that nobody, not even the contact, learns their IP
address.

> **Status: pre-release (0.2.0-alpha).** The protocol and code have not yet
> been independently audited. Read the [threat model](docs/THREAT_MODEL.md)
> before relying on neccrit, and report problems as described in
> [SECURITY.md](SECURITY.md).

Version 0.2 is a complete rewrite in Rust. The earlier Python prototype did
not work and made security claims it could not keep; the reasons are
documented in [docs/PROTOTYPE_REVIEW.md](docs/PROTOTYPE_REVIEW.md).

## What neccrit gives you

* **End-to-end encryption with mutual authentication** – Noise
  `XKpsk3_25519_ChaChaPoly_BLAKE2s` via the widely used
  [`snow`](https://crates.io/crates/snow) library.
* **Protection against "harvest now, decrypt later"** – every session also
  runs an ML-KEM-768 key exchange (formally verified
  [`libcrux`](https://github.com/cryspen/libcrux) implementation, the project
  OpenSSH's ML-KEM code is derived from). Recorded traffic stays secret unless *both* X25519 and ML-KEM are
  broken.
* **Forward secrecy** – fresh ephemeral keys for every session and a key
  ratchet after every single message.
* **Verifiable contacts** – contacts are pinned by public key; a 60-digit
  safety number, compared once in person or by phone, rules out a man in the
  middle.
* **Minimal metadata** – messages are padded to fixed sizes, no message
  history is written to disk, peers that do not know your public key get no
  response at all, and Tor support with per-contact circuit isolation hides
  IP addresses.
* **Encrypted profile** – the identity key and contact list are stored in one
  file encrypted with XChaCha20-Poly1305 under an Argon2id-derived key.
* **Safe display** – terminal control sequences, zero-width and bidi-override
  characters in received messages are made visible instead of being
  interpreted.
* **Memory-safe implementation** – Rust with `#![forbid(unsafe_code)]`,
  tested end to end over real sockets.

## What neccrit deliberately does not do

* No steganography, no traffic "mimicry", no camouflage modes. These features
  are routinely detectable, give a false sense of safety and invite misuse;
  they were removed in the rewrite.
* No servers: messages are delivered only while both people are online
  (undelivered messages wait in memory while the program runs).
* No group chats, multiple devices, attachments or history – yet.
* It cannot protect you if your computer itself is compromised.

See the [threat model](docs/THREAT_MODEL.md) for the complete list.

## Installation

Requires Rust 1.94 or newer ([rustup.rs](https://rustup.rs)).

```bash
git clone https://github.com/LashSesh/neccrit.git
cd neccrit
cargo install --locked --path crates/neccrit-cli
```

This installs the `neccrit` binary into `~/.cargo/bin`.

## Quick start

### 1. Create a profile

Recommended – over Tor (install and start Tor first, e.g. `apt install tor`):

```bash
neccrit init --tor --name alice
```

Add an onion service to your `torrc` (usually `/etc/tor/torrc`) and restart
Tor:

```
HiddenServiceDir /var/lib/tor/neccrit/
HiddenServicePort 7878 127.0.0.1:7878
```

Then tell neccrit its address:

```bash
neccrit config --address "$(sudo cat /var/lib/tor/neccrit/hostname):7878"
```

Alternatively, without Tor (your IP address is visible to your contacts and
to the network), e.g. inside a LAN:

```bash
neccrit init --name alice --listen 0.0.0.0:7878 --address 192.168.1.20:7878
```

You choose a passphrase (at least 10 characters; a sequence of random words
works well). It protects the profile file.

### 2. Exchange invite codes

```bash
neccrit invite                       # prints neccrit:...
neccrit contact add bob neccrit:...  # paste Bob's code
```

The invite code is not secret, but it is also **not authenticated**:
whoever can tamper with the channel you send it over could swap it.

### 3. Verify each other – do not skip this

```bash
neccrit contact verify bob
```

Both of you see the same 60-digit safety number. Compare **all** digits over
a channel where you can be sure you are talking to the right person – in
person, or on a call where you recognise the voice. If they match, confirm;
if not, someone may be intercepting: remove the contact and exchange codes
again another way. Unverified contacts are clearly marked in the chat.

### 4. Chat

```bash
neccrit chat bob
```

Inside the chat:

| Input | Effect |
| --- | --- |
| text | send to the current contact |
| `/to <name>` | switch contact (connects in the background) |
| `/contacts` | contacts with online status and queued messages |
| `/safety [name]` | show the safety number |
| `/quit` | leave (asks again if messages are still undelivered) |
| `//text` | send a message that starts with `/` |

`✓ delivered` confirms that the message arrived on your contact's device.

## Command reference

```
neccrit init [--tor] [--name N] [--listen ADDR] [--address HOST:PORT]
neccrit status
neccrit invite
neccrit config [--name N|none] [--listen ADDR|none] [--address HOST:PORT|none] [--socks5 ADDR|none]
neccrit contact add <name> <invite-code|public-key> [--address HOST:PORT]
neccrit contact list | show <name> | verify <name> | unverify <name>
neccrit contact rename <old> <new> | set-address <name> <addr|none> | remove <name>
neccrit passwd
neccrit chat [name]
```

Global options: `--profile DIR` (or `NECCRIT_PROFILE`) selects the profile
directory, by default `~/.local/share/neccrit` (Linux),
`~/Library/Application Support/neccrit` (macOS) or `%APPDATA%\neccrit`
(Windows). `--passphrase-file FILE` (or `NECCRIT_PASSPHRASE_FILE`) reads the
passphrase from a file for scripting.

Commands that change the profile take a lock, so concurrent changes cannot
overwrite each other. A running chat does not pick up contacts added
meanwhile; restart it.

## How it works

```
 Alice                                                     Bob
 ─────                                                     ───
 profile.neccrit  (Argon2id + XChaCha20-Poly1305)          profile.neccrit
        │                                                         │
        │   TCP (direct or via Tor SOCKS5, per-contact circuit)   │
        │ ── e, es        + ML-KEM-768 public key ──────────────▶ │
        │ ◀─ e, ee        + ML-KEM-768 ciphertext ─────────────── │
        │ ── s, se, psk   (psk = ML-KEM shared secret) ─────────▶ │  is Alice a contact?
        │ ◀─ key confirmation ─────────────────────────────────── │
        │                                                         │
        │ ◀═ padded messages, receipts, keepalives ════════════▶ │  rekey after every message
```

The full specification, including the rationale for each choice, is in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Project layout

```
crates/neccrit-core   protocol, key management, encrypted storage, networking (library)
crates/neccrit-cli    the `neccrit` command line client
docs/                 protocol specification, threat model, prototype review
```

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo deny check            # requires `cargo install cargo-deny`
```

The test suite covers the handshake under attack (wrong keys, strangers,
probing, tampering, replay), the wire format (including property-based
tests), the encrypted profile, the networking node over real TCP sockets
(including offline queuing, simultaneous dialing and a SOCKS5 proxy) and the
real binary in a two-process chat.

Contributions are welcome. Changes to cryptography or the protocol need a
written rationale in `docs/PROTOCOL.md` and tests that demonstrate failure on
attack, not just success.

## License

Apache-2.0, see [LICENSE](LICENSE).

---

## Deutsche Kurzfassung

**neccrit** ist ein Ende-zu-Ende-verschlüsselter Peer-to-Peer-Messenger für
Menschen, die sich kennen – ohne Server, Konten oder Telefonnummern.

* **Verschlüsselung:** Noise-Protokoll (`XKpsk3`, Bibliothek `snow`) mit
  gegenseitiger Authentifizierung, kombiniert mit ML-KEM-768 (formal
  verifizierte `libcrux`-Implementierung) gegen spätere Entschlüsselung durch
  Quantencomputer. Neue Schlüssel für jede Sitzung und Schlüsselfortschaltung
  nach jeder Nachricht.
* **Kontakte** werden per Einladungscode hinzugefügt und **müssen** einmal über
  eine 60-stellige Sicherheitsnummer verifiziert werden (persönlich oder per
  Telefonat): `neccrit contact verify <name>`.
* **Metadaten:** gepolsterte Nachrichtengrößen, kein Nachrichtenverlauf auf
  der Festplatte, optional Tor (Onion-Service, getrennte Circuits pro
  Kontakt).
* **Profil** (Identitätsschlüssel, Kontakte) liegt verschlüsselt in einer
  Datei (Argon2id + XChaCha20-Poly1305).
* **Bewusst nicht enthalten:** Steganographie, Traffic-Tarnung,
  „Überwachungserkennung“ – diese Funktionen des Prototyps waren wirkungslos
  oder irreführend und wurden entfernt (Begründung in
  [docs/PROTOTYPE_REVIEW.md](docs/PROTOTYPE_REVIEW.md)).
* **Status:** Vorabversion, noch nicht unabhängig auditiert.

Schnellstart: `neccrit init --tor --name alice`, Onion-Service in Tor
einrichten (siehe oben), `neccrit invite` mit dem Kontakt austauschen,
`neccrit contact add bob neccrit:…`, `neccrit contact verify bob`,
`neccrit chat bob`.
