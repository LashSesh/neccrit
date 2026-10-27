# Review of the Python prototype (up to commit `6a13463`)

This document records why the original Python prototype was replaced by a
rewrite instead of being fixed. Line references point to the files as they
were at commit `6a13463`; use `git show 6a13463:<file>` to read them.

**Summary:** the prototype could not deliver a single message correctly, its
headline security layer ("tripolar spectral masking") provided no security,
peers were not authenticated, and several documented protections were either
not implemented or were simulated with random numbers. The problems were in
the foundations, so a rewrite was cheaper and safer than incremental repair.

## 1. Messages could not be transmitted

* `send_fragment` sent the **magnitude** of the first half of an FFT of the
  character codes (`oscillator_core.py:31-35`). Dropping the phase and half of
  the coefficients is irreversible; the original text cannot be recovered.
* The receiver interpreted those magnitudes as Unicode code points
  (`spectralship_engine_duallayer.py:289`), producing garbage of half the
  original length.
* Before that, `_resonant()` (`spectralship_engine_duallayer.py:240-245`)
  required `sum(values) % resonance_code == 0`. With the default code `1337`
  practically every message was silently discarded as "not resonant".

Reproduction with the prototype's own functions: the input
`"Hello Bob, meet at 8"` comes out as `'٫\x0c©Pć\x7fÁt¬\x11'` and is rejected as
non-resonant. No test exercised a full send/receive round trip, which is how
this went unnoticed.

## 2. "Tripolar masking" provided no security

The mask is a sum of sinusoids added to the values. All of its parameters –
`kappa`, `theta` and the seed – were transmitted **inside the same payload**
as the masked data (`spectralship_engine_duallayer.py:311-320`). Anyone who can
read the payload can remove the mask; anyone who cannot read it gains nothing
from it either. The claim "nobody can decipher messages with only one half of
the security layers" (GUI about text, README) was false: there was only one
layer that mattered, the encryption.

## 3. No authentication of peers

* The handshake was an anonymous X25519 exchange; the only secret was a
  shared password used as an HKDF salt
  (`spectralship_engine_duallayer.py:103-122`, `188-238`). There were no
  identity keys and no way to verify who is on the other end.
* Everyone who knew the password could impersonate everyone else. The sender
  name was a self-declared field inside the payload
  (`spectralship_engine_duallayer.py:314`) and was even used to select
  ratchet state (`_register_ratchet_alias`, line 271), so a peer could attach
  itself to another peer's session state by claiming their name.
* **Offline password guessing:** an active attacker who answers a single
  connection learns ciphertext under a key derived only from their own DH
  share and the password, and can then test password guesses offline. The
  "PSK" salt was derived from the password itself
  (`crypto_layer.py:36-43`), so guesses could even be precomputed once for all
  users. The GUI shipped with the default password `secret_password`.

## 4. Secrets exported in QR codes

"Show My QR Code" encoded the full parameter set **including the crypto
password** in plain text (`neccrit_pyqt6.py:502-508` with `get_params()` at
line 361). `SECURITY.md` at the same time stated that QR codes contain only
public information.

## 5. Cryptography did not match the documentation

* With `ENABLE_RATCHET = True` (the default) payloads were encrypted with
  **Fernet (AES-128-CBC + HMAC)** via `core/crypto_layer.py`, not with the
  documented AES-256-GCM.
* The home-grown "Double Ratchet" (`core/ratchet.py`) did not authenticate its
  header (`dh_pub`, `pn`, `n` were not bound to the ciphertext), kept an
  unbounded set of processed message keys (memory exhaustion), and was keyed
  by spoofable identifiers (IP address and claimed name). The fresh handshake
  performed for every message was ignored after the first one.
* Replay protection relied on sender timestamps within ±300 s, silently
  dropping messages between peers whose clocks differ.

## 6. Privacy and metadata

* The listener bound to all interfaces (`spectralship_engine_duallayer.py:252`)
  and peers connected directly by IP address. There was no Tor or proxy
  support, so contacts and every network observer learned both IP addresses.
* Every message opened a new TCP connection with a new handshake, making
  message timing and count trivially observable; message lengths were not
  padded.
* Decrypted messages were printed to stdout
  (`spectralship_engine_duallayer.py:293`), i.e. into terminals and logs.

## 7. Features that only pretended to work

* **"AngelCore" surveillance detection** computed its verdict from
  `random.randint()` / `random.uniform()` values
  (`neccrit_pyqt6.py:561-567`) – CPU load, RAM, mouse activity and the
  "microphone noise floor" were random numbers. The resulting `ALERT` state
  (blacking out the chat) was noise, and the feature suggested a protection
  that does not exist.
* **"Cover traffic"** sent literal marker strings such as `[COVER:cover]`
  through the normal message path (`core/transport.py:35-61`); the
  "HTTP mimicry" output was computed and then discarded
  (`addons/scorpiosync_adapter.py:12`).

## 8. Steganography

The optional zero-width steganography (`addons/scorpiosync_generators_complete.py:28-37`)
encoded JSON as a sequence of U+200B/U+200C characters. It

* provided **no confidentiality** (a fixed, public bit mapping),
* was **trivially detectable** (long runs of zero-width characters are
  conspicuous and are flagged or stripped by many tools), so it offered no
  real deniability while suggesting that it did,
* is a classic dual-use feature that invites misuse and legal trouble without
  adding anything to the core purpose of a private messenger.

The confirmation phrases and the local "audit log" did not change any of this.

**Decision:** steganography, traffic "mimicry", cover-traffic theatre and
visual "camouflage" are removed entirely and are out of scope for the
project. What remains is honest, standard traffic-analysis hardening:
fixed-size padding buckets, optional Tor transport with stream isolation, and
no message history on disk. The new client additionally makes zero-width and
bidirectional-override characters **visible** in received messages, so
hidden content cannot be smuggled past the user.

## 9. Process

* The release workflow ignored test failures (`pytest -q || true` in
  `.github/workflows/release-core.yml:13`).
* `SECURITY.md` described properties the code did not have (QR contents,
  cipher choice).

## What the rewrite does instead

| Prototype | Rewrite |
| --- | --- |
| Shared password, anonymous DH | Long-term X25519 identity per profile; contacts pinned by key and verified with a 60-digit safety number |
| Tripolar masking + Fernet + custom ratchet | Noise `XKpsk3` (snow) with hybrid ML-KEM-768 (libcrux, formally verified) and per-message rekeying |
| Timestamp-based replay window | Noise nonces: every transport message is accepted exactly once, in order |
| Password in QR code | Invite code contains only the public key and an optional address |
| Direct TCP only, bound to all interfaces | Opt-in listening, Tor/SOCKS5 support with remote DNS and per-contact stream isolation |
| Plaintext printed to stdout | No logging of content; terminal-safe rendering of untrusted text |
| Random "surveillance detection", cover traffic markers, steganography | Removed |
| Python, untested end to end | Rust (`#![forbid(unsafe_code)]`), unit + end-to-end tests over real sockets and the real binary, CI with clippy and `cargo deny` |
