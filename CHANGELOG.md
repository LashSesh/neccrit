# Changelog

## [0.2.0-alpha.1] – unreleased

Complete rewrite in Rust. Nothing of the Python prototype is retained; it did
not deliver messages correctly and several of its security claims were not
true (see `docs/PROTOTYPE_REVIEW.md`). Profiles and parameters of the
prototype are not compatible.

### Added
- Long-term X25519 identities, invite codes and 60-digit safety numbers for
  out-of-band verification.
- Noise `XKpsk3_25519_ChaChaPoly_BLAKE2s` handshake with ML-KEM-768 mixed in
  as PSK (hybrid post-quantum confidentiality), explicit key confirmation and
  per-message rekeying.
- Padding of all messages to fixed size buckets; delivery receipts;
  in-memory outbox with re-sending and duplicate suppression.
- Probe-resistant listener: peers that do not know the public key get no
  response; only contacts can complete a session.
- Tor / SOCKS5 support with remote DNS and per-contact stream isolation.
- Encrypted profile file (Argon2id + XChaCha20-Poly1305), atomic writes,
  profile locking.
- `neccrit` command line client with terminal-safe rendering of untrusted
  text.
- Specification (`docs/PROTOCOL.md`), threat model, CI with rustfmt, clippy,
  tests and `cargo deny`.

### Hardening after internal review
- Inbound rate limits are per contact and survive reconnects; replaced
  sessions are terminated after a grace period.
- A newer session replaces a stale one outside the simultaneous-dial window,
  so a peer can reconnect after a network change without waiting for the
  idle timeout; reconnect backoff only resets after stable sessions.
- Separate reader/writer tasks per session (no write deadlock when both
  sides flush large queues).
- First handshake message must arrive within 10 s.
- Public keys of small order are rejected.
- All default-ignorable, format and line/paragraph-separator characters are
  made visible; long blank runs are collapsed; sender labels are highlighted.

### Removed
- Zero-width steganography, HTTP "mimicry" and cover-traffic markers.
- "AngelCore" surveillance detection (it was driven by random numbers).
- "Tripolar spectral masking" (no security value, and it destroyed messages).
- Shared-password model and QR codes containing the password.
- PyQt6 GUI (a new graphical client may be built on `neccrit-core` later).

## Python prototype (≤ 1.1.0)

Unsupported. See the git history up to commit `6a13463` and
`docs/PROTOTYPE_REVIEW.md`.
