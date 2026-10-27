# Security policy

## Status

neccrit is pre-release software. The protocol ([docs/PROTOCOL.md](docs/PROTOCOL.md))
and the implementation **have not been independently audited**. The threat
model, including what is explicitly out of scope, is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

- Open a private report via GitHub Security Advisories for this project
  ("Security" tab → "Report a vulnerability"). Please do not open public
  issues for security problems.
- We aim to acknowledge reports within 3 business days and provide status
  updates every 7 days until resolution.
- Please include the affected version or commit, a description of the impact
  and, if possible, a reproduction or failing test.

## Supported versions

Only the latest release and the `main` branch receive security fixes. The
Python prototype (versions before 0.2) is unsupported and must not be used.

## Cryptographic inventory

| Purpose | Algorithm | Implementation |
| --- | --- | --- |
| Handshake and transport | Noise `XKpsk3_25519_ChaChaPoly_BLAKE2s` | `snow` |
| Hybrid post-quantum key exchange | ML-KEM-768 (FIPS 203), mixed in as the Noise PSK | `libcrux-ml-kem` |
| In-session forward secrecy | Noise `Rekey` after every message | `snow` |
| Profile encryption | XChaCha20-Poly1305, key from Argon2id (64 MiB, t=3, p=4) | `chacha20poly1305`, `argon2` |
| Safety numbers, invite checksums | BLAKE2b (5200 iterations for fingerprints) | `blake2` |
| Randomness | operating system CSPRNG | `getrandom` |

No cryptographic primitive is implemented in this repository.

## Engineering rules

- `unsafe` code is forbidden in all crates.
- Message contents and key material are never logged, printed in `Debug`
  output or included in error messages.
- Every parser of untrusted input (wire messages, frames, invite codes,
  addresses, profile files) rejects non-canonical input and has tests for
  malformed data.
- Security-relevant changes need tests that show the attack *fails*, not
  only that the happy path works.
- Dependencies are checked in CI with `cargo deny` (advisories, licenses,
  sources). Exceptions are documented in `deny.toml`.

## Out of scope

Steganography, traffic camouflage and similar "covert" features are not part
of neccrit and requests to add them will be declined; see
[docs/PROTOTYPE_REVIEW.md](docs/PROTOTYPE_REVIEW.md) for the reasons.
