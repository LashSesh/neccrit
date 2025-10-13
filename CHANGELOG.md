# Changelog

## [Unreleased]
### Security
- Migrated symmetric encryption from Fernet (AES-128-CBC + HMAC) to AES-256-GCM while retaining Scrypt-derived keys and salt-per-message design.

## [1.1.0] - 2025-02-14
### Security
- Removed insecure pickle-based network deserialization in favor of JSON envelopes with explicit length prefixes.
- Replaced SHA-256 password hashing with Scrypt (N=2**15, r=8, p=1) and per-message salts to derive authenticated encryption keys.
- Added ephemeral X25519 key exchange with HKDF-derived session keys for forward secrecy.
- Enforced replay protection, frame-size limits, socket timeouts, and basic per-IP rate limiting.
- Added regression tests plus CI automation for pytest, Bandit, and pip-audit to guard security-sensitive code paths.

### Documentation
- Introduced SECURITY.md describing threat model, key derivation parameters, and disclosure process.
