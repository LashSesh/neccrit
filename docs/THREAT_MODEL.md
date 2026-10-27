# Threat model

neccrit is a one-to-one messenger for people who know each other and can
exchange invite codes and compare safety numbers. This document states
plainly what it protects against and what it does not. If a property is not
listed under "protected", assume it is not provided.

## Assets

1. Message contents.
2. The fact that two particular people communicate (relationship metadata).
3. The long-term identity key and the contact list.
4. Users' IP addresses and online times.

## Adversaries and guarantees

| Adversary | Can | Cannot (as long as the stated assumptions hold) |
| --- | --- | --- |
| **Passive network observer** (ISP, Wi-Fi operator) | See that connections happen, their timing and approximate sizes (in padding buckets). Without Tor: see both IP addresses. | Read messages. Learn the static public keys (identity hiding of `XK`). Distinguish short texts from receipts/keepalives by size. |
| **Active network attacker** (can modify traffic) | Block, delay or reset connections (denial of service). | Read or alter messages, impersonate a contact, or downgrade the protocol — provided the contact's key was verified via safety number. |
| **Attacker who substitutes an invite code** | Become a man in the middle for contacts who never compare safety numbers. | Remain undetected when safety numbers are compared over an authentic channel. |
| **Future quantum computer** recording traffic today | – | Decrypt recorded sessions, as long as ML-KEM-768 is secure (hybrid key exchange). |
| **Stranger who learned your address** | Open TCP connections, consume some resources. | Get any response without also knowing your public key; complete a session without being in your contact list. |
| **A contact** | Learn when you are online; send you messages; learn your IP address unless you use Tor. | Read your conversations with others; inject terminal control sequences or hidden (zero-width / bidi) text unnoticed. |
| **Thief of a powered-off device** | Copy the profile file and attempt to guess the passphrase offline. | Read the profile with a strong passphrase (Argon2id, 64 MiB per guess). No message history exists on disk. |
| **Compromise of a device during a session** | Read messages from then on; impersonate the user (the identity key is in memory). | Decrypt messages sent earlier in the same session (per-message rekeying) or in earlier sessions (ephemeral keys). |

## Assumptions

* The operating system, terminal and hardware of both participants are not
  compromised. **neccrit cannot protect against malware, keyloggers or
  screen capture on an endpoint.**
* The cryptographic primitives (X25519, ML-KEM-768, ChaCha20-Poly1305,
  BLAKE2, Argon2id) and their implementations are sound.
* Users verify safety numbers before relying on the confidentiality of a
  conversation, and choose a strong passphrase.
* When using Tor, Tor itself provides its documented anonymity properties.

## Not protected / non-goals

* **Traffic analysis beyond padding.** Timing of messages, the regular
  keepalive pattern and the existence of a connection are observable. Over
  Tor, the network observer cannot tell whom you talk to, but timing
  correlation by an adversary who watches both ends is out of scope.
* **Online status** is visible to contacts (they can try to connect).
* **IP addresses** are visible to contacts and observers in direct mode. Use
  Tor if this matters.
* **Asynchronous delivery.** There is no server; messages are delivered only
  while both parties are online. Undelivered messages live in memory and are
  lost when the program exits.
* **Denial of service** against a reachable listener cannot be prevented, only
  limited (handshake slots, timeouts, rate limits).
* **Group chats, multiple devices, attachments, history** are not
  implemented.
* **Deniability, steganography, camouflage.** neccrit does not try to hide
  that it is being used, does not disguise traffic as other protocols and
  contains no steganography. Such features are easy to get wrong, give a
  false sense of safety and are routinely detectable; they were deliberately
  removed (see `PROTOTYPE_REVIEW.md`).
* **Memory forensics.** Secrets are zeroized where the libraries allow it,
  but Rust and the operating system may leave copies (e.g. in swap). Use full
  disk encryption.
* **Terminal scrollback** contains the messages you displayed; clear it if
  this matters.
* **Post-quantum authentication.** Only confidentiality is hybrid;
  authentication relies on X25519.

## Status

The design and code have **not been audited**. Treat neccrit as a
pre-release until an independent review has taken place, and report issues
as described in `SECURITY.md`.
