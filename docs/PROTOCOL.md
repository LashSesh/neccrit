# neccrit protocol, version 1

Status: **draft, not yet independently reviewed.** Changes that break wire
compatibility bump the version in the Noise prologue.

## 1. Design goals and principles

* Use only established constructions and widely used implementations; invent
  nothing that a reviewer would have to analyse from scratch.
* Authenticate peers by long-term keys that users verify out of band.
* Protect recorded traffic against future quantum computers (hybrid key
  exchange), without depending on the post-quantum component alone.
* Minimise metadata: no servers, no accounts, no phone numbers, padded
  messages, optional Tor transport.
* Fail closed: any malformed input terminates the connection without a
  response.

Building blocks:

| Purpose | Construction | Implementation |
| --- | --- | --- |
| Handshake & transport | Noise `XKpsk3_25519_ChaChaPoly_BLAKE2s` (Noise spec rev. 34) | [`snow`](https://crates.io/crates/snow) |
| Post-quantum KEM | ML-KEM-768 (FIPS 203) | [`libcrux-ml-kem`](https://crates.io/crates/libcrux-ml-kem) (formally verified) |
| Passphrase KDF | Argon2id v1.3 (RFC 9106) | [`argon2`](https://crates.io/crates/argon2) |
| Storage encryption | XChaCha20-Poly1305 | [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) |
| Fingerprints, checksums | BLAKE2b | [`blake2`](https://crates.io/crates/blake2) |
| Randomness | OS CSPRNG | [`getrandom`](https://crates.io/crates/getrandom) |

## 2. Identities

Each profile has one long-term X25519 key pair (the Noise static key). The
public key *is* the identity; there are no user names on the wire. Contacts
are stored locally as `(local name, public key, optional address, verified)`.

### 2.1 Invite codes

An invite code transports a public key and an optional address:

```
"neccrit:" || base32_nopad_lowercase(
    0x01                       version
    pubkey[32]
    addr_len[1] || addr        UTF-8, "host:port", "[v6]:port" or "<onion>.onion:port"
    name_len[1] || name        UTF-8, <= 64 bytes, untrusted suggestion
    checksum[4]                BLAKE2b-32bit("neccrit invite checksum v1" || preceding bytes)
)
```

The checksum only detects typos. **An invite code is not authenticated.**
Whoever controls the channel it travels over can substitute their own key,
which is why contacts must compare safety numbers.

### 2.2 Safety numbers

For a public key `K`:

```
h_0     = BLAKE2b-512("neccrit fingerprint v1" || K)
h_{i+1} = BLAKE2b-512(h_i || K)            for i = 0 .. 5199
fp(K)   = 6 groups: for j in 0..6: u40_be(h_5200[5j .. 5j+5]) mod 100000
```

The safety number of two parties is `fp(A) || fp(B)`, ordered so that both
see the same 60 digits (lexicographic order of the group lists). Because each
half depends on a single key, an attacker substituting keys must find a key
whose fingerprint matches the victim's on the compared digits (a second
preimage), not merely any collision; the iteration count raises the cost of
such a search. This mirrors the construction of Signal's safety numbers.

Users compare all 60 digits over a channel where they can authenticate each
other (in person, or a voice call) and then mark the contact as verified.

## 3. Transport

Connections are TCP streams, either direct or through a SOCKS5 proxy (Tor).
Every Noise message is framed as `len_u16_be || message`. Frames of length 0
or larger than the maximum for the current state are a fatal error.

### 3.1 Handshake

Pattern `Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s`, prologue
`"neccrit/1 Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s+ML-KEM-768"`.

```
XKpsk3:
  <- s
  ...
  -> e, es              payload: ek     ML-KEM-768 encapsulation key, 1184 bytes
  <- e, ee              payload: ct     ML-KEM-768 ciphertext,        1088 bytes
  -> s, se, psk         payload: empty
  <- (transport)        payload: KeepAlive (key confirmation)
```

1. The **initiator** knows the responder's static key from the contact
   entry. (Public keys of small order, for which every X25519 result is zero,
   are rejected wherever keys are parsed.) It generates a fresh ML-KEM-768 key pair `(dk, ek)` and sends
   message 1 with `ek` as payload (1232 bytes on the wire).
2. The **responder** processes message 1, which must arrive within 10 s of
   the TCP connection. Decryption of the payload only succeeds if the
   initiator used the responder's real static key; otherwise the connection
   is closed without any response. At most 32 handshakes are processed
   concurrently. The responder checks `ek`
   (FIPS 203 encapsulation key check), computes `(ct, ss) = Encaps(ek)`, sets
   `ss` as the PSK for the `psk` token and sends message 2 with `ct`
   (1136 bytes).
3. The initiator computes `ss = Decaps(dk, ct)`, sets it as PSK and sends
   message 3 (64 bytes), which transmits its static key encrypted and mixes in
   `ss` via the `psk` token.
4. The responder learns the initiator's static key from message 3 and accepts
   the session only if that key belongs to a contact. It then sends one
   transport message (`KeepAlive`). The initiator treats the session as
   established only after decrypting it (**key confirmation**). Unknown
   initiators therefore never observe a successful session.

The ephemeral X25519 and ML-KEM keys are discarded after the handshake.

**Why this is sound.** The Noise `psk` modifier is the mechanism the Noise
specification provides for mixing additional secret key material into the
handshake; the session keys are derived from a chaining key that has absorbed
the outputs of `ee`, `es`, `se` *and* `ss`. Recovering them therefore
requires breaking X25519 *and* ML-KEM. The same "KEM output as PSK" idea is
used by Rosenpass for WireGuard and is analysed in the PQNoise literature.
Authentication remains classical (X25519): a future quantum adversary could
impersonate peers in *new* sessions but cannot decrypt recorded ones.

Properties of `XK` (from the payload-security and identity-hiding tables of
the Noise specification): mutual authentication; the responder's
static key is never transmitted; the initiator's static key is encrypted with
forward secrecy; message 3's payload and all transport messages are
resistant to key-compromise impersonation.

### 3.2 Transport phase

Each transport frame carries one Noise transport message of at most
16 384 + 16 bytes. Noise nonces increment implicitly; since TCP delivers in
order, any replayed, dropped, reordered or modified frame fails decryption
and terminates the session.

After every message both directions apply Noise `Rekey()` (the sender after
encrypting, the receiver after decrypting). Old transport keys are thus
overwritten by a one-way function of themselves: a compromise of a running
session's state does not expose messages sent earlier in that session.

Plaintext structure before encryption:

```
message || 0x80 || 0x00*     padded to the smallest of 256, 1024, 4096, 16384 bytes

message =
    0x01 || id[16] || len_u16_be || utf8[len]    Text      (1 <= len <= 8192)
  | 0x02 || id[16]                               Receipt
  | 0x03                                         KeepAlive
  | 0x04                                         Close
```

Decoders reject non-canonical encodings: wrong bucket for the content length,
missing `0x80` marker, trailing bytes, invalid UTF-8, unknown types.

* `Text` ids are 128-bit random values. The receiver answers every `Text`
  with a `Receipt` for the same id and suppresses duplicates (the most
  recent 4096 ids per contact).
* The sender keeps unacknowledged messages in memory (at most 100 per
  contact) and re-sends them on every new session until a receipt arrives.
* `KeepAlive` is sent every 25 s; a session with no incoming frame for 80 s
  is closed. Keepalives, receipts and short texts share the 256-byte bucket.
* Inbound traffic is rate limited **per contact**, with budgets shared by all
  of that contact's sessions so that reconnecting does not refill them:
  frames burst 512 / 64 per second, text messages burst 150 / 2 per second
  (the burst covers flushing a full outbox). Exceeding a budget closes the
  session.
* Each session reads, writes and processes in separate tasks; a peer that is
  slow to read can never block reading (no mutual write deadlock when both
  sides flush large queues). A write that does not complete within the
  handshake timeout ends the session.

### 3.3 Session selection

A node dials a contact only while it has no session with them. When a new
session arrives while one exists:

* if the existing session is younger than the handshake timeout, both
  contacts dialled at (roughly) the same time: each side keeps the session
  whose **initiator has the lexicographically smaller static public key**, so
  both converge on the same session;
* otherwise the **newer session wins**: the peer dialled because, from its
  point of view, the old session is gone (for example after a network
  change), even if our end has not noticed yet;
* a newer session initiated by the same side always replaces the old one.

A replaced session is asked to close and is terminated after a two-second
grace period. Pending messages are re-sent on the surviving session;
duplicates are suppressed by id. The reconnect backoff (1 s doubling to 60 s,
plus jitter) is only reset by a session that lasted at least 30 s or by an
explicit user request, so a peer that keeps accepting and dropping
connections is not hammered.

### 3.4 Tor and SOCKS5

If a SOCKS5 proxy is configured, **all** outgoing connections use it; there
is no fallback to direct connections. Host names (including `.onion`) are
passed to the proxy as domain names, so no DNS lookups happen locally. Each
contact uses its own random SOCKS username/password per process run, which
Tor (`IsolateSOCKSAuth`, enabled by default) uses to put connections to
different contacts on different circuits. Onion addresses are refused when
no proxy is configured.

Receiving connections over Tor requires an onion service configured in Tor
that forwards to the local listen address (see README).

## 4. Local storage

The profile (identity key, settings, contacts) is serialised as JSON and
stored in a single file:

```
"NECCRITV" || 0x01 || 0x01 (Argon2id v1.3)
  || m_cost_kib_u32 || t_cost_u32 || p_cost_u32 || salt[16] || nonce[24]
  || XChaCha20-Poly1305(key, nonce, json, aad = all preceding bytes)

key = Argon2id(passphrase, salt, m = 64 MiB, t = 3, p = 4)   (RFC 9106 second recommendation)
```

* The header (including the KDF parameters) is authenticated, so cost
  parameters cannot be downgraded unnoticed; implausible parameters are
  rejected before running the KDF.
* Writes are atomic (temporary file, `fsync`, rename) with mode `0600`.
* Messages, message history and undelivered messages are never written to
  disk.

## 5. Versioning

The prologue binds the protocol version; peers with different versions fail
the handshake rather than misinterpret each other. Invite codes and the
profile file carry their own version bytes.
