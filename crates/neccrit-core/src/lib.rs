//! Core of the neccrit end-to-end encrypted messenger.
//!
//! The crate is deliberately small and built only from established,
//! well-reviewed constructions:
//!
//! * **Transport security:** the Noise protocol framework
//!   (`Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s`, via the `snow` crate) with an
//!   ephemeral ML-KEM-768 key encapsulation (formally verified `libcrux`
//!   implementation) mixed in as the PSK. The resulting session keys are only
//!   compromised if *both* X25519 and ML-KEM are broken. See
//!   [`handshake`] and `docs/PROTOCOL.md`.
//! * **Identity:** a long-term X25519 key pair per profile. Contacts are pinned
//!   by public key and verified out of band with a [`contact::SafetyNumber`].
//! * **Storage:** the whole profile (identity key, settings, contacts) is a
//!   single file encrypted with XChaCha20-Poly1305 under a key derived from the
//!   user's passphrase with Argon2id. Message history is never written to disk.
//! * **Traffic shape:** every message is padded to a small set of fixed bucket
//!   sizes before encryption; keepalives are indistinguishable from short
//!   messages.
//!
//! There is intentionally no steganography, traffic "mimicry" or other
//! camouflage functionality in this crate. See `docs/PROTOTYPE_REVIEW.md` for
//! the reasoning.

pub mod address;
pub mod contact;
mod error;
mod framing;
pub mod handshake;
pub mod identity;
pub mod node;
pub mod profile;
mod random;
mod session;
pub mod vault;
pub mod wire;

pub use address::PeerAddress;
pub use contact::{Contact, Invite, SafetyNumber};
pub use error::{Error, Result};
pub use identity::{Identity, PublicKey};
pub use node::{ContactRef, Event, Node, NodeConfig, NodeHandle};
pub use profile::Profile;
pub use wire::MessageId;
