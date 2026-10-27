use crate::identity::PublicKey;

/// Errors produced by `neccrit-core`.
///
/// Error messages never contain message content or key material.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cryptographic handshake failed")]
    Handshake,

    #[error("decryption or authentication failed")]
    Crypto,

    #[error("protocol violation: {0}")]
    Protocol(&'static str),

    #[error("peer is not in the contact list: {0}")]
    UnknownPeer(PublicKey),

    #[error("operation timed out")]
    Timeout,

    #[error("invalid invite code: {0}")]
    InvalidInvite(&'static str),

    #[error("invalid address: {0}")]
    InvalidAddress(&'static str),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("wrong passphrase or corrupted profile")]
    WrongPassphraseOrCorrupt,

    #[error("unsupported profile format")]
    UnsupportedProfileFormat,

    #[error("profile serialization failed")]
    ProfileSerialization,

    #[error("operating system random number generator failed")]
    Rng,

    #[error("message rejected: {0}")]
    InvalidMessage(&'static str),

    #[error("unknown contact")]
    UnknownContact,

    #[error("too many undelivered messages for this contact")]
    OutboxFull,

    #[error("proxy connection failed: {0}")]
    Proxy(String),

    #[error("the node has shut down")]
    NodeStopped,
}

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<snow::Error> for Error {
    fn from(err: snow::Error) -> Self {
        match err {
            snow::Error::Decrypt => Error::Crypto,
            _ => Error::Handshake,
        }
    }
}
