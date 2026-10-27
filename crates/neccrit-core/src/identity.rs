//! Long-term identity keys.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::handshake::NOISE_PARAMS;

/// Length of an X25519 public or private key.
pub const KEY_LEN: usize = 32;

/// An X25519 public key identifying a neccrit profile.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Lower-case, unpadded base32 rendering (52 characters).
    pub fn to_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0).to_ascii_lowercase()
    }

    pub fn from_base32(text: &str) -> Result<Self> {
        let bytes =
            BASE32_NOPAD.decode(text.trim().to_ascii_uppercase().as_bytes()).map_err(|_| Error::InvalidPublicKey)?;
        Self::from_slice(&bytes)
    }

    /// Short, human-friendly tag (first 16 base32 characters). This is only a
    /// label for display; it is **not** sufficient for verification. Use
    /// [`crate::SafetyNumber`] for that.
    pub fn short_id(&self) -> String {
        let full = self.to_base32();
        format!("{}-{}-{}-{}", &full[0..4], &full[4..8], &full[8..12], &full[12..16])
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.short_id())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short_id())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base32())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        PublicKey::from_base32(&text).map_err(serde::de::Error::custom)
    }
}

/// The local long-term key pair.
///
/// The private key is zeroized when the value is dropped and is never
/// printed by `Debug`.
#[derive(Clone)]
pub struct Identity {
    secret: Zeroizing<[u8; KEY_LEN]>,
    public: PublicKey,
}

impl Identity {
    /// Generate a fresh key pair from the operating system CSPRNG.
    pub fn generate() -> Result<Self> {
        let params = NOISE_PARAMS.parse().map_err(|_| Error::Handshake)?;
        let keypair = snow::Builder::new(params).generate_keypair()?;
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        secret.copy_from_slice(&keypair.private);
        let mut private = keypair.private;
        zeroize::Zeroize::zeroize(&mut private);
        Ok(Self { secret, public: PublicKey::from_slice(&keypair.public)? })
    }

    /// Reassemble an identity from stored key material.
    pub(crate) fn from_parts(secret: Zeroizing<[u8; KEY_LEN]>, public: PublicKey) -> Self {
        Self { secret, public }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub(crate) fn secret_bytes(&self) -> &[u8; KEY_LEN] {
        &self.secret
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").field("public", &self.public).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        let id = Identity::generate().unwrap();
        let text = id.public_key().to_base32();
        assert_eq!(text.len(), 52);
        assert_eq!(PublicKey::from_base32(&text).unwrap(), *id.public_key());
        assert_eq!(PublicKey::from_base32(&text.to_uppercase()).unwrap(), *id.public_key());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(PublicKey::from_slice(&[0u8; 31]).is_err());
        assert!(PublicKey::from_base32("abcd").is_err());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let id = Identity::generate().unwrap();
        let dbg = format!("{id:?}");
        let secret_b32 = BASE32_NOPAD.encode(id.secret_bytes()).to_ascii_lowercase();
        assert!(!dbg.contains(&secret_b32[..16]));
    }

    #[test]
    fn keys_are_unique() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }
}
