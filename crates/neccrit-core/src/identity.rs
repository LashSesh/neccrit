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
    /// Parse a public key. Rejects keys of small order (such as all zeros),
    /// for which every Diffie-Hellman result is zero: anyone could
    /// impersonate a "contact" with such a key.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
        if is_small_order(&arr)? {
            return Err(Error::InvalidPublicKey);
        }
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

/// X25519 clamps scalars to multiples of the cofactor, so the shared secret
/// with a point of small order is zero for *every* private key. Checking one
/// exchange with a throwaway key therefore detects all such points, including
/// non-canonical encodings.
fn is_small_order(key: &[u8; KEY_LEN]) -> Result<bool> {
    use snow::params::DHChoice;
    use snow::resolvers::{CryptoResolver, DefaultResolver};

    let resolver = DefaultResolver;
    let mut dh = resolver.resolve_dh(&DHChoice::Curve25519).ok_or(Error::Handshake)?;
    let mut rng = resolver.resolve_rng().ok_or(Error::Rng)?;
    dh.generate(&mut *rng).map_err(|_| Error::Rng)?;
    let mut shared = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    dh.dh(key, shared.as_mut()).map_err(|_| Error::InvalidPublicKey)?;
    Ok(shared.iter().all(|&b| b == 0))
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
    fn rejects_small_order_points() {
        let hex = |s: &str| -> [u8; 32] {
            let v: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
            v.try_into().unwrap()
        };
        let mut one = [0u8; 32];
        one[0] = 1;
        let small_order = [
            [0u8; 32],
            one,
            hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            // The same points with the (ignored, RFC 7748) top bit set.
            hex("0000000000000000000000000000000000000000000000000000000000000080"),
            hex("0100000000000000000000000000000000000000000000000000000000000080"),
            hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"),
            hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7"),
            hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ];
        for key in small_order {
            assert!(PublicKey::from_slice(&key).is_err(), "accepted {key:02x?}");
        }
        let b32 = BASE32_NOPAD.encode(&[0u8; 32]).to_ascii_lowercase();
        assert!(PublicKey::from_base32(&b32).is_err());
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
