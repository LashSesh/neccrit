//! Contacts, invite codes and safety numbers.
//!
//! An [`Invite`] is a short text code that carries a public key and an
//! optional address. It is meant to be transferred over any channel; its
//! checksum only catches typos. **Authenticity comes exclusively from
//! comparing the [`SafetyNumber`] over a trusted channel** (in person, a
//! phone call with a known voice, ...).

use std::fmt;

use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar, Digest};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use crate::address::{MAX_ADDRESS_LEN, PeerAddress};
use crate::error::{Error, Result};
use crate::identity::{KEY_LEN, PublicKey};

/// Prefix of every invite code.
pub const INVITE_PREFIX: &str = "neccrit:";
const INVITE_VERSION: u8 = 1;
const INVITE_CHECKSUM_LEN: usize = 4;
/// Maximum length (in bytes) of the name hint inside an invite.
pub const MAX_NAME_HINT_LEN: usize = 64;
/// Maximum length (in bytes) of a local contact name.
pub const MAX_CONTACT_NAME_LEN: usize = 64;

/// A contact as stored in the local profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Local, user-chosen name. Never sent over the network.
    pub name: String,
    pub public_key: PublicKey,
    pub address: Option<PeerAddress>,
    /// Set once the user confirmed that the safety numbers match.
    pub verified: bool,
}

impl Contact {
    pub fn new(name: &str, public_key: PublicKey, address: Option<PeerAddress>) -> Result<Self> {
        Ok(Self { name: validate_contact_name(name)?, public_key, address, verified: false })
    }
}

/// Validate a local contact name: 1..=64 bytes, no control or invisible
/// formatting characters, no leading/trailing whitespace, no whitespace
/// inside (names are used as command arguments).
pub fn validate_contact_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_CONTACT_NAME_LEN {
        return Err(Error::InvalidMessage("contact names must be 1 to 64 bytes long"));
    }
    if name.chars().any(|c| c.is_whitespace() || c.is_control() || is_invisible_format_char(c)) {
        return Err(Error::InvalidMessage(
            "contact names must not contain whitespace, control or invisible characters",
        ));
    }
    Ok(name.to_owned())
}

/// Unicode format characters that are invisible or reorder text (bidi
/// controls, zero-width characters, tag characters). They are rejected in
/// names and must be made visible when displaying untrusted text.
pub fn is_invisible_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{034F}'
        | '\u{061C}'
        | '\u{115F}'..='\u{1160}'
        | '\u{17B4}'..='\u{17B5}'
        | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}'
        | '\u{3164}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{FEFF}'
        | '\u{FFA0}'
        | '\u{FFF0}'..='\u{FFFB}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// The contents of an invite code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub public_key: PublicKey,
    pub address: Option<PeerAddress>,
    /// Name the sender suggested for themselves. Untrusted; only used as a
    /// default suggestion.
    pub name_hint: Option<String>,
}

impl Invite {
    pub fn encode(&self) -> Result<String> {
        let address = self.address.as_ref().map(ToString::to_string).unwrap_or_default();
        let name = self.name_hint.clone().unwrap_or_default();
        if address.len() > MAX_ADDRESS_LEN {
            return Err(Error::InvalidInvite("address too long"));
        }
        if name.len() > MAX_NAME_HINT_LEN {
            return Err(Error::InvalidInvite("name too long"));
        }
        let mut body = Vec::with_capacity(1 + KEY_LEN + 2 + address.len() + name.len());
        body.push(INVITE_VERSION);
        body.extend_from_slice(self.public_key.as_bytes());
        body.push(address.len() as u8);
        body.extend_from_slice(address.as_bytes());
        body.push(name.len() as u8);
        body.extend_from_slice(name.as_bytes());
        let checksum = invite_checksum(&body);
        body.extend_from_slice(&checksum);
        Ok(format!("{INVITE_PREFIX}{}", BASE32_NOPAD.encode(&body).to_ascii_lowercase()))
    }

    pub fn decode(code: &str) -> Result<Self> {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let lower = code.to_ascii_lowercase();
        let payload = lower.strip_prefix(INVITE_PREFIX).ok_or(Error::InvalidInvite("missing 'neccrit:' prefix"))?;
        let raw = BASE32_NOPAD
            .decode(payload.to_ascii_uppercase().as_bytes())
            .map_err(|_| Error::InvalidInvite("not valid base32"))?;
        if raw.len() < 1 + KEY_LEN + 2 + INVITE_CHECKSUM_LEN {
            return Err(Error::InvalidInvite("too short"));
        }
        let (body, checksum) = raw.split_at(raw.len() - INVITE_CHECKSUM_LEN);
        if invite_checksum(body) != checksum {
            return Err(Error::InvalidInvite("checksum mismatch (typo?)"));
        }
        if body[0] != INVITE_VERSION {
            return Err(Error::InvalidInvite("unsupported version"));
        }
        let mut rest = &body[1..];
        let public_key = PublicKey::from_slice(take(&mut rest, KEY_LEN)?)?;
        let addr_len = usize::from(take(&mut rest, 1)?[0]);
        let address = std::str::from_utf8(take(&mut rest, addr_len)?)
            .map_err(|_| Error::InvalidInvite("address is not UTF-8"))?;
        let name_len = usize::from(take(&mut rest, 1)?[0]);
        if name_len > MAX_NAME_HINT_LEN {
            return Err(Error::InvalidInvite("name too long"));
        }
        let name =
            std::str::from_utf8(take(&mut rest, name_len)?).map_err(|_| Error::InvalidInvite("name is not UTF-8"))?;
        if !rest.is_empty() {
            return Err(Error::InvalidInvite("trailing data"));
        }
        let address = if address.is_empty() {
            None
        } else {
            Some(address.parse().map_err(|_| Error::InvalidInvite("invalid address"))?)
        };
        let name_hint = validate_contact_name(name).ok();
        Ok(Self { public_key, address, name_hint })
    }
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if rest.len() < n {
        return Err(Error::InvalidInvite("truncated"));
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn invite_checksum(body: &[u8]) -> [u8; INVITE_CHECKSUM_LEN] {
    let mut hasher = Blake2bVar::new(INVITE_CHECKSUM_LEN).unwrap_or_else(|_| unreachable!());
    hasher.update(b"neccrit invite checksum v1");
    hasher.update(body);
    let mut out = [0u8; INVITE_CHECKSUM_LEN];
    hasher.finalize_variable(&mut out).unwrap_or_else(|_| unreachable!());
    out
}

/// Iterations of the fingerprint hash. Raises the cost of grinding for a key
/// whose fingerprint matches a victim's on the displayed digits (the same
/// approach and order of magnitude as Signal's safety numbers).
const FINGERPRINT_ITERATIONS: usize = 5200;
const FINGERPRINT_GROUPS: usize = 6;

/// The 30-digit fingerprint of a single public key.
fn fingerprint_digits(key: &PublicKey) -> [u32; FINGERPRINT_GROUPS] {
    let mut hash = Blake2b512::new().chain_update(b"neccrit fingerprint v1").chain_update(key.as_bytes()).finalize();
    for _ in 0..FINGERPRINT_ITERATIONS {
        hash = Blake2b512::new().chain_update(hash).chain_update(key.as_bytes()).finalize();
    }
    let mut groups = [0u32; FINGERPRINT_GROUPS];
    for (i, group) in groups.iter_mut().enumerate() {
        let chunk = &hash[i * 5..i * 5 + 5];
        let value = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        *group = (value % 100_000) as u32;
    }
    groups
}

/// A 60-digit number that two contacts compare over a trusted channel to
/// rule out a man-in-the-middle.
///
/// It is the concatenation of both parties' 30-digit fingerprints, ordered so
/// that both sides see the same number. Because each half depends on only one
/// key, an attacker cannot use a birthday attack: they would need a key
/// whose fingerprint matches the victim's.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SafetyNumber {
    groups: [u32; FINGERPRINT_GROUPS * 2],
}

impl SafetyNumber {
    pub fn new(a: &PublicKey, b: &PublicKey) -> Self {
        let fa = fingerprint_digits(a);
        let fb = fingerprint_digits(b);
        let (first, second) = if fa <= fb { (fa, fb) } else { (fb, fa) };
        let mut groups = [0u32; FINGERPRINT_GROUPS * 2];
        groups[..FINGERPRINT_GROUPS].copy_from_slice(&first);
        groups[FINGERPRINT_GROUPS..].copy_from_slice(&second);
        Self { groups }
    }

    /// Twelve groups of five digits.
    pub fn groups(&self) -> Vec<String> {
        self.groups.iter().map(|g| format!("{g:05}")).collect()
    }

    /// Three lines of four groups, convenient to read aloud.
    pub fn to_lines(&self) -> [String; 3] {
        let g = self.groups();
        [g[0..4].join(" "), g[4..8].join(" "), g[8..12].join(" ")]
    }
}

impl fmt::Display for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.groups().join(" "))
    }
}

impl fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafetyNumber({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn key() -> PublicKey {
        *Identity::generate().unwrap().public_key()
    }

    #[test]
    fn invite_roundtrip() {
        let invite = Invite {
            public_key: key(),
            address: Some("192.0.2.7:7878".parse().unwrap()),
            name_hint: Some("alice".into()),
        };
        let code = invite.encode().unwrap();
        assert!(code.starts_with(INVITE_PREFIX));
        assert_eq!(Invite::decode(&code).unwrap(), invite);
        // Case and whitespace insensitive (e.g. after line wrapping).
        let mangled = format!(" {}\n{} ", code[..20].to_uppercase(), &code[20..]);
        assert_eq!(Invite::decode(&mangled).unwrap(), invite);
    }

    #[test]
    fn invite_without_address_or_name() {
        let invite = Invite { public_key: key(), address: None, name_hint: None };
        assert_eq!(Invite::decode(&invite.encode().unwrap()).unwrap(), invite);
    }

    #[test]
    fn invite_detects_typos() {
        let invite = Invite { public_key: key(), address: None, name_hint: Some("bob".into()) };
        let code = invite.encode().unwrap();
        let mut chars: Vec<char> = code.chars().collect();
        let pos = INVITE_PREFIX.len() + 10;
        chars[pos] = if chars[pos] == 'a' { 'b' } else { 'a' };
        let typo: String = chars.into_iter().collect();
        assert!(Invite::decode(&typo).is_err());
        assert!(Invite::decode("neccrit:").is_err());
        assert!(Invite::decode("hello").is_err());
    }

    #[test]
    fn invite_drops_hostile_name_hint() {
        let invite = Invite { public_key: key(), address: None, name_hint: Some("evil\u{202e}gnp".into()) };
        let decoded = Invite::decode(&invite.encode().unwrap()).unwrap();
        assert_eq!(decoded.name_hint, None);
    }

    #[test]
    fn safety_number_is_symmetric_and_distinct() {
        let (a, b, c) = (key(), key(), key());
        let ab = SafetyNumber::new(&a, &b);
        assert_eq!(ab, SafetyNumber::new(&b, &a));
        assert_ne!(ab, SafetyNumber::new(&a, &c));
        let text = ab.to_string();
        assert_eq!(text.len(), 12 * 5 + 11);
        assert!(text.chars().all(|c| c.is_ascii_digit() || c == ' '));
    }

    #[test]
    fn contact_name_validation() {
        assert!(validate_contact_name("alice").is_ok());
        assert!(validate_contact_name("Jürgen").is_ok());
        for bad in ["", " ", "a b", "x\u{200b}y", "x\u{202e}y", "a\nb", &"x".repeat(65)] {
            assert!(validate_contact_name(bad).is_err(), "accepted {bad:?}");
        }
    }
}
