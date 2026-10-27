//! The local profile: identity key, settings and contacts.
//!
//! A profile is only ever stored encrypted (see [`crate::vault`]).

use std::net::SocketAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::address::PeerAddress;
use crate::contact::{Contact, Invite, MAX_NAME_HINT_LEN, validate_contact_name};
use crate::error::{Error, Result};
use crate::identity::{Identity, KEY_LEN, PublicKey};

const PROFILE_VERSION: u32 = 1;

/// Everything neccrit stores about the local user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    version: u32,
    #[serde(with = "identity_serde")]
    identity: Identity,
    /// Name suggested to contacts inside invite codes. Optional.
    pub display_name: Option<String>,
    /// Local socket to accept connections on. `None` disables listening.
    pub listen: Option<SocketAddr>,
    /// Address contacts should use to reach this profile (put into invites),
    /// e.g. an onion address or a public host name.
    pub advertised_address: Option<PeerAddress>,
    /// SOCKS5 proxy (normally Tor at 127.0.0.1:9050) used for **all**
    /// outgoing connections when set.
    pub socks5_proxy: Option<SocketAddr>,
    contacts: Vec<Contact>,
}

impl Profile {
    pub fn new(identity: Identity) -> Self {
        Self {
            version: PROFILE_VERSION,
            identity,
            display_name: None,
            listen: None,
            advertised_address: None,
            socks5_proxy: None,
            contacts: Vec::new(),
        }
    }

    pub(crate) fn check_version(&self) -> Result<()> {
        if self.version == PROFILE_VERSION { Ok(()) } else { Err(Error::UnsupportedProfileFormat) }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn public_key(&self) -> &PublicKey {
        self.identity.public_key()
    }

    pub fn contacts(&self) -> &[Contact] {
        &self.contacts
    }

    pub fn contact(&self, name: &str) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.name == name)
    }

    pub fn contact_mut(&mut self, name: &str) -> Option<&mut Contact> {
        self.contacts.iter_mut().find(|c| c.name == name)
    }

    pub fn contact_by_key(&self, key: &PublicKey) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.public_key == *key)
    }

    /// Add a contact. Names and keys must be unique, and the own key cannot
    /// be added.
    pub fn add_contact(&mut self, contact: Contact) -> Result<()> {
        validate_contact_name(&contact.name)?;
        if contact.public_key == *self.public_key() {
            return Err(Error::InvalidMessage("this invite is your own"));
        }
        if self.contact(&contact.name).is_some() {
            return Err(Error::InvalidMessage("a contact with this name already exists"));
        }
        if let Some(existing) = self.contact_by_key(&contact.public_key) {
            return Err(Error::InvalidMessage(if existing.verified {
                "this key is already a (verified) contact under another name"
            } else {
                "this key is already a contact under another name"
            }));
        }
        self.contacts.push(contact);
        Ok(())
    }

    pub fn remove_contact(&mut self, name: &str) -> Result<Contact> {
        let idx = self.contacts.iter().position(|c| c.name == name).ok_or(Error::UnknownContact)?;
        Ok(self.contacts.remove(idx))
    }

    /// Rename a contact.
    pub fn rename_contact(&mut self, old: &str, new: &str) -> Result<()> {
        let new = validate_contact_name(new)?;
        if self.contact(&new).is_some() {
            return Err(Error::InvalidMessage("a contact with this name already exists"));
        }
        self.contact_mut(old).ok_or(Error::UnknownContact)?.name = new;
        Ok(())
    }

    /// The invite code for this profile.
    pub fn invite(&self) -> Invite {
        let name_hint = self
            .display_name
            .as_deref()
            .filter(|n| n.len() <= MAX_NAME_HINT_LEN)
            .and_then(|n| validate_contact_name(n).ok());
        Invite { public_key: *self.public_key(), address: self.advertised_address.clone(), name_hint }
    }
}

mod identity_serde {
    use super::*;

    #[derive(Serialize)]
    struct Out<'a> {
        secret: &'a str,
        public: &'a PublicKey,
    }

    #[derive(Deserialize)]
    struct In<'a> {
        #[serde(borrow)]
        secret: std::borrow::Cow<'a, str>,
        public: PublicKey,
    }

    pub(super) fn serialize<S: Serializer>(identity: &Identity, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let secret = Zeroizing::new(data_encoding::BASE32_NOPAD.encode(identity.secret_bytes()));
        Out { secret: &secret, public: identity.public_key() }.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Identity, D::Error> {
        let raw = In::deserialize(deserializer)?;
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        let decoded = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(raw.secret.as_bytes())
                .map_err(|_| serde::de::Error::custom("invalid secret key"))?,
        );
        if decoded.len() != KEY_LEN {
            return Err(serde::de::Error::custom("invalid secret key"));
        }
        secret.copy_from_slice(&decoded);
        if let std::borrow::Cow::Owned(mut s) = raw.secret {
            zeroize::Zeroize::zeroize(&mut s);
        }
        Ok(Identity::from_parts(secret, raw.public))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn other_key() -> PublicKey {
        *Identity::generate().unwrap().public_key()
    }

    #[test]
    fn contact_management() {
        let mut p = Profile::new(Identity::generate().unwrap());
        let k1 = other_key();
        p.add_contact(Contact::new("bob", k1, None).unwrap()).unwrap();
        assert!(p.add_contact(Contact::new("bob", other_key(), None).unwrap()).is_err());
        assert!(p.add_contact(Contact::new("robert", k1, None).unwrap()).is_err());
        let own = *p.public_key();
        assert!(p.add_contact(Contact::new("me", own, None).unwrap()).is_err());
        p.rename_contact("bob", "robert").unwrap();
        assert!(p.contact("bob").is_none());
        assert_eq!(p.contact_by_key(&k1).unwrap().name, "robert");
        p.remove_contact("robert").unwrap();
        assert!(p.contacts().is_empty());
    }

    #[test]
    fn serde_roundtrip_keeps_identity() {
        let mut p = Profile::new(Identity::generate().unwrap());
        p.display_name = Some("alice".into());
        p.listen = Some("127.0.0.1:7878".parse().unwrap());
        p.add_contact(Contact::new("bob", other_key(), Some("192.0.2.1:7878".parse().unwrap())).unwrap()).unwrap();
        let json = serde_json::to_vec(&p).unwrap();
        let back: Profile = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.public_key(), p.public_key());
        assert_eq!(back.identity().secret_bytes(), p.identity().secret_bytes());
        assert_eq!(back.contacts(), p.contacts());
        assert_eq!(back.invite(), p.invite());
    }
}
