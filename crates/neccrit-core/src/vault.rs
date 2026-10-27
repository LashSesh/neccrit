//! Encrypted on-disk storage of a [`Profile`].
//!
//! File layout (all integers big-endian):
//!
//! ```text
//! magic      8 bytes   "NECCRITV"
//! version    1 byte    0x01
//! kdf        1 byte    0x01 = Argon2id (v1.3)
//! m_cost     4 bytes   memory in KiB
//! t_cost     4 bytes   iterations
//! p_cost     4 bytes   lanes
//! salt      16 bytes
//! nonce     24 bytes
//! ciphertext           XChaCha20-Poly1305(key, nonce, plaintext, aad = all bytes above)
//! ```
//!
//! The key is derived once per unlock; every save uses a fresh random nonce.
//! Files are written atomically (temp file, fsync, rename) with mode 0600.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::profile::Profile;
use crate::random;

const MAGIC: &[u8; 8] = b"NECCRITV";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 8 + 1 + 1 + 12 + SALT_LEN + NONCE_LEN;
const MAX_FILE_LEN: u64 = 16 * 1024 * 1024;

/// Minimum passphrase length accepted when creating a vault.
pub const MIN_PASSPHRASE_CHARS: usize = 10;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// RFC 9106 "second recommended option": 64 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: Self = Self { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 4 };

    /// Cheap parameters for unit tests only. Never use for real profiles.
    pub const INSECURE_TEST_ONLY: Self = Self { m_cost_kib: 64, t_cost: 1, p_cost: 1 };

    /// Bounds enforced when reading a file, so a crafted profile cannot make
    /// the unlock consume unbounded memory or time.
    fn check_bounds(&self) -> Result<()> {
        let ok = (8..=4 * 1024 * 1024).contains(&self.m_cost_kib)
            && (1..=64).contains(&self.t_cost)
            && (1..=64).contains(&self.p_cost);
        if ok { Ok(()) } else { Err(Error::UnsupportedProfileFormat) }
    }

    fn derive(&self, passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
        self.check_bounds()?;
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|_| Error::UnsupportedProfileFormat)?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
            .map_err(|_| Error::UnsupportedProfileFormat)?;
        Ok(key)
    }
}

/// An unlocked profile file.
pub struct Vault {
    path: PathBuf,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("path", &self.path).field("params", &self.params).finish_non_exhaustive()
    }
}

/// Reject obviously weak passphrases at creation time.
pub fn check_new_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(Error::InvalidMessage("passphrase must be at least 10 characters long"));
    }
    Ok(())
}

impl Vault {
    /// Create a new vault file. Fails if the file already exists.
    pub fn create(path: &Path, passphrase: &str, params: KdfParams, profile: &Profile) -> Result<Self> {
        check_new_passphrase(passphrase)?;
        if path.exists() {
            return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "profile already exists")));
        }
        let salt = random::bytes::<SALT_LEN>()?;
        let key = params.derive(passphrase, &salt)?;
        let vault = Self { path: path.to_owned(), params, salt, key };
        vault.save(profile)?;
        Ok(vault)
    }

    /// Open and decrypt an existing vault.
    pub fn open(path: &Path, passphrase: &str) -> Result<(Self, Profile)> {
        let meta = fs::metadata(path)?;
        if meta.len() > MAX_FILE_LEN || meta.len() < (HEADER_LEN + 16) as u64 {
            return Err(Error::UnsupportedProfileFormat);
        }
        let data = fs::read(path)?;
        let (header, ciphertext) = data.split_at(HEADER_LEN);
        if &header[..8] != MAGIC || header[8] != FORMAT_VERSION || header[9] != KDF_ARGON2ID {
            return Err(Error::UnsupportedProfileFormat);
        }
        let be = |i: usize| u32::from_be_bytes([header[i], header[i + 1], header[i + 2], header[i + 3]]);
        let params = KdfParams { m_cost_kib: be(10), t_cost: be(14), p_cost: be(18) };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&header[22..22 + SALT_LEN]);
        let nonce = XNonce::from_slice(&header[22 + SALT_LEN..HEADER_LEN]);

        let key = params.derive(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, Payload { msg: ciphertext, aad: header })
                .map_err(|_| Error::WrongPassphraseOrCorrupt)?,
        );
        let profile: Profile = serde_json::from_slice(&plaintext).map_err(|_| Error::WrongPassphraseOrCorrupt)?;
        profile.check_version()?;
        Ok((Self { path: path.to_owned(), params, salt, key }, profile))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Encrypt and atomically write `profile`.
    pub fn save(&self, profile: &Profile) -> Result<()> {
        let mut plaintext = Zeroizing::new(Vec::with_capacity(8192 + 512 * profile.contacts().len()));
        serde_json::to_writer(&mut *plaintext, profile).map_err(|_| Error::ProfileSerialization)?;

        let nonce_bytes = random::bytes::<NONCE_LEN>()?;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(FORMAT_VERSION);
        header.push(KDF_ARGON2ID);
        header.extend_from_slice(&self.params.m_cost_kib.to_be_bytes());
        header.extend_from_slice(&self.params.t_cost.to_be_bytes());
        header.extend_from_slice(&self.params.p_cost.to_be_bytes());
        header.extend_from_slice(&self.salt);
        header.extend_from_slice(&nonce_bytes);

        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce_bytes), Payload { msg: &plaintext, aad: &header })
            .map_err(|_| Error::Crypto)?;
        let mut out = header;
        out.extend_from_slice(&ciphertext);
        write_atomic(&self.path, &out)?;
        Ok(())
    }

    /// Re-encrypt under a new passphrase (fresh salt).
    pub fn change_passphrase(&mut self, new_passphrase: &str, params: KdfParams, profile: &Profile) -> Result<()> {
        check_new_passphrase(new_passphrase)?;
        let salt = random::bytes::<SALT_LEN>()?;
        let key = params.derive(new_passphrase, &salt)?;
        let next = Self { path: self.path.clone(), params, salt, key };
        next.save(profile)?;
        *self = next;
        Ok(())
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut tmp_name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::Contact;
    use crate::identity::Identity;

    const PW: &str = "correct horse battery staple";

    fn profile() -> Profile {
        let mut p = Profile::new(Identity::generate().unwrap());
        let other = *Identity::generate().unwrap().public_key();
        p.add_contact(Contact::new("bob", other, None).unwrap()).unwrap();
        p
    }

    #[test]
    fn create_open_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.neccrit");
        let p = profile();
        let vault = Vault::create(&path, PW, KdfParams::INSECURE_TEST_ONLY, &p).unwrap();
        assert!(Vault::create(&path, PW, KdfParams::INSECURE_TEST_ONLY, &p).is_err(), "must not overwrite");

        let (vault2, loaded) = Vault::open(&path, PW).unwrap();
        assert_eq!(loaded.public_key(), p.public_key());
        assert_eq!(loaded.contacts(), p.contacts());

        let mut changed = loaded;
        changed.remove_contact("bob").unwrap();
        vault2.save(&changed).unwrap();
        let (_, reloaded) = Vault::open(&path, PW).unwrap();
        assert!(reloaded.contacts().is_empty());
        drop(vault);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn wrong_passphrase_and_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.neccrit");
        Vault::create(&path, PW, KdfParams::INSECURE_TEST_ONLY, &profile()).unwrap();
        assert!(matches!(Vault::open(&path, "wrong passphrase!"), Err(Error::WrongPassphraseOrCorrupt)));

        let original = fs::read(&path).unwrap();
        // Flip a ciphertext bit.
        let mut data = original.clone();
        let last = data.len() - 1;
        data[last] ^= 1;
        fs::write(&path, &data).unwrap();
        assert!(Vault::open(&path, PW).is_err());
        // Tamper with authenticated header (lower the KDF cost).
        let mut data = original.clone();
        data[17] ^= 1;
        fs::write(&path, &data).unwrap();
        assert!(Vault::open(&path, PW).is_err());
        // Absurd KDF parameters are refused before deriving.
        let mut data = original;
        data[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        fs::write(&path, &data).unwrap();
        assert!(matches!(Vault::open(&path, PW), Err(Error::UnsupportedProfileFormat)));
    }

    #[test]
    fn plaintext_not_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.neccrit");
        let p = profile();
        Vault::create(&path, PW, KdfParams::INSECURE_TEST_ONLY, &p).unwrap();
        let raw = fs::read(&path).unwrap();
        let needle = p.public_key().to_base32();
        assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()));
        assert!(!raw.windows(3).any(|w| w == b"bob"));
    }

    #[test]
    fn change_passphrase_works() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.neccrit");
        let p = profile();
        let mut vault = Vault::create(&path, PW, KdfParams::INSECURE_TEST_ONLY, &p).unwrap();
        vault.change_passphrase("another long passphrase", KdfParams::INSECURE_TEST_ONLY, &p).unwrap();
        assert!(Vault::open(&path, PW).is_err());
        assert!(Vault::open(&path, "another long passphrase").is_ok());
    }

    #[test]
    fn weak_passphrase_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.neccrit");
        assert!(Vault::create(&path, "short", KdfParams::INSECURE_TEST_ONLY, &profile()).is_err());
        assert!(!path.exists());
    }
}
