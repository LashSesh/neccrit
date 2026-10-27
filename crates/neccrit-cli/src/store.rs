//! Locating, unlocking and locking the profile on disk.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use neccrit_core::Profile;
use neccrit_core::vault::{KdfParams, Vault, check_new_passphrase};
use zeroize::Zeroizing;

const PROFILE_FILE: &str = "profile.neccrit";
const LOCK_FILE: &str = "lock";

/// Platform data directory: `$XDG_DATA_HOME/neccrit` or
/// `~/.local/share/neccrit` on Linux/BSD, `~/Library/Application Support/neccrit`
/// on macOS, `%APPDATA%\neccrit` on Windows.
#[cfg(target_os = "windows")]
fn default_data_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("neccrit"))
}

#[cfg(target_os = "macos")]
fn default_data_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/neccrit"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn default_data_dir() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p| p.is_absolute());
    xdg.or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share"))).map(|p| p.join("neccrit"))
}

/// How to obtain the passphrase.
#[derive(Clone, Debug)]
pub enum PassphraseSource {
    Prompt,
    /// First line of a file (for scripting; keep the file private).
    File(PathBuf),
}

impl PassphraseSource {
    fn read(&self, prompt: &str) -> Result<Zeroizing<String>> {
        match self {
            Self::Prompt => Ok(Zeroizing::new(rpassword::prompt_password(prompt).context("reading passphrase")?)),
            Self::File(path) => {
                let content = Zeroizing::new(fs::read_to_string(path).context("reading passphrase file")?);
                let line = content.lines().next().unwrap_or_default();
                Ok(Zeroizing::new(line.to_owned()))
            }
        }
    }

    fn read_new(&self) -> Result<Zeroizing<String>> {
        let first = self.read("New passphrase (at least 10 characters): ")?;
        check_new_passphrase(&first)?;
        if matches!(self, Self::Prompt) {
            let second = self.read("Repeat passphrase: ")?;
            if *first != *second {
                bail!("passphrases do not match");
            }
        }
        Ok(first)
    }
}

/// A profile directory.
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    passphrase: PassphraseSource,
}

/// Exclusive lock held while a command modifies the profile, so that two
/// processes cannot overwrite each other's changes.
#[derive(Debug)]
pub struct ProfileLock {
    _file: File,
}

impl Store {
    pub fn new(dir: Option<PathBuf>, passphrase: PassphraseSource) -> Result<Self> {
        let dir = match dir {
            Some(dir) => dir,
            None => default_data_dir().context("cannot determine a data directory; use --profile")?,
        };
        Ok(Self { dir, passphrase })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn profile_path(&self) -> PathBuf {
        self.dir.join(PROFILE_FILE)
    }

    pub fn exists(&self) -> bool {
        self.profile_path().exists()
    }

    fn ensure_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir).with_context(|| format!("creating {}", self.dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }

    pub fn lock(&self) -> Result<ProfileLock> {
        self.ensure_dir()?;
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(self.dir.join(LOCK_FILE)).context("opening lock file")?;
        match file.try_lock() {
            Ok(()) => Ok(ProfileLock { _file: file }),
            Err(_) => bail!("the profile is being modified by another neccrit process"),
        }
    }

    pub fn create(&self, profile: &Profile) -> Result<Vault> {
        self.ensure_dir()?;
        if self.exists() {
            bail!("a profile already exists in {}", self.dir.display());
        }
        let passphrase = self.passphrase.read_new()?;
        Ok(Vault::create(&self.profile_path(), &passphrase, KdfParams::DEFAULT, profile)?)
    }

    pub fn open(&self) -> Result<(Vault, Profile)> {
        if !self.exists() {
            bail!("no profile found in {} (run `neccrit init` first)", self.dir.display());
        }
        let passphrase = self.passphrase.read("Passphrase: ")?;
        Ok(Vault::open(&self.profile_path(), &passphrase)?)
    }

    pub fn change_passphrase(&self, vault: &mut Vault, profile: &Profile) -> Result<()> {
        let passphrase = self.passphrase.read_new()?;
        Ok(vault.change_passphrase(&passphrase, KdfParams::DEFAULT, profile)?)
    }
}
