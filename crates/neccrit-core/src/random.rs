use crate::error::{Error, Result};

/// Fill `N` bytes from the operating system CSPRNG.
pub(crate) fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Rng)?;
    Ok(out)
}

/// Uniform-ish jitter in `0..max_ms` milliseconds (modulo bias is irrelevant
/// for retry jitter).
pub(crate) fn jitter_ms(max_ms: u64) -> u64 {
    if max_ms == 0 {
        return 0;
    }
    bytes::<8>().map_or(0, |b| u64::from_le_bytes(b) % max_ms)
}
