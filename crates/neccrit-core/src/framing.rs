//! Length-prefixed framing of Noise messages on a byte stream
//! (2-byte big-endian length, as recommended by the Noise specification).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Absolute upper bound imposed by the 2-byte length prefix and by Noise.
pub(crate) const NOISE_MAX_MESSAGE: usize = 65_535;

pub(crate) async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let len = u16::try_from(payload.len()).map_err(|_| Error::Protocol("frame too large"))?;
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame, rejecting empty frames and frames larger than `max_len`
/// before allocating.
pub(crate) async fn read_frame<R: AsyncRead + Unpin + ?Sized>(reader: &mut R, max_len: usize) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 || len > max_len.min(NOISE_MAX_MESSAGE) {
        return Err(Error::Protocol("invalid frame length"));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_and_limits() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        write_frame(&mut a, b"hello").await.unwrap();
        assert_eq!(read_frame(&mut b, 16).await.unwrap(), b"hello");

        write_frame(&mut a, &[1u8; 17]).await.unwrap();
        assert!(read_frame(&mut b, 16).await.is_err());

        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0]).await.unwrap();
        assert!(read_frame(&mut b, 16).await.is_err());

        assert!(write_frame(&mut a, &vec![0u8; NOISE_MAX_MESSAGE + 1]).await.is_err());
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 10, 1, 2, 3]).await.unwrap();
        drop(a);
        assert!(read_frame(&mut b, 64).await.is_err());
    }
}
