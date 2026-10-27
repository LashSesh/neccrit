//! Application messages exchanged inside an established encrypted session.
//!
//! Every message is encoded into a strict binary format and then padded to
//! one of a few fixed bucket sizes (ISO/IEC 7816-4 padding: a single `0x80`
//! byte followed by zeros) **before** encryption, so that an observer only
//! learns which bucket a message falls into, not its exact length.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Maximum size of a text message body in bytes (UTF-8).
pub const MAX_TEXT_BYTES: usize = 8 * 1024;

/// Padded plaintext sizes. Keepalives, receipts and short texts all use the
/// smallest bucket and are indistinguishable on the wire.
pub const PADDING_BUCKETS: [usize; 4] = [256, 1024, 4096, 16 * 1024];

/// Largest padded plaintext.
pub const MAX_PADDED_LEN: usize = PADDING_BUCKETS[PADDING_BUCKETS.len() - 1];

const TAG_TEXT: u8 = 0x01;
const TAG_RECEIPT: u8 = 0x02;
const TAG_KEEPALIVE: u8 = 0x03;
const TAG_CLOSE: u8 = 0x04;
const PAD_MARKER: u8 = 0x80;

/// Random 128-bit identifier of a text message, used for delivery receipts
/// and duplicate suppression.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; 16]);

impl MessageId {
    pub fn random() -> Result<Self> {
        crate::random::bytes().map(Self)
    }

    /// Short display form (first 8 hex digits).
    pub fn short(&self) -> String {
        self.0[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.short())
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

/// A message inside an encrypted session.
#[derive(Clone, PartialEq, Eq)]
pub enum WireMessage {
    /// A chat message.
    Text { id: MessageId, body: String },
    /// Acknowledges receipt of the text message with the given id.
    Receipt { id: MessageId },
    /// Liveness probe; carries no information.
    KeepAlive,
    /// Orderly shutdown of the session.
    Close,
}

impl fmt::Debug for WireMessage {
    // Never print message bodies, not even in debug output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text { id, body } => write!(f, "Text({id}, {} bytes)", body.len()),
            Self::Receipt { id } => write!(f, "Receipt({id})"),
            Self::KeepAlive => f.write_str("KeepAlive"),
            Self::Close => f.write_str("Close"),
        }
    }
}

/// Validate an outgoing text body.
pub fn validate_text(body: &str) -> Result<()> {
    if body.is_empty() {
        return Err(Error::InvalidMessage("empty message"));
    }
    if body.len() > MAX_TEXT_BYTES {
        return Err(Error::InvalidMessage("message too long (limit 8 KiB)"));
    }
    Ok(())
}

impl WireMessage {
    /// Encode and pad. The returned buffer is zeroized on drop.
    pub fn encode_padded(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::with_capacity(PADDING_BUCKETS[0]));
        match self {
            Self::Text { id, body } => {
                validate_text(body)?;
                out.push(TAG_TEXT);
                out.extend_from_slice(&id.0);
                out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                out.extend_from_slice(body.as_bytes());
            }
            Self::Receipt { id } => {
                out.push(TAG_RECEIPT);
                out.extend_from_slice(&id.0);
            }
            Self::KeepAlive => out.push(TAG_KEEPALIVE),
            Self::Close => out.push(TAG_CLOSE),
        }
        out.push(PAD_MARKER);
        let target = PADDING_BUCKETS
            .iter()
            .copied()
            .find(|&size| size >= out.len())
            .ok_or(Error::InvalidMessage("message too long"))?;
        out.resize(target, 0);
        Ok(out)
    }

    /// Strip padding and decode. Rejects anything that is not exactly the
    /// canonical encoding of a message padded to a valid bucket size.
    pub fn decode_padded(buf: &[u8]) -> Result<Self> {
        if !PADDING_BUCKETS.contains(&buf.len()) {
            return Err(Error::Protocol("invalid padded length"));
        }
        let marker = buf.iter().rposition(|&b| b != 0).ok_or(Error::Protocol("missing padding"))?;
        if buf[marker] != PAD_MARKER {
            return Err(Error::Protocol("bad padding"));
        }
        let content = &buf[..marker];
        // The bucket must be the smallest one that fits.
        let needed = content.len() + 1;
        if PADDING_BUCKETS.iter().copied().find(|&s| s >= needed) != Some(buf.len()) {
            return Err(Error::Protocol("non-canonical padding"));
        }
        let (&tag, rest) = content.split_first().ok_or(Error::Protocol("empty message"))?;
        match tag {
            TAG_TEXT => {
                if rest.len() < 18 {
                    return Err(Error::Protocol("truncated text message"));
                }
                let id = MessageId(rest[..16].try_into().map_err(|_| Error::Protocol("bad id"))?);
                let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
                let body = &rest[18..];
                if body.len() != len {
                    return Err(Error::Protocol("text length mismatch"));
                }
                let body = std::str::from_utf8(body).map_err(|_| Error::Protocol("text is not UTF-8"))?;
                validate_text(body).map_err(|_| Error::Protocol("invalid text"))?;
                Ok(Self::Text { id, body: body.to_owned() })
            }
            TAG_RECEIPT => {
                let id: [u8; 16] = rest.try_into().map_err(|_| Error::Protocol("bad receipt"))?;
                Ok(Self::Receipt { id: MessageId(id) })
            }
            TAG_KEEPALIVE if rest.is_empty() => Ok(Self::KeepAlive),
            TAG_CLOSE if rest.is_empty() => Ok(Self::Close),
            _ => Err(Error::Protocol("unknown message type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn id(n: u8) -> MessageId {
        MessageId([n; 16])
    }

    #[test]
    fn roundtrip_all_types() {
        for msg in [
            WireMessage::Text { id: id(1), body: "hallo 👋".into() },
            WireMessage::Receipt { id: id(2) },
            WireMessage::KeepAlive,
            WireMessage::Close,
        ] {
            let enc = msg.encode_padded().unwrap();
            assert_eq!(WireMessage::decode_padded(&enc).unwrap(), msg);
        }
    }

    #[test]
    fn small_messages_share_a_bucket() {
        let sizes: Vec<usize> = [
            WireMessage::Text { id: id(1), body: "ok".into() },
            WireMessage::Text { id: id(1), body: "x".repeat(200) },
            WireMessage::Receipt { id: id(2) },
            WireMessage::KeepAlive,
        ]
        .iter()
        .map(|m| m.encode_padded().unwrap().len())
        .collect();
        assert!(sizes.iter().all(|&s| s == PADDING_BUCKETS[0]), "{sizes:?}");
    }

    #[test]
    fn bucket_boundaries() {
        // 1 tag + 16 id + 2 len + body + 1 marker
        let fits = |n: usize| WireMessage::Text { id: id(0), body: "a".repeat(n) }.encode_padded().unwrap().len();
        assert_eq!(fits(256 - 20), 256);
        assert_eq!(fits(256 - 19), 1024);
        assert_eq!(fits(MAX_TEXT_BYTES), 16 * 1024);
        assert!(WireMessage::Text { id: id(0), body: "a".repeat(MAX_TEXT_BYTES + 1) }.encode_padded().is_err());
        assert!(WireMessage::Text { id: id(0), body: String::new() }.encode_padded().is_err());
    }

    #[test]
    fn rejects_malformed() {
        let good = WireMessage::KeepAlive.encode_padded().unwrap();
        // wrong length
        assert!(WireMessage::decode_padded(&good[..255]).is_err());
        // all zero
        assert!(WireMessage::decode_padded(&[0u8; 256]).is_err());
        // bad marker
        let mut bad = good.to_vec();
        bad[1] = 0x81;
        assert!(WireMessage::decode_padded(&bad).is_err());
        // trailing bytes after keepalive
        let mut bad = vec![0u8; 256];
        bad[0] = TAG_KEEPALIVE;
        bad[1] = 7;
        bad[2] = PAD_MARKER;
        assert!(WireMessage::decode_padded(&bad).is_err());
        // non-canonical bucket (keepalive padded to 1024)
        let mut bad = vec![0u8; 1024];
        bad[0] = TAG_KEEPALIVE;
        bad[1] = PAD_MARKER;
        assert!(WireMessage::decode_padded(&bad).is_err());
        // unknown tag
        let mut bad = vec![0u8; 256];
        bad[0] = 0x7f;
        bad[1] = PAD_MARKER;
        assert!(WireMessage::decode_padded(&bad).is_err());
    }

    #[test]
    fn debug_hides_body() {
        let msg = WireMessage::Text { id: id(1), body: "geheim".into() };
        assert!(!format!("{msg:?}").contains("geheim"));
    }

    proptest! {
        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = WireMessage::decode_padded(&data);
        }

        #[test]
        fn text_roundtrip(body in "\\PC{1,600}", raw_id in any::<[u8; 16]>()) {
            prop_assume!(body.len() <= MAX_TEXT_BYTES);
            let msg = WireMessage::Text { id: MessageId(raw_id), body };
            let enc = msg.encode_padded().unwrap();
            prop_assert!(PADDING_BUCKETS.contains(&enc.len()));
            prop_assert_eq!(WireMessage::decode_padded(&enc).unwrap(), msg);
        }
    }
}
