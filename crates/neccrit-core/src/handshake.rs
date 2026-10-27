//! Mutually authenticated, hybrid post-quantum key exchange.
//!
//! The handshake is the Noise pattern **`Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s`**
//! with an ephemeral **ML-KEM-768** encapsulation supplying the PSK:
//!
//! ```text
//!   (pre-message)   <- s                       initiator knows responder's static key
//!   msg 1  I -> R:  e, es        payload = ML-KEM-768 encapsulation key (1184 bytes)
//!   msg 2  R -> I:  e, ee        payload = ML-KEM-768 ciphertext        (1088 bytes)
//!   msg 3  I -> R:  s, se, psk   payload = empty;  psk = ML-KEM shared secret
//! ```
//!
//! Properties (see `docs/PROTOCOL.md` for the full discussion):
//!
//! * Both sides are authenticated by their long-term X25519 keys. The
//!   initiator must already know the responder's key (from the invite), and
//!   the responder only accepts initiators whose key is in its contact list.
//! * Session keys depend on X25519 **and** ML-KEM. Recorded traffic stays
//!   confidential against a future quantum computer as long as ML-KEM holds
//!   ("harvest now, decrypt later"), and against classical attackers as long
//!   as either primitive holds. Authentication itself is classical.
//! * Forward secrecy: all ephemeral keys are discarded after the handshake.
//! * Identity hiding: the responder's static key never appears on the wire;
//!   the initiator's static key is sent encrypted with forward secrecy.
//! * Probing resistance: a responder only answers clients that already know
//!   its public key; everyone else gets the connection closed without a
//!   single byte of response.
//! * Key confirmation: after accepting the initiator, the responder sends one
//!   transport message (a keepalive). The initiator only considers the
//!   session established once it decrypted it, so a rejected initiator never
//!   believes it is connected.

use libcrux_ml_kem::mlkem768;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::framing::{read_frame, write_frame};
use crate::identity::{Identity, PublicKey};
use crate::random;
use crate::wire::{MAX_PADDED_LEN, WireMessage};

/// Noise protocol name.
pub const NOISE_PARAMS: &str = "Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s";

/// Bound into the handshake transcript; a peer speaking any other protocol
/// version fails the handshake instead of being misinterpreted.
pub const PROLOGUE: &[u8] = b"neccrit/1 Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s+ML-KEM-768";

const PSK_SLOT: usize = 3;
const NOISE_TAG_LEN: usize = 16;
const DH_LEN: usize = 32;
const MLKEM_PK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;

const MSG1_LEN: usize = DH_LEN + MLKEM_PK_LEN + NOISE_TAG_LEN;
const MSG2_LEN: usize = DH_LEN + MLKEM_CT_LEN + NOISE_TAG_LEN;
const MSG3_LEN: usize = DH_LEN + NOISE_TAG_LEN + NOISE_TAG_LEN;

/// Largest ciphertext frame accepted once the session is established.
pub(crate) const MAX_TRANSPORT_FRAME: usize = MAX_PADDED_LEN + NOISE_TAG_LEN;

fn builder() -> Result<snow::Builder<'static>> {
    let params = NOISE_PARAMS.parse().map_err(|_| Error::Handshake)?;
    snow::Builder::new(params).prologue(PROLOGUE).map_err(Error::from)
}

/// An established, authenticated and encrypted session with a contact.
pub struct SecureChannel {
    transport: snow::TransportState,
    remote: PublicKey,
    initiator: bool,
    handshake_hash: [u8; 32],
}

impl std::fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureChannel")
            .field("remote", &self.remote)
            .field("initiator", &self.initiator)
            .finish_non_exhaustive()
    }
}

impl SecureChannel {
    /// The authenticated long-term key of the peer.
    pub fn remote(&self) -> &PublicKey {
        &self.remote
    }

    /// Whether the local side initiated this session.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Noise handshake hash: a unique, secret-independent identifier of this
    /// session that both sides agree on.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Pad and encrypt a message; returns the ciphertext frame body.
    ///
    /// The sending key is replaced by a one-way function of itself after
    /// every message (Noise `Rekey`), so a later compromise of the session
    /// state does not expose earlier messages of the same session.
    pub fn seal(&mut self, msg: &WireMessage) -> Result<Vec<u8>> {
        let plain = msg.encode_padded()?;
        let mut out = vec![0u8; plain.len() + NOISE_TAG_LEN];
        let n = self.transport.write_message(&plain, &mut out).map_err(|_| Error::Crypto)?;
        self.transport.rekey_outgoing();
        out.truncate(n);
        Ok(out)
    }

    /// Decrypt and decode a ciphertext frame body. Any failure is fatal for
    /// the session: Noise transport messages must arrive exactly once and in
    /// order. The receiving key is ratcheted forward like the sending key.
    pub fn open(&mut self, frame: &[u8]) -> Result<WireMessage> {
        if frame.len() > MAX_TRANSPORT_FRAME || frame.len() < NOISE_TAG_LEN {
            return Err(Error::Protocol("invalid ciphertext length"));
        }
        let mut plain = Zeroizing::new(vec![0u8; frame.len()]);
        let n = self.transport.read_message(frame, &mut plain).map_err(|_| Error::Crypto)?;
        self.transport.rekey_incoming();
        WireMessage::decode_padded(&plain[..n])
    }
}

/// Run the initiator side of the handshake over `stream`, expecting the
/// responder to hold the private key for `remote`.
pub async fn initiate<S>(stream: &mut S, identity: &Identity, remote: &PublicKey) -> Result<SecureChannel>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut hs = builder()?
        .local_private_key(identity.secret_bytes())?
        .remote_public_key(remote.as_bytes())?
        .build_initiator()?;

    let mut seed = Zeroizing::new(random::bytes::<64>()?);
    let kem = mlkem768::generate_key_pair(*seed);
    seed.zeroize();

    let mut buf = vec![0u8; MSG1_LEN];
    let n = hs.write_message(kem.public_key().as_slice(), &mut buf)?;
    write_frame(stream, &buf[..n]).await?;

    let msg2 = read_frame(stream, MSG2_LEN).await?;
    let mut payload = vec![0u8; msg2.len()];
    let n = hs.read_message(&msg2, &mut payload)?;
    if n != MLKEM_CT_LEN {
        return Err(Error::Handshake);
    }
    let ct = mlkem768::MlKem768Ciphertext::try_from(&payload[..n]).map_err(|_| Error::Handshake)?;
    // Note: libcrux key types do not zeroize themselves; the ephemeral KEM
    // key pair lives only for the duration of this function.
    let shared = Zeroizing::new(mlkem768::decapsulate(kem.private_key(), &ct));
    hs.set_psk(PSK_SLOT, shared.as_ref())?;

    let mut buf = vec![0u8; MSG3_LEN];
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(stream, &buf[..n]).await?;

    let mut channel = finish(hs, *remote, true)?;
    let confirmation = read_frame(stream, MAX_TRANSPORT_FRAME).await?;
    match channel.open(&confirmation) {
        Ok(WireMessage::KeepAlive) => Ok(channel),
        _ => Err(Error::Handshake),
    }
}

/// Run the responder side of the handshake. `is_allowed` is consulted with
/// the initiator's authenticated static key before the session is accepted.
pub async fn respond<S, F>(stream: &mut S, identity: &Identity, is_allowed: F) -> Result<SecureChannel>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    F: FnOnce(&PublicKey) -> bool,
{
    let mut hs = builder()?.local_private_key(identity.secret_bytes())?.build_responder()?;

    // Message 1 only decrypts if the initiator used our real static key.
    let msg1 = read_frame(stream, MSG1_LEN).await?;
    let mut payload = vec![0u8; msg1.len()];
    let n = hs.read_message(&msg1, &mut payload)?;
    if n != MLKEM_PK_LEN {
        return Err(Error::Handshake);
    }
    let ek = mlkem768::MlKem768PublicKey::try_from(&payload[..n]).map_err(|_| Error::Handshake)?;
    // FIPS 203 input validation of the encapsulation key.
    if !mlkem768::validate_public_key(&ek) {
        return Err(Error::Handshake);
    }
    let mut coins = Zeroizing::new(random::bytes::<32>()?);
    let (ct, shared) = mlkem768::encapsulate(&ek, *coins);
    coins.zeroize();
    let shared = Zeroizing::new(shared);
    hs.set_psk(PSK_SLOT, shared.as_ref())?;

    let mut buf = vec![0u8; MSG2_LEN];
    let n = hs.write_message(ct.as_slice(), &mut buf)?;
    write_frame(stream, &buf[..n]).await?;

    let msg3 = read_frame(stream, MSG3_LEN).await?;
    let mut payload = vec![0u8; msg3.len()];
    let n = hs.read_message(&msg3, &mut payload)?;
    if n != 0 {
        return Err(Error::Handshake);
    }
    let remote = PublicKey::from_slice(hs.get_remote_static().ok_or(Error::Handshake)?)?;
    if !is_allowed(&remote) {
        return Err(Error::UnknownPeer(remote));
    }
    let mut channel = finish(hs, remote, false)?;
    let confirmation = channel.seal(&WireMessage::KeepAlive)?;
    write_frame(stream, &confirmation).await?;
    Ok(channel)
}

fn finish(hs: snow::HandshakeState, remote: PublicKey, initiator: bool) -> Result<SecureChannel> {
    if !hs.is_handshake_finished() {
        return Err(Error::Handshake);
    }
    let handshake_hash: [u8; 32] = hs.get_handshake_hash().try_into().map_err(|_| Error::Handshake)?;
    let transport = hs.into_transport_mode()?;
    Ok(SecureChannel { transport, remote, initiator, handshake_hash })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::MessageId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair(
        initiator: &Identity,
        expected_remote: &PublicKey,
        responder: &Identity,
        allowed: Option<PublicKey>,
    ) -> (Result<SecureChannel>, Result<SecureChannel>) {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let i = async {
            let r = initiate(&mut a, initiator, expected_remote).await;
            drop(a);
            r
        };
        let r = async {
            let r = respond(&mut b, responder, |k| Some(*k) == allowed).await;
            drop(b);
            r
        };
        tokio::join!(i, r)
    }

    #[tokio::test]
    async fn handshake_and_transport() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (a, b) = pair(&alice, bob.public_key(), &bob, Some(*alice.public_key())).await;
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.remote(), bob.public_key());
        assert_eq!(b.remote(), alice.public_key());
        assert_eq!(a.handshake_hash(), b.handshake_hash());
        assert!(a.is_initiator() && !b.is_initiator());

        let msg = WireMessage::Text { id: MessageId([7; 16]), body: "hi bob".into() };
        let ct = a.seal(&msg).unwrap();
        assert_eq!(ct.len(), 256 + 16);
        assert_eq!(b.open(&ct).unwrap(), msg);

        let reply = WireMessage::Receipt { id: MessageId([7; 16]) };
        let ct = b.seal(&reply).unwrap();
        assert_eq!(a.open(&ct).unwrap(), reply);

        // Per-message rekeying stays in sync over many messages, and the
        // same plaintext never produces the same ciphertext.
        let mut previous = Vec::new();
        for i in 0..200u8 {
            let msg = WireMessage::Text { id: MessageId([i; 16]), body: "same".into() };
            let ct = a.seal(&msg).unwrap();
            assert_ne!(ct, previous);
            assert_eq!(b.open(&ct).unwrap(), msg);
            previous = ct;
        }
    }

    #[tokio::test]
    async fn sessions_have_fresh_keys() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (a1, _) = pair(&alice, bob.public_key(), &bob, Some(*alice.public_key())).await;
        let (a2, _) = pair(&alice, bob.public_key(), &bob, Some(*alice.public_key())).await;
        assert_ne!(a1.unwrap().handshake_hash(), a2.unwrap().handshake_hash());
    }

    #[tokio::test]
    async fn wrong_responder_key_fails() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        // Alice believes she talks to Bob, but Mallory answers.
        let (a, m) = pair(&alice, bob.public_key(), &mallory, Some(*alice.public_key())).await;
        assert!(a.is_err());
        assert!(m.is_err());
    }

    #[tokio::test]
    async fn unknown_initiator_rejected() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (_, b) = pair(&alice, bob.public_key(), &bob, None).await;
        match b {
            Err(Error::UnknownPeer(k)) => assert_eq!(k, *alice.public_key()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn prober_gets_no_response() {
        // Someone who does not know Bob's public key cannot make him answer.
        let bob = Identity::generate().unwrap();
        let (mut probe, mut b) = tokio::io::duplex(1 << 16);
        let resp = tokio::spawn(async move { respond(&mut b, &bob, |_| true).await });
        let junk = vec![0x42u8; MSG1_LEN];
        probe.write_all(&(junk.len() as u16).to_be_bytes()).await.unwrap();
        probe.write_all(&junk).await.unwrap();
        assert!(resp.await.unwrap().is_err());
        let mut rest = Vec::new();
        probe.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "responder must not send anything to a prober");
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (a, b) = pair(&alice, bob.public_key(), &bob, Some(*alice.public_key())).await;
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        let mut ct = a.seal(&WireMessage::KeepAlive).unwrap();
        ct[10] ^= 1;
        assert!(b.open(&ct).is_err());
    }

    #[tokio::test]
    async fn replay_and_reordering_are_rejected() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (a, b) = pair(&alice, bob.public_key(), &bob, Some(*alice.public_key())).await;
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        let first = a.seal(&WireMessage::KeepAlive).unwrap();
        let second = a.seal(&WireMessage::KeepAlive).unwrap();
        assert!(b.open(&second).is_err(), "out-of-order message accepted");

        let (a, b) = pair(&alice, bob.public_key(), &bob, Some(*alice.public_key())).await;
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        let ct = a.seal(&WireMessage::KeepAlive).unwrap();
        b.open(&ct).unwrap();
        assert!(b.open(&ct).is_err(), "replayed message accepted");
        drop(first);
    }

    #[tokio::test]
    async fn kem_secret_is_bound_into_session() {
        // Run a handshake where the responder mixes a PSK that differs from the
        // ML-KEM secret: it must fail. This guards against the KEM output
        // silently not being used.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let bob_key = *bob.public_key();
        let responder = tokio::spawn(async move {
            let mut hs = builder().unwrap().local_private_key(bob.secret_bytes()).unwrap().build_responder().unwrap();
            let msg1 = read_frame(&mut b, MSG1_LEN).await.unwrap();
            let mut p = vec![0u8; msg1.len()];
            let n = hs.read_message(&msg1, &mut p).unwrap();
            let ek = mlkem768::MlKem768PublicKey::try_from(&p[..n]).unwrap();
            let (ct, _shared) = mlkem768::encapsulate(&ek, [9u8; 32]);
            hs.set_psk(PSK_SLOT, &[0u8; 32]).unwrap();
            let mut buf = vec![0u8; MSG2_LEN];
            let n = hs.write_message(ct.as_slice(), &mut buf).unwrap();
            write_frame(&mut b, &buf[..n]).await.unwrap();
            let msg3 = read_frame(&mut b, MSG3_LEN).await.unwrap();
            let mut p = vec![0u8; msg3.len()];
            hs.read_message(&msg3, &mut p).map(|_| ())
        });
        let _ = initiate(&mut a, &alice, &bob_key).await;
        assert!(responder.await.unwrap().is_err());
    }
}
