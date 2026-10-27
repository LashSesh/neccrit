//! Runs one established session: decrypts incoming frames, sends queued
//! messages, receipts and keepalives, and enforces timeouts and rate limits.
//!
//! Reading, writing and protocol logic run in separate tasks so that a peer
//! which is slow to read can never stop us from reading (two peers flushing
//! large queues at each other must not deadlock).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio::time::{Instant, timeout};

use crate::error::Result;
use crate::framing::{read_frame, write_frame};
use crate::handshake::{MAX_TRANSPORT_FRAME, SecureChannel};
use crate::wire::{MessageId, WireMessage};

pub(crate) trait Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for T {}

/// A type-erased byte stream (plain TCP or TCP through a SOCKS proxy).
pub(crate) type BoxStream = Box<dyn Stream>;

/// Commands from the node to a session.
#[derive(Debug)]
pub(crate) enum SessionCmd {
    Send(WireMessage),
    Close,
}

/// Reports from a session to the node.
#[derive(Debug)]
pub(crate) enum SessionReport {
    Text { id: MessageId, body: String },
    Receipt { id: MessageId },
    Closed,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionTiming {
    pub keepalive: Duration,
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
}

struct TokenBucket {
    capacity: f64,
    per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, per_sec: f64) -> Self {
        Self { capacity, per_sec, tokens: capacity, last: Instant::now() }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Inbound budgets of one contact, shared by all of its sessions so that
/// reconnecting does not refill them.
///
/// * frames: burst 512, 64/s – bounds decryption work;
/// * texts: burst 150 (enough to flush a full outbox of 100 after a
///   reconnect), 2/s sustained – far above human typing speed, and bounds how
///   fast a contact can grow the event queue if the user interface stalls.
pub(crate) struct RateLimits {
    frames: TokenBucket,
    texts: TokenBucket,
}

impl RateLimits {
    pub(crate) fn shared() -> SharedLimits {
        Arc::new(Mutex::new(Self { frames: TokenBucket::new(512.0, 64.0), texts: TokenBucket::new(150.0, 2.0) }))
    }
}

pub(crate) type SharedLimits = Arc<Mutex<RateLimits>>;

fn with_limits<R>(limits: &SharedLimits, f: impl FnOnce(&mut RateLimits) -> R) -> R {
    let mut guard = limits.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut guard)
}

/// Aborts a task when dropped, so helper tasks never outlive their session
/// (including when the session task itself is aborted).
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Encrypt and hand a message to the writer task. `false` means the
/// session is unusable.
fn queue(channel: &mut SecureChannel, out: &mpsc::UnboundedSender<Vec<u8>>, msg: &WireMessage) -> bool {
    channel.seal(msg).is_ok_and(|frame| out.send(frame).is_ok())
}

pub(crate) async fn run<F>(
    mut channel: SecureChannel,
    stream: BoxStream,
    mut commands: mpsc::UnboundedReceiver<SessionCmd>,
    timing: SessionTiming,
    limits: SharedLimits,
    report: F,
) where
    F: Fn(SessionReport),
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    let (frame_tx, mut frames) = mpsc::channel::<Result<Vec<u8>>>(16);
    let reader_task = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut reader, MAX_TRANSPORT_FRAME).await;
            let failed = frame.is_err();
            if frame_tx.send(frame).await.is_err() || failed {
                break;
            }
        }
    });
    let _reader_guard = AbortOnDrop(reader_task.abort_handle());

    // The outgoing queue holds at most the outbox flush, receipts for
    // rate-limited inbound texts and keepalives; a peer that stops reading
    // makes a write time out and ends the session.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let write_timeout = timing.write_timeout;
    let mut writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if !matches!(timeout(write_timeout, write_frame(&mut writer, &frame)).await, Ok(Ok(()))) {
                return;
            }
        }
        let _ = timeout(write_timeout, writer.shutdown()).await;
    });
    let _writer_guard = AbortOnDrop(writer_task.abort_handle());

    let mut keepalive = tokio::time::interval_at(Instant::now() + timing.keepalive, timing.keepalive);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = Instant::now() + timing.idle_timeout;
    let mut writer_done = false;

    loop {
        tokio::select! {
            frame = frames.recv() => {
                let Some(Ok(frame)) = frame else { break };
                deadline = Instant::now() + timing.idle_timeout;
                if !with_limits(&limits, |l| l.frames.take()) {
                    break;
                }
                match channel.open(&frame) {
                    Ok(WireMessage::Text { id, body }) => {
                        if !with_limits(&limits, |l| l.texts.take()) {
                            break;
                        }
                        if !queue(&mut channel, &out_tx, &WireMessage::Receipt { id }) {
                            break;
                        }
                        report(SessionReport::Text { id, body });
                    }
                    Ok(WireMessage::Receipt { id }) => report(SessionReport::Receipt { id }),
                    Ok(WireMessage::KeepAlive) => {}
                    Ok(WireMessage::Close) | Err(_) => break,
                }
            }
            cmd = commands.recv() => match cmd {
                Some(SessionCmd::Send(msg)) => {
                    if !queue(&mut channel, &out_tx, &msg) {
                        break;
                    }
                }
                Some(SessionCmd::Close) | None => {
                    queue(&mut channel, &out_tx, &WireMessage::Close);
                    break;
                }
            },
            _ = keepalive.tick() => {
                if !queue(&mut channel, &out_tx, &WireMessage::KeepAlive) {
                    break;
                }
            }
            () = tokio::time::sleep_until(deadline) => break,
            _ = &mut writer_task => {
                writer_done = true;
                break;
            }
        }
    }

    // Let the writer flush what is queued (e.g. the Close message), then shut
    // the connection down.
    drop(out_tx);
    if !writer_done {
        let _ = timeout(timing.write_timeout, &mut writer_task).await;
    }
    report(SessionReport::Closed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_limits_bursts() {
        let mut bucket = TokenBucket::new(3.0, 0.0);
        assert!(bucket.take() && bucket.take() && bucket.take());
        assert!(!bucket.take());
    }

    #[test]
    fn shared_limits_survive_reconnects() {
        let limits = RateLimits::shared();
        let first_session = limits.clone();
        for _ in 0..150 {
            assert!(with_limits(&first_session, |l| l.texts.take()));
        }
        // A new session of the same contact does not get a fresh budget.
        let second_session = limits.clone();
        assert!(!with_limits(&second_session, |l| l.texts.take()));
    }
}
