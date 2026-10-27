//! Runs one established session: decrypts incoming frames, sends queued
//! messages, receipts and keepalives, and enforces timeouts and rate limits.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

use crate::error::{Error, Result};
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

/// Inbound frame budget per session: generous for humans and for flushing
/// a full outbox after a reconnect, but bounds abuse by a misbehaving contact.
const RATE_BURST: f64 = 512.0;
const RATE_PER_SEC: f64 = 64.0;

struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new() -> Self {
        Self { tokens: RATE_BURST, last: Instant::now() }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * RATE_PER_SEC).min(RATE_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn send<W: AsyncWrite + Unpin>(
    channel: &mut SecureChannel,
    writer: &mut W,
    msg: &WireMessage,
    timing: SessionTiming,
) -> Result<()> {
    let frame = channel.seal(msg)?;
    timeout(timing.write_timeout, write_frame(writer, &frame)).await.map_err(|_| Error::Timeout)?
}

pub(crate) async fn run<F>(
    mut channel: SecureChannel,
    stream: BoxStream,
    mut commands: mpsc::UnboundedReceiver<SessionCmd>,
    timing: SessionTiming,
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

    let mut keepalive = tokio::time::interval_at(Instant::now() + timing.keepalive, timing.keepalive);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = Instant::now() + timing.idle_timeout;
    let mut budget = TokenBucket::new();

    loop {
        tokio::select! {
            frame = frames.recv() => {
                let Some(Ok(frame)) = frame else { break };
                deadline = Instant::now() + timing.idle_timeout;
                if !budget.take() {
                    break;
                }
                match channel.open(&frame) {
                    Ok(WireMessage::Text { id, body }) => {
                        if send(&mut channel, &mut writer, &WireMessage::Receipt { id }, timing).await.is_err() {
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
                    if send(&mut channel, &mut writer, &msg, timing).await.is_err() {
                        break;
                    }
                }
                Some(SessionCmd::Close) | None => {
                    let _ = send(&mut channel, &mut writer, &WireMessage::Close, timing).await;
                    break;
                }
            },
            _ = keepalive.tick() => {
                if send(&mut channel, &mut writer, &WireMessage::KeepAlive, timing).await.is_err() {
                    break;
                }
            }
            () = tokio::time::sleep_until(deadline) => break,
        }
    }

    reader_task.abort();
    let _ = timeout(timing.write_timeout, shutdown(&mut writer)).await;
    report(SessionReport::Closed);
}

async fn shutdown(writer: &mut WriteHalf<BoxStream>) -> std::io::Result<()> {
    writer.shutdown().await
}
