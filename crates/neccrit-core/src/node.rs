//! The networking runtime: accepts and dials sessions, queues outgoing
//! messages until they are acknowledged, suppresses duplicates and reports
//! [`Event`]s to the user interface.
//!
//! Internally a single actor task owns all mutable state; listener, dialer
//! and session tasks talk to it over channels.
//!
//! Delivery semantics: messages are kept **in memory** until the recipient
//! acknowledges them and are re-sent on every new session, so delivery is
//! at-least-once and the receiver drops duplicates by message id. Nothing is
//! persisted: undelivered messages are lost when the node stops.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::address::PeerAddress;
use crate::error::{Error, Result};
use crate::handshake::{self, SecureChannel};
use crate::identity::{Identity, PublicKey};
use crate::random;
use crate::session::{self, BoxStream, SessionCmd, SessionReport, SessionTiming};
use crate::wire::{MessageId, WireMessage, validate_text};

/// Maximum number of unacknowledged messages per contact.
pub const MAX_OUTBOX: usize = 100;
const MAX_PENDING_HANDSHAKES: usize = 32;
const RECENT_IDS: usize = 4096;
const MAX_UNKNOWN_PEER_REPORTS: usize = 64;

/// Runtime configuration of a [`Node`].
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Where to accept connections. `None` disables listening.
    pub listen: Option<SocketAddr>,
    /// If set, every outgoing connection goes through this SOCKS5 proxy
    /// (normally Tor). There is no fallback to direct connections.
    pub socks5_proxy: Option<SocketAddr>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub keepalive_interval: Duration,
    pub idle_timeout: Duration,
    pub max_retry_delay: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: None,
            socks5_proxy: None,
            // Generous: building a circuit to an onion service can be slow.
            connect_timeout: Duration::from_secs(90),
            handshake_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(25),
            idle_timeout: Duration::from_secs(80),
            max_retry_delay: Duration::from_secs(60),
        }
    }
}

/// A contact as far as networking is concerned.
#[derive(Clone, Debug)]
pub struct ContactRef {
    pub public_key: PublicKey,
    pub address: Option<PeerAddress>,
}

/// Something the user interface should know about.
#[derive(Clone, PartialEq, Eq)]
pub enum Event {
    Listening {
        addr: SocketAddr,
    },
    Connected {
        contact: PublicKey,
    },
    Disconnected {
        contact: PublicKey,
    },
    Message {
        contact: PublicKey,
        id: MessageId,
        text: String,
    },
    Delivered {
        contact: PublicKey,
        id: MessageId,
    },
    ConnectFailed {
        contact: PublicKey,
        error: String,
        retry_in: Option<Duration>,
    },
    /// A peer that knows our public key and address completed a handshake
    /// but is not a contact. Reported at most once per key.
    UnknownPeer {
        public_key: PublicKey,
    },
}

impl fmt::Debug for Event {
    // Message bodies never appear in debug output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listening { addr } => write!(f, "Listening({addr})"),
            Self::Connected { contact } => write!(f, "Connected({contact})"),
            Self::Disconnected { contact } => write!(f, "Disconnected({contact})"),
            Self::Message { contact, id, text } => write!(f, "Message({contact}, {id}, {} bytes)", text.len()),
            Self::Delivered { contact, id } => write!(f, "Delivered({contact}, {id})"),
            Self::ConnectFailed { contact, error, retry_in } => {
                write!(f, "ConnectFailed({contact}, {error}, retry {retry_in:?})")
            }
            Self::UnknownPeer { public_key } => write!(f, "UnknownPeer({public_key})"),
        }
    }
}

/// Entry point; see [`Node::start`].
#[derive(Debug)]
pub struct Node;

impl Node {
    /// Start listening (if configured) and return a handle plus the event
    /// stream. `contacts` is the complete allow-list of peers.
    pub async fn start(
        identity: Identity,
        contacts: Vec<ContactRef>,
        config: NodeConfig,
    ) -> Result<(NodeHandle, mpsc::UnboundedReceiver<Event>)> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (internal_tx, internal_rx) = mpsc::unbounded_channel();

        let allowed: HashSet<PublicKey> = contacts.iter().map(|c| c.public_key).collect();
        let shared = Arc::new(Shared { identity, config, allowed });

        let listener = match shared.config.listen {
            Some(addr) => {
                let listener = TcpListener::bind(addr).await?;
                let local = listener.local_addr()?;
                let _ = event_tx.send(Event::Listening { addr: local });
                Some(tokio::spawn(accept_loop(listener, shared.clone(), internal_tx.clone())))
            }
            None => None,
        };

        let mut states = HashMap::new();
        for c in contacts {
            states.insert(c.public_key, ContactState::new(c.address)?);
        }

        let actor = Actor {
            shared,
            contacts: states,
            events: event_tx,
            internal_tx,
            next_session_id: 1,
            listener,
            session_tasks: Vec::new(),
            reported_unknown: HashSet::new(),
        };
        tokio::spawn(actor.run(cmd_rx, internal_rx));
        Ok((NodeHandle { tx: cmd_tx }, event_rx))
    }
}

/// Cheap, cloneable handle to control a running node.
#[derive(Clone, Debug)]
pub struct NodeHandle {
    tx: mpsc::UnboundedSender<Command>,
}

impl NodeHandle {
    /// Queue a text message. It is sent immediately if a session exists and
    /// otherwise as soon as one can be established.
    pub async fn send_text(&self, contact: PublicKey, text: String) -> Result<MessageId> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(Command::SendText { contact, text, reply }).map_err(|_| Error::NodeStopped)?;
        rx.await.map_err(|_| Error::NodeStopped)?
    }

    /// Keep trying to connect to `contact` (with backoff) until a session
    /// exists, even without pending messages.
    pub fn connect(&self, contact: PublicKey) -> Result<()> {
        self.tx.send(Command::Connect { contact }).map_err(|_| Error::NodeStopped)
    }

    /// Number of messages to `contact` that have not been acknowledged.
    pub async fn pending(&self, contact: PublicKey) -> Result<usize> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(Command::Pending { contact, reply }).map_err(|_| Error::NodeStopped)?;
        rx.await.map_err(|_| Error::NodeStopped)?
    }

    /// Whether a session with `contact` is currently established.
    pub async fn is_connected(&self, contact: PublicKey) -> Result<bool> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(Command::IsConnected { contact, reply }).map_err(|_| Error::NodeStopped)?;
        rx.await.map_err(|_| Error::NodeStopped)?
    }

    /// Close all sessions (sending an orderly close) and stop the node.
    pub async fn shutdown(&self) {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::Shutdown { reply }).is_ok() {
            let _ = rx.await;
        }
    }
}

enum Command {
    SendText { contact: PublicKey, text: String, reply: oneshot::Sender<Result<MessageId>> },
    Connect { contact: PublicKey },
    Pending { contact: PublicKey, reply: oneshot::Sender<Result<usize>> },
    IsConnected { contact: PublicKey, reply: oneshot::Sender<Result<bool>> },
    Shutdown { reply: oneshot::Sender<()> },
}

enum Internal {
    Established { channel: SecureChannel, stream: BoxStream, dialed: Option<PublicKey> },
    DialFailed { contact: PublicKey, error: String },
    Retry { contact: PublicKey },
    Session { contact: PublicKey, session_id: u64, report: SessionReport },
    UnknownPeer(PublicKey),
}

struct Shared {
    identity: Identity,
    config: NodeConfig,
    allowed: HashSet<PublicKey>,
}

struct ActiveSession {
    id: u64,
    /// Long-term key of the side that initiated the session.
    initiator: PublicKey,
    tx: mpsc::UnboundedSender<SessionCmd>,
}

struct ContactState {
    address: Option<PeerAddress>,
    session: Option<ActiveSession>,
    outbox: VecDeque<(MessageId, String)>,
    recent: RecentIds,
    dialing: bool,
    retry_scheduled: bool,
    retry_attempt: u32,
    want_connection: bool,
    /// SOCKS credentials used for Tor stream isolation (one circuit per
    /// contact, unlinkable across contacts).
    isolation: String,
}

impl ContactState {
    fn new(address: Option<PeerAddress>) -> Result<Self> {
        let token = random::bytes::<16>()?;
        Ok(Self {
            address,
            session: None,
            outbox: VecDeque::new(),
            recent: RecentIds::default(),
            dialing: false,
            retry_scheduled: false,
            retry_attempt: 0,
            want_connection: false,
            isolation: token.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }

    fn needs_connection(&self) -> bool {
        self.session.is_none() && (self.want_connection || !self.outbox.is_empty())
    }
}

/// Bounded set of recently seen message ids.
#[derive(Default)]
struct RecentIds {
    order: VecDeque<MessageId>,
    set: HashSet<MessageId>,
}

impl RecentIds {
    /// Returns `true` if the id was not seen before.
    fn insert(&mut self, id: MessageId) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > RECENT_IDS
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }
}

struct Actor {
    shared: Arc<Shared>,
    contacts: HashMap<PublicKey, ContactState>,
    events: mpsc::UnboundedSender<Event>,
    internal_tx: mpsc::UnboundedSender<Internal>,
    next_session_id: u64,
    listener: Option<JoinHandle<()>>,
    session_tasks: Vec<JoinHandle<()>>,
    reported_unknown: HashSet<PublicKey>,
}

impl Actor {
    async fn run(
        mut self,
        mut commands: mpsc::UnboundedReceiver<Command>,
        mut internal: mpsc::UnboundedReceiver<Internal>,
    ) {
        loop {
            tokio::select! {
                cmd = commands.recv() => match cmd {
                    Some(Command::Shutdown { reply }) => {
                        self.shutdown().await;
                        let _ = reply.send(());
                        return;
                    }
                    Some(cmd) => self.on_command(cmd),
                    None => {
                        self.shutdown().await;
                        return;
                    }
                },
                Some(msg) = internal.recv() => self.on_internal(msg),
            }
        }
    }

    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    fn on_command(&mut self, cmd: Command) {
        match cmd {
            Command::SendText { contact, text, reply } => {
                let _ = reply.send(self.send_text(contact, text));
            }
            Command::Connect { contact } => {
                if let Some(c) = self.contacts.get_mut(&contact) {
                    c.want_connection = true;
                    self.ensure_dial(contact);
                }
            }
            Command::Pending { contact, reply } => {
                let _ = reply.send(self.contacts.get(&contact).map(|c| c.outbox.len()).ok_or(Error::UnknownContact));
            }
            Command::IsConnected { contact, reply } => {
                let _ =
                    reply.send(self.contacts.get(&contact).map(|c| c.session.is_some()).ok_or(Error::UnknownContact));
            }
            Command::Shutdown { .. } => {}
        }
    }

    fn send_text(&mut self, contact: PublicKey, text: String) -> Result<MessageId> {
        validate_text(&text)?;
        let c = self.contacts.get_mut(&contact).ok_or(Error::UnknownContact)?;
        if c.outbox.len() >= MAX_OUTBOX {
            return Err(Error::OutboxFull);
        }
        let id = MessageId::random()?;
        c.outbox.push_back((id, text.clone()));
        match &c.session {
            Some(s) => {
                let _ = s.tx.send(SessionCmd::Send(WireMessage::Text { id, body: text }));
            }
            None => self.ensure_dial(contact),
        }
        Ok(id)
    }

    fn ensure_dial(&mut self, contact: PublicKey) {
        let Some(c) = self.contacts.get_mut(&contact) else { return };
        if c.session.is_some() || c.dialing || c.retry_scheduled {
            return;
        }
        // Without an address we can only wait for the contact to call us.
        let Some(address) = c.address.clone() else { return };
        c.dialing = true;
        let shared = self.shared.clone();
        let internal = self.internal_tx.clone();
        let isolation = c.isolation.clone();
        tokio::spawn(async move {
            let msg = match dial(&shared, contact, &address, &isolation).await {
                Ok((channel, stream)) => Internal::Established { channel, stream, dialed: Some(contact) },
                Err(err) => Internal::DialFailed { contact, error: err.to_string() },
            };
            let _ = internal.send(msg);
        });
    }

    fn schedule_retry(&mut self, contact: PublicKey) -> Option<Duration> {
        let max = self.shared.config.max_retry_delay;
        let c = self.contacts.get_mut(&contact)?;
        if !c.needs_connection() || c.retry_scheduled || c.address.is_none() {
            return None;
        }
        let base = Duration::from_secs(1u64 << c.retry_attempt.min(6)).min(max);
        let delay = base + Duration::from_millis(random::jitter_ms(1000));
        c.retry_attempt = c.retry_attempt.saturating_add(1);
        c.retry_scheduled = true;
        let internal = self.internal_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = internal.send(Internal::Retry { contact });
        });
        Some(delay)
    }

    fn on_internal(&mut self, msg: Internal) {
        match msg {
            Internal::Established { channel, stream, dialed } => self.on_established(channel, stream, dialed),
            Internal::DialFailed { contact, error } => {
                if let Some(c) = self.contacts.get_mut(&contact) {
                    c.dialing = false;
                }
                let retry_in = self.schedule_retry(contact);
                self.emit(Event::ConnectFailed { contact, error, retry_in });
            }
            Internal::Retry { contact } => {
                if let Some(c) = self.contacts.get_mut(&contact) {
                    c.retry_scheduled = false;
                    if c.needs_connection() {
                        self.ensure_dial(contact);
                    }
                }
            }
            Internal::Session { contact, session_id, report } => self.on_session_report(contact, session_id, report),
            Internal::UnknownPeer(key) => {
                if self.reported_unknown.len() < MAX_UNKNOWN_PEER_REPORTS && self.reported_unknown.insert(key) {
                    self.emit(Event::UnknownPeer { public_key: key });
                }
            }
        }
    }

    fn on_established(&mut self, channel: SecureChannel, stream: BoxStream, dialed: Option<PublicKey>) {
        let remote = *channel.remote();
        let own = *self.shared.identity.public_key();
        let initiator = if channel.is_initiator() { own } else { remote };
        if let Some(d) = dialed.and_then(|d| self.contacts.get_mut(&d)) {
            d.dialing = false;
        }
        let Some(c) = self.contacts.get_mut(&remote) else { return };

        // If both sides dialed at the same time there are two sessions. Both
        // peers keep the one initiated by the numerically smaller key, so
        // they converge on the same session. A newer session in the same
        // direction replaces the old one (the peer reconnected).
        let keep_new = match &c.session {
            None => true,
            Some(existing) => existing.initiator == initiator || initiator < existing.initiator,
        };
        if !keep_new {
            return; // dropping `stream` closes the connection
        }
        let was_connected = c.session.is_some();
        if let Some(old) = c.session.take() {
            let _ = old.tx.send(SessionCmd::Close);
        }

        let session_id = self.next_session_id;
        self.next_session_id += 1;
        let (tx, rx) = mpsc::unbounded_channel();
        // Re-send everything that has not been acknowledged yet.
        for (id, text) in &c.outbox {
            let _ = tx.send(SessionCmd::Send(WireMessage::Text { id: *id, body: text.clone() }));
        }
        c.session = Some(ActiveSession { id: session_id, initiator, tx });
        c.retry_attempt = 0;

        let cfg = &self.shared.config;
        let timing = SessionTiming {
            keepalive: cfg.keepalive_interval,
            idle_timeout: cfg.idle_timeout,
            write_timeout: cfg.handshake_timeout,
        };
        let internal = self.internal_tx.clone();
        let task = tokio::spawn(session::run(channel, stream, rx, timing, move |report| {
            let _ = internal.send(Internal::Session { contact: remote, session_id, report });
        }));
        self.session_tasks.retain(|t| !t.is_finished());
        self.session_tasks.push(task);
        if !was_connected {
            self.emit(Event::Connected { contact: remote });
        }
    }

    fn on_session_report(&mut self, contact: PublicKey, session_id: u64, report: SessionReport) {
        let Some(c) = self.contacts.get_mut(&contact) else { return };
        match report {
            SessionReport::Text { id, body } => {
                if c.recent.insert(id) {
                    self.emit(Event::Message { contact, id, text: body });
                }
            }
            SessionReport::Receipt { id } => {
                if let Some(pos) = c.outbox.iter().position(|(pending, _)| *pending == id) {
                    c.outbox.remove(pos);
                    self.emit(Event::Delivered { contact, id });
                }
            }
            SessionReport::Closed => {
                if c.session.as_ref().is_some_and(|s| s.id == session_id) {
                    c.session = None;
                    self.emit(Event::Disconnected { contact });
                    self.schedule_retry(contact);
                }
            }
        }
    }

    async fn shutdown(&mut self) {
        if let Some(listener) = self.listener.take() {
            listener.abort();
        }
        for c in self.contacts.values_mut() {
            if let Some(s) = c.session.take() {
                let _ = s.tx.send(SessionCmd::Close);
            }
        }
        let tasks = std::mem::take(&mut self.session_tasks);
        let _ = timeout(Duration::from_secs(3), async {
            for t in tasks {
                let _ = t.await;
            }
        })
        .await;
    }
}

async fn dial(
    shared: &Shared,
    contact: PublicKey,
    address: &PeerAddress,
    isolation: &str,
) -> Result<(SecureChannel, BoxStream)> {
    let cfg = &shared.config;
    let host = address.host();
    let mut stream: BoxStream = match cfg.socks5_proxy {
        Some(proxy) => {
            let connect = tokio_socks::tcp::Socks5Stream::connect_with_password(
                proxy,
                (host.as_str(), address.port()),
                "neccrit",
                isolation,
            );
            let stream = timeout(cfg.connect_timeout, connect)
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|e| Error::Proxy(e.to_string()))?;
            Box::new(stream)
        }
        None => {
            if address.is_onion() {
                return Err(Error::Proxy(
                    "onion addresses can only be reached through Tor (set a SOCKS5 proxy)".into(),
                ));
            }
            let stream = timeout(cfg.connect_timeout, TcpStream::connect((host.as_str(), address.port())))
                .await
                .map_err(|_| Error::Timeout)??;
            let _ = stream.set_nodelay(true);
            Box::new(stream)
        }
    };
    let channel = timeout(cfg.handshake_timeout, handshake::initiate(&mut stream, &shared.identity, &contact))
        .await
        .map_err(|_| Error::Timeout)??;
    Ok((channel, stream))
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>, internal: mpsc::UnboundedSender<Internal>) {
    let permits = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        // Peer IP addresses are deliberately neither logged nor reported.
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue; // overloaded: drop the connection
        };
        let shared = shared.clone();
        let internal = internal.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            let mut stream: BoxStream = Box::new(stream);
            let allowed = |key: &PublicKey| shared.allowed.contains(key);
            let result =
                timeout(shared.config.handshake_timeout, handshake::respond(&mut stream, &shared.identity, allowed))
                    .await;
            match result {
                Ok(Ok(channel)) => {
                    let _ = internal.send(Internal::Established { channel, stream, dialed: None });
                }
                Ok(Err(Error::UnknownPeer(key))) => {
                    let _ = internal.send(Internal::UnknownPeer(key));
                }
                // Probes, garbage and timeouts are dropped silently.
                _ => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_ids_bounded() {
        let mut r = RecentIds::default();
        assert!(r.insert(MessageId([0; 16])));
        assert!(!r.insert(MessageId([0; 16])));
        for i in 0..RECENT_IDS as u32 + 10 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id[15] = 1;
            r.insert(MessageId(id));
        }
        assert_eq!(r.order.len(), RECENT_IDS);
        assert_eq!(r.set.len(), RECENT_IDS);
    }
}
