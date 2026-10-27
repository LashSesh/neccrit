#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end tests of the networking node over real TCP sockets on
//! localhost.

use std::net::SocketAddr;
use std::time::Duration;

use neccrit_core::{ContactRef, Event, Identity, Node, NodeConfig, NodeHandle, PeerAddress, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(20);

fn config(listen: Option<SocketAddr>) -> NodeConfig {
    NodeConfig {
        listen,
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(5),
        max_retry_delay: Duration::from_secs(1),
        ..NodeConfig::default()
    }
}

fn localhost() -> Option<SocketAddr> {
    Some("127.0.0.1:0".parse().unwrap())
}

fn addr(socket: SocketAddr) -> Option<PeerAddress> {
    Some(socket.to_string().parse().unwrap())
}

async fn free_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// Wait for the first event matching `pred`, skipping others.
async fn expect<F: Fn(&Event) -> bool>(events: &mut UnboundedReceiver<Event>, what: &str, pred: F) -> Event {
    timeout(WAIT, async {
        loop {
            let ev = events.recv().await.unwrap_or_else(|| panic!("event stream ended waiting for {what}"));
            if pred(&ev) {
                return ev;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

async fn listening(events: &mut UnboundedReceiver<Event>) -> SocketAddr {
    match expect(events, "listening", |e| matches!(e, Event::Listening { .. })).await {
        Event::Listening { addr } => addr,
        _ => unreachable!(),
    }
}

struct Peer {
    key: PublicKey,
    handle: NodeHandle,
    events: UnboundedReceiver<Event>,
}

async fn start(id: Identity, contacts: Vec<ContactRef>, cfg: NodeConfig) -> Peer {
    let key = *id.public_key();
    let (handle, events) = Node::start(id, contacts, cfg).await.unwrap();
    Peer { key, handle, events }
}

#[tokio::test(flavor = "multi_thread")]
async fn message_exchange_with_receipts() {
    let alice_id = Identity::generate().unwrap();
    let bob_id = Identity::generate().unwrap();
    let (alice_key, bob_key) = (*alice_id.public_key(), *bob_id.public_key());

    let mut bob = start(bob_id, vec![ContactRef { public_key: alice_key, address: None }], config(localhost())).await;
    let bob_addr = listening(&mut bob.events).await;
    let mut alice =
        start(alice_id, vec![ContactRef { public_key: bob_key, address: addr(bob_addr) }], config(None)).await;

    let id = alice.handle.send_text(bob.key, "Hallo Bob 👋".into()).await.unwrap();
    let got = expect(&mut bob.events, "message", |e| matches!(e, Event::Message { .. })).await;
    assert_eq!(got, Event::Message { contact: alice.key, id, text: "Hallo Bob 👋".into() });
    expect(&mut alice.events, "receipt", |e| *e == Event::Delivered { contact: bob.key, id }).await;
    assert_eq!(alice.handle.pending(bob.key).await.unwrap(), 0);

    // Bob has no address for Alice, but can answer over the same session.
    let reply = bob.handle.send_text(alice.key, "Hi Alice".into()).await.unwrap();
    let got = expect(&mut alice.events, "reply", |e| matches!(e, Event::Message { .. })).await;
    assert_eq!(got, Event::Message { contact: bob.key, id: reply, text: "Hi Alice".into() });
    expect(&mut bob.events, "reply receipt", |e| *e == Event::Delivered { contact: alice.key, id: reply }).await;

    alice.handle.shutdown().await;
    expect(&mut bob.events, "disconnect", |e| *e == Event::Disconnected { contact: alice.key }).await;
    bob.handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn messages_are_queued_until_peer_comes_online() {
    let alice_id = Identity::generate().unwrap();
    let bob_id = Identity::generate().unwrap();
    let (alice_key, bob_key) = (*alice_id.public_key(), *bob_id.public_key());
    let bob_socket = free_port().await;

    let mut alice =
        start(alice_id, vec![ContactRef { public_key: bob_key, address: addr(bob_socket) }], config(None)).await;
    let first = alice.handle.send_text(bob_key, "one".into()).await.unwrap();
    let second = alice.handle.send_text(bob_key, "two".into()).await.unwrap();
    expect(&mut alice.events, "connect failure", |e| matches!(e, Event::ConnectFailed { retry_in: Some(_), .. })).await;
    assert_eq!(alice.handle.pending(bob_key).await.unwrap(), 2);

    let mut bob =
        start(bob_id, vec![ContactRef { public_key: alice_key, address: None }], config(Some(bob_socket))).await;
    let mut texts = Vec::new();
    while texts.len() < 2 {
        if let Event::Message { text, .. } =
            expect(&mut bob.events, "queued", |e| matches!(e, Event::Message { .. })).await
        {
            texts.push(text);
        }
    }
    assert_eq!(texts, ["one", "two"], "order must be preserved");
    expect(&mut alice.events, "first receipt", |e| *e == Event::Delivered { contact: bob_key, id: first }).await;
    expect(&mut alice.events, "second receipt", |e| *e == Event::Delivered { contact: bob_key, id: second }).await;
    alice.handle.shutdown().await;
    bob.handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_dial_converges_to_one_session() {
    let alice_id = Identity::generate().unwrap();
    let bob_id = Identity::generate().unwrap();
    let (alice_key, bob_key) = (*alice_id.public_key(), *bob_id.public_key());
    let (alice_socket, bob_socket) = (free_port().await, free_port().await);

    let mut alice = start(
        alice_id,
        vec![ContactRef { public_key: bob_key, address: addr(bob_socket) }],
        config(Some(alice_socket)),
    )
    .await;
    let mut bob = start(
        bob_id,
        vec![ContactRef { public_key: alice_key, address: addr(alice_socket) }],
        config(Some(bob_socket)),
    )
    .await;
    alice.handle.connect(bob_key).unwrap();
    bob.handle.connect(alice_key).unwrap();
    expect(&mut alice.events, "alice connected", |e| matches!(e, Event::Connected { .. })).await;
    expect(&mut bob.events, "bob connected", |e| matches!(e, Event::Connected { .. })).await;

    // Exchange several messages in both directions; each must arrive exactly once.
    for i in 0..5 {
        alice.handle.send_text(bob_key, format!("a{i}")).await.unwrap();
        bob.handle.send_text(alice_key, format!("b{i}")).await.unwrap();
    }
    let mut at_bob = Vec::new();
    while at_bob.len() < 5 {
        if let Event::Message { text, .. } =
            expect(&mut bob.events, "a-msgs", |e| matches!(e, Event::Message { .. })).await
        {
            at_bob.push(text);
        }
    }
    let mut at_alice = Vec::new();
    while at_alice.len() < 5 {
        if let Event::Message { text, .. } =
            expect(&mut alice.events, "b-msgs", |e| matches!(e, Event::Message { .. })).await
        {
            at_alice.push(text);
        }
    }
    at_bob.sort();
    at_alice.sort();
    assert_eq!(at_bob, ["a0", "a1", "a2", "a3", "a4"]);
    assert_eq!(at_alice, ["b0", "b1", "b2", "b3", "b4"]);

    // No duplicates show up afterwards.
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(ev) = alice.events.try_recv() {
        assert!(!matches!(ev, Event::Message { .. }), "duplicate at alice: {ev:?}");
    }
    while let Ok(ev) = bob.events.try_recv() {
        assert!(!matches!(ev, Event::Message { .. }), "duplicate at bob: {ev:?}");
    }
    assert!(alice.handle.is_connected(bob_key).await.unwrap());
    assert!(bob.handle.is_connected(alice_key).await.unwrap());
    alice.handle.shutdown().await;
    bob.handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn strangers_are_rejected() {
    let bob_id = Identity::generate().unwrap();
    let mallory_id = Identity::generate().unwrap();
    let friend = *Identity::generate().unwrap().public_key();
    let (bob_key, mallory_key) = (*bob_id.public_key(), *mallory_id.public_key());

    let mut bob = start(bob_id, vec![ContactRef { public_key: friend, address: None }], config(localhost())).await;
    let bob_addr = listening(&mut bob.events).await;
    let mut mallory =
        start(mallory_id, vec![ContactRef { public_key: bob_key, address: addr(bob_addr) }], config(None)).await;

    mallory.handle.send_text(bob_key, "let me in".into()).await.unwrap();
    expect(&mut bob.events, "unknown peer", |e| *e == Event::UnknownPeer { public_key: mallory_key }).await;
    // Mallory never believes she is connected thanks to key confirmation.
    let ev =
        expect(&mut mallory.events, "failure", |e| matches!(e, Event::ConnectFailed { .. } | Event::Connected { .. }))
            .await;
    assert!(matches!(ev, Event::ConnectFailed { .. }), "got {ev:?}");
    assert_eq!(mallory.handle.pending(bob_key).await.unwrap(), 1);
    mallory.handle.shutdown().await;
    bob.handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn impostor_with_wrong_key_is_not_accepted() {
    // Alice thinks bob_socket belongs to Bob, but Mallory listens there.
    let alice_id = Identity::generate().unwrap();
    let bob_key = *Identity::generate().unwrap().public_key();
    let mallory_id = Identity::generate().unwrap();
    let alice_key = *alice_id.public_key();

    let mut mallory =
        start(mallory_id, vec![ContactRef { public_key: alice_key, address: None }], config(localhost())).await;
    let socket = listening(&mut mallory.events).await;
    let mut alice =
        start(alice_id, vec![ContactRef { public_key: bob_key, address: addr(socket) }], config(None)).await;
    alice.handle.send_text(bob_key, "secret".into()).await.unwrap();
    expect(&mut alice.events, "failure", |e| matches!(e, Event::ConnectFailed { .. })).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    while let Ok(ev) = mallory.events.try_recv() {
        assert!(!matches!(ev, Event::Message { .. } | Event::Connected { .. }), "{ev:?}");
    }
    alice.handle.shutdown().await;
    mallory.handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn onion_address_requires_proxy() {
    let alice_id = Identity::generate().unwrap();
    let bob_key = *Identity::generate().unwrap().public_key();
    let onion: PeerAddress = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:7878".parse().unwrap();
    let mut alice = start(alice_id, vec![ContactRef { public_key: bob_key, address: Some(onion) }], config(None)).await;
    alice.handle.send_text(bob_key, "hi".into()).await.unwrap();
    let ev = expect(&mut alice.events, "failure", |e| matches!(e, Event::ConnectFailed { .. })).await;
    let Event::ConnectFailed { error, .. } = ev else { unreachable!() };
    assert!(error.contains("Tor"), "{error}");
    alice.handle.shutdown().await;
}

/// Minimal SOCKS5 server (RFC 1928/1929) that records the requested target
/// and forwards to a fixed local address, standing in for Tor.
async fn fake_socks_proxy(forward_to: SocketAddr) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                client.read_exact(&mut hdr).await.unwrap();
                let mut methods = vec![0u8; hdr[1] as usize];
                client.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&2), "client must offer username/password (stream isolation)");
                client.write_all(&[5, 2]).await.unwrap();
                let mut ver_ulen = [0u8; 2];
                client.read_exact(&mut ver_ulen).await.unwrap();
                let mut user = vec![0u8; ver_ulen[1] as usize];
                client.read_exact(&mut user).await.unwrap();
                let mut plen = [0u8; 1];
                client.read_exact(&mut plen).await.unwrap();
                let mut pass = vec![0u8; plen[0] as usize];
                client.read_exact(&mut pass).await.unwrap();
                client.write_all(&[1, 0]).await.unwrap();
                let mut req = [0u8; 4];
                client.read_exact(&mut req).await.unwrap();
                assert_eq!(req[3], 3, "target must be sent as a domain name (no local DNS)");
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await.unwrap();
                let mut host = vec![0u8; len[0] as usize];
                client.read_exact(&mut host).await.unwrap();
                let mut port = [0u8; 2];
                client.read_exact(&mut port).await.unwrap();
                let _ = tx.send(format!("{}:{}", String::from_utf8(host).unwrap(), u16::from_be_bytes(port)));
                let mut upstream = TcpStream::connect(forward_to).await.unwrap();
                client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (local, rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn connects_through_socks5_proxy_to_onion() {
    let alice_id = Identity::generate().unwrap();
    let bob_id = Identity::generate().unwrap();
    let (alice_key, bob_key) = (*alice_id.public_key(), *bob_id.public_key());
    let mut bob = start(bob_id, vec![ContactRef { public_key: alice_key, address: None }], config(localhost())).await;
    let bob_socket = listening(&mut bob.events).await;
    let (proxy, mut requests) = fake_socks_proxy(bob_socket).await;

    let onion = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:7878";
    let mut cfg = config(None);
    cfg.socks5_proxy = Some(proxy);
    let alice =
        start(alice_id, vec![ContactRef { public_key: bob_key, address: Some(onion.parse().unwrap()) }], cfg).await;
    alice.handle.send_text(bob_key, "via tor".into()).await.unwrap();
    let got = expect(&mut bob.events, "message", |e| matches!(e, Event::Message { .. })).await;
    assert!(matches!(got, Event::Message { ref text, .. } if text == "via tor"));
    assert_eq!(timeout(WAIT, requests.recv()).await.unwrap().unwrap(), onion);
    alice.handle.shutdown().await;
    bob.handle.shutdown().await;
}

/// Two identities ordered so that the first has the smaller public key.
fn ordered_pair() -> (Identity, Identity) {
    loop {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        if a.public_key() < b.public_key() {
            return (a, b);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnect_replaces_a_dead_session() {
    // Alice (smaller key) holds a session she initiated whose other end is
    // dead but whose TCP connection is still open. When Bob comes back and
    // dials her, the new session must win instead of waiting for the idle
    // timeout.
    let (alice_id, bob_id) = ordered_pair();
    let (alice_key, bob_key) = (*alice_id.public_key(), *bob_id.public_key());

    let dead_bob = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_bob_addr = dead_bob.local_addr().unwrap();
    let zombie_identity = bob_id.clone();
    let zombie = tokio::spawn(async move {
        let (mut stream, _) = dead_bob.accept().await.unwrap();
        let first = std::time::Duration::from_secs(5);
        let channel =
            neccrit_core::handshake::respond(&mut stream, &zombie_identity, first, |k| *k == alice_key).await.unwrap();
        // Keep the connection open but never read or write again.
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop((channel, stream));
    });

    let mut cfg = config(localhost());
    cfg.handshake_timeout = Duration::from_secs(1);
    let mut alice = start(alice_id, vec![ContactRef { public_key: bob_key, address: addr(dead_bob_addr) }], cfg).await;
    let alice_addr = listening(&mut alice.events).await;
    alice.handle.connect(bob_key).unwrap();
    expect(&mut alice.events, "first session", |e| *e == Event::Connected { contact: bob_key }).await;

    // Outlive the simultaneous-dial window, then Bob reappears.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut bob =
        start(bob_id, vec![ContactRef { public_key: alice_key, address: addr(alice_addr) }], config(None)).await;
    let id = bob.handle.send_text(alice_key, "back again".into()).await.unwrap();
    let got = expect(&mut alice.events, "message", |e| matches!(e, Event::Message { .. })).await;
    assert!(matches!(got, Event::Message { ref text, .. } if text == "back again"));
    expect(&mut bob.events, "receipt", |e| *e == Event::Delivered { contact: alice_key, id }).await;
    zombie.abort();
    alice.handle.shutdown().await;
    bob.handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn large_queues_flush_in_both_directions() {
    let alice_id = Identity::generate().unwrap();
    let bob_id = Identity::generate().unwrap();
    let (alice_key, bob_key) = (*alice_id.public_key(), *bob_id.public_key());
    let body = "x".repeat(8000);

    // Bob cannot reach Alice, so his messages wait in his outbox.
    let mut bob = start(bob_id, vec![ContactRef { public_key: alice_key, address: None }], config(localhost())).await;
    let bob_addr = listening(&mut bob.events).await;
    for _ in 0..100 {
        bob.handle.send_text(alice_key, body.clone()).await.unwrap();
    }
    // Alice queues as many; as soon as she connects both sides flush ~1.6 MB.
    let mut alice =
        start(alice_id, vec![ContactRef { public_key: bob_key, address: addr(bob_addr) }], config(None)).await;
    for _ in 0..100 {
        alice.handle.send_text(bob_key, body.clone()).await.unwrap();
    }

    async fn drain(peer: &mut Peer, other: PublicKey) {
        let (mut received, mut delivered) = (0, 0);
        while received < 100 || delivered < 100 {
            match expect(&mut peer.events, "traffic", |e| matches!(e, Event::Message { .. } | Event::Delivered { .. }))
                .await
            {
                Event::Message { contact, .. } if contact == other => received += 1,
                Event::Delivered { contact, .. } if contact == other => delivered += 1,
                ev => panic!("unexpected {ev:?}"),
            }
        }
    }
    tokio::join!(drain(&mut alice, bob_key), drain(&mut bob, alice_key));
    assert_eq!(alice.handle.pending(bob_key).await.unwrap(), 0);
    assert_eq!(bob.handle.pending(alice_key).await.unwrap(), 0);
    alice.handle.shutdown().await;
    bob.handle.shutdown().await;
}
