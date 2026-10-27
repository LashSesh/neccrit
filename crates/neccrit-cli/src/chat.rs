//! Interactive line-based chat.

use std::collections::{HashMap, HashSet};
use std::io::BufRead;

use anyhow::{Result, bail};
use neccrit_core::{ContactRef, Event, Node, NodeConfig, NodeHandle, Profile, PublicKey, SafetyNumber};
use tokio::sync::mpsc;

use crate::display::{Style, sanitize};

const HELP: &str = "\
Commands:
  /to <name>        talk to <name> (connects in the background)
  /contacts         list contacts with online status
  /safety [name]    show the safety number for verification
  /help             this help
  /quit             leave (undelivered messages are lost)
Anything else is sent to the current contact; start a line with // to send a leading '/'.";

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Quit,
}

struct Ui {
    profile: Profile,
    names: HashMap<PublicKey, String>,
    node: NodeHandle,
    current: Option<PublicKey>,
    unreachable_reported: HashSet<PublicKey>,
    quit_requested: bool,
    style: Style,
}

fn now() -> String {
    chrono::Local::now().format("%H:%M").to_string()
}

pub async fn run(profile: Profile, initial: Option<String>) -> Result<()> {
    if profile.contacts().is_empty() {
        bail!("you have no contacts yet; add one with `neccrit contact add <name> <invite-code>`");
    }
    let contacts = profile
        .contacts()
        .iter()
        .map(|c| ContactRef { public_key: c.public_key, address: c.address.clone() })
        .collect();
    let config = NodeConfig { listen: profile.listen, socks5_proxy: profile.socks5_proxy, ..NodeConfig::default() };

    match profile.socks5_proxy {
        Some(proxy) => println!("* outgoing connections go through socks5://{proxy}"),
        None => println!("* direct connections: contacts (and network observers) can see your IP address"),
    }
    if profile.listen.is_none() {
        println!("* not listening: contacts cannot call you, you can only call them");
    }

    let (node, mut events) = Node::start(profile.identity().clone(), contacts, config).await?;
    let names = profile.contacts().iter().map(|c| (c.public_key, c.name.clone())).collect();
    let mut ui = Ui {
        profile,
        names,
        node: node.clone(),
        current: None,
        unreachable_reported: HashSet::new(),
        quit_requested: false,
        style: Style::detect(),
    };
    println!("* type /help for commands");
    if let Some(name) = initial {
        ui.switch_to(&name);
    }

    // Blocking stdin reader on its own thread so that quitting never waits for
    // a pending read.
    let (line_tx, mut lines) = mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            line = lines.recv() => match line {
                Some(line) => {
                    if ui.on_line(&line).await == Flow::Quit {
                        break;
                    }
                }
                None => break,
            },
            event = events.recv() => match event {
                Some(event) => ui.on_event(event),
                None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    println!("* closing sessions…");
    node.shutdown().await;
    Ok(())
}

impl Ui {
    fn name(&self, key: &PublicKey) -> String {
        self.names.get(key).cloned().unwrap_or_else(|| key.short_id())
    }

    fn label(&self, key: &PublicKey) -> String {
        let verified = self.profile.contact_by_key(key).is_some_and(|c| c.verified);
        if verified { self.name(key) } else { format!("{} (unverified)", self.name(key)) }
    }

    fn switch_to(&mut self, name: &str) {
        let Some(contact) = self.profile.contact(name) else {
            println!("! no contact named {}", sanitize(name, ""));
            return;
        };
        let key = contact.public_key;
        self.current = Some(key);
        println!("* now talking to {}", self.label(&key));
        if !contact.verified {
            println!("! {name} is not verified: compare safety numbers (/safety) before sharing anything sensitive");
        }
        if contact.address.is_none() {
            println!("* no address known for {name}; waiting for them to connect");
        }
        if self.node.connect(key).is_err() {
            println!("! node stopped");
        }
    }

    async fn on_line(&mut self, line: &str) -> Flow {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            return Flow::Continue;
        }
        if let Some(text) = line.strip_prefix("//") {
            self.send(&format!("/{text}")).await;
            return Flow::Continue;
        }
        let Some(command) = line.strip_prefix('/') else {
            self.send(line).await;
            return Flow::Continue;
        };
        let mut parts = command.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("help"), _) => println!("{HELP}"),
            (Some("quit" | "exit" | "q"), _) => return self.quit().await,
            (Some("to"), Some(name)) => self.switch_to(name),
            (Some("contacts" | "list"), _) => self.list().await,
            (Some("safety"), name) => {
                let key = match name {
                    Some(n) => self.profile.contact(n).map(|c| c.public_key),
                    None => self.current,
                };
                match key {
                    Some(key) => {
                        println!("* safety number with {}:", self.label(&key));
                        for line in SafetyNumber::new(self.profile.public_key(), &key).to_lines() {
                            println!("    {line}");
                        }
                        println!(
                            "* after comparing, mark as verified with `neccrit contact verify {}`",
                            self.name(&key)
                        );
                    }
                    None => println!("! which contact? /safety <name>"),
                }
            }
            _ => println!("! unknown command, see /help"),
        }
        Flow::Continue
    }

    async fn send(&mut self, text: &str) {
        let Some(key) = self.current else {
            println!("! no recipient selected: /to <name>");
            return;
        };
        match self.node.send_text(key, text.to_owned()).await {
            Ok(_) => {
                self.quit_requested = false;
                if !self.node.is_connected(key).await.unwrap_or(false) {
                    println!("* {} is not connected; message queued", self.name(&key));
                }
            }
            Err(err) => println!("! not sent: {err}"),
        }
    }

    async fn list(&self) {
        for c in self.profile.contacts() {
            let online = self.node.is_connected(c.public_key).await.unwrap_or(false);
            let pending = self.node.pending(c.public_key).await.unwrap_or(0);
            println!(
                "  {:<20} {:<8} {:<11} {}",
                c.name,
                if online { "online" } else { "offline" },
                if c.verified { "verified" } else { "UNVERIFIED" },
                if pending > 0 { format!("{pending} queued") } else { String::new() }
            );
        }
    }

    async fn quit(&mut self) -> Flow {
        let mut pending = 0;
        for c in self.profile.contacts() {
            pending += self.node.pending(c.public_key).await.unwrap_or(0);
        }
        if pending > 0 && !self.quit_requested {
            println!("! {pending} message(s) not yet delivered will be lost. Type /quit again to leave anyway.");
            self.quit_requested = true;
            return Flow::Continue;
        }
        Flow::Quit
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Listening { addr } => println!("* listening on {addr}"),
            Event::Connected { contact } => {
                self.unreachable_reported.remove(&contact);
                println!("* {} is online (end-to-end encrypted session)", self.label(&contact));
            }
            Event::Disconnected { contact } => println!("* {} went offline", self.name(&contact)),
            Event::Message { contact, text, .. } => {
                let marker = if self.current == Some(contact) { "" } else { "  ← /to to reply" };
                let verified = self.profile.contact_by_key(&contact).is_some_and(|c| c.verified);
                let sender = self.style.sender(&format!("[{}] {}:", now(), self.label(&contact)), verified);
                println!("{sender} {}{marker}", sanitize(&text, "      | "));
            }
            Event::Delivered { contact, id } => println!("  ✓ delivered to {} [{id}]", self.name(&contact)),
            Event::ConnectFailed { contact, error, .. } => {
                if self.unreachable_reported.insert(contact) {
                    println!("* cannot reach {} ({error}); retrying in the background", self.name(&contact));
                }
            }
            Event::UnknownPeer { public_key } => {
                println!("* someone who is not in your contacts connected and was rejected. Their key:");
                println!("    {}", public_key.to_base32());
                println!("  If you expected this, add them with `neccrit contact add <name> <key>` and verify them.");
            }
        }
    }
}
