//! Drives the real `neccrit` binary: profile setup, invite exchange,
//! verification and a chat between two processes on localhost.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_neccrit");

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    pw: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        let pw = root.join("pw");
        std::fs::write(&pw, "a long test passphrase\n").unwrap();
        Self { _dir: dir, root, pw }
    }

    fn cmd(&self, profile: &str) -> Command {
        let mut c = Command::new(BIN);
        c.arg("--profile").arg(self.root.join(profile)).env("NECCRIT_PASSPHRASE_FILE", &self.pw);
        c
    }

    fn run(&self, profile: &str, args: &[&str]) -> Output {
        let out = self.cmd(profile).args(args).output().unwrap();
        assert!(out.status.success(), "{args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        out
    }

    fn run_with_stdin(&self, profile: &str, args: &[&str], input: &str) -> String {
        let mut child = self.cmd(profile).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn setup_pair(env: &Env) -> (u16, u16) {
    let (pa, pb) = (free_port(), free_port());
    for (name, port) in [("alice", pa), ("bob", pb)] {
        let addr = format!("127.0.0.1:{port}");
        env.run(name, &["init", "--name", name, "--listen", &addr, "--address", &addr]);
    }
    let alice_invite = stdout(&env.run("alice", &["invite"])).trim().to_owned();
    let bob_invite = stdout(&env.run("bob", &["invite"])).trim().to_owned();
    let a = stdout(&env.run("alice", &["contact", "add", "bob", &bob_invite]));
    let b = stdout(&env.run("bob", &["contact", "add", "alice", &alice_invite]));
    // Both sides must display the same safety number.
    let number = |s: &str| s.lines().filter(|l| l.starts_with("    ")).collect::<Vec<_>>().join("\n");
    assert_eq!(number(&a), number(&b));
    assert_eq!(number(&a).lines().count(), 3);
    (pa, pb)
}

#[test]
fn profile_and_contact_management() {
    let env = Env::new();
    setup_pair(&env);

    // Profile file is encrypted: neither names nor keys appear in it.
    let raw = std::fs::read(env.root.join("alice/profile.neccrit")).unwrap();
    assert!(raw.starts_with(b"NECCRITV"));
    assert!(!raw.windows(3).any(|w| w == b"bob"));

    // Wrong passphrase is refused.
    let bad = env.root.join("bad");
    std::fs::write(&bad, "not the passphrase\n").unwrap();
    let out = Command::new(BIN)
        .args(["--profile", env.root.join("alice").to_str().unwrap(), "status"])
        .env("NECCRIT_PASSPHRASE_FILE", &bad)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong passphrase"));

    let list = stdout(&env.run("alice", &["contact", "list"]));
    assert!(list.contains("bob") && list.contains("UNVERIFIED"));

    // Declining the comparison leaves the contact unverified.
    let out = env.run_with_stdin("alice", &["contact", "verify", "bob"], "n\n");
    assert!(out.contains("Not verified"));
    assert!(stdout(&env.run("alice", &["contact", "list"])).contains("UNVERIFIED"));
    let out = env.run_with_stdin("alice", &["contact", "verify", "bob"], "y\n");
    assert!(out.contains("now verified"));
    assert!(!stdout(&env.run("alice", &["contact", "list"])).contains("UNVERIFIED"));

    env.run("alice", &["contact", "rename", "bob", "robert"]);
    env.run("alice", &["contact", "set-address", "robert", "none"]);
    let show = stdout(&env.run("alice", &["contact", "show", "robert"]));
    assert!(show.contains("Address:   -"));

    // Duplicate keys and own invites are refused.
    let bob_invite = stdout(&env.run("bob", &["invite"])).trim().to_owned();
    let out = env.cmd("alice").args(["contact", "add", "bobby", &bob_invite]).output().unwrap();
    assert!(!out.status.success());
    let own = stdout(&env.run("alice", &["invite"])).trim().to_owned();
    let out = env.cmd("alice").args(["contact", "add", "me", &own]).output().unwrap();
    assert!(!out.status.success());

    env.run("alice", &["contact", "remove", "robert"]);
    assert!(stdout(&env.run("alice", &["contact", "list"])).contains("No contacts"));

    // Re-initialising must never overwrite an existing identity.
    let out = env.cmd("alice").args(["init"]).output().unwrap();
    assert!(!out.status.success());
}

struct ChatProc {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl ChatProc {
    fn spawn(env: &Env, profile: &str, peer: &str) -> Self {
        let mut child = env
            .cmd(profile)
            .args(["chat", peer])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, stdin, lines, seen: Vec::new() }
    }

    fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn wait_for(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(needle) {
                        return line;
                    }
                }
                Err(_) => panic!("timed out waiting for {needle:?}; output so far:\n{}", self.seen.join("\n")),
            }
        }
    }

    fn quit(mut self) {
        self.send("/quit");
        self.send("/quit");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        panic!("chat did not exit after /quit");
    }
}

#[test]
fn two_processes_chat() {
    let env = Env::new();
    setup_pair(&env);
    let mut bob = ChatProc::spawn(&env, "bob", "alice");
    let mut alice = ChatProc::spawn(&env, "alice", "bob");

    alice.wait_for("bob (unverified) is online");
    bob.wait_for("alice (unverified) is online");

    alice.send("Hallo Bob \u{1b}[2J");
    let got = bob.wait_for("alice (unverified): Hallo Bob");
    assert!(got.ends_with("Hallo Bob <U+001B>[2J"), "{got:?}");
    alice.wait_for("delivered to bob");

    bob.send("//slash first");
    let got = alice.wait_for("bob (unverified): ");
    assert!(got.ends_with("/slash first"), "{got:?}");
    bob.wait_for("delivered to alice");

    alice.quit();
    bob.wait_for("alice went offline");
    bob.quit();
}

#[test]
fn chat_refuses_without_contacts() {
    let env = Env::new();
    env.run("solo", &["init"]);
    let out = env.cmd("solo").args(["chat"]).stdin(Stdio::null()).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no contacts"));
}
