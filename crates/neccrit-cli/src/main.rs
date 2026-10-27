//! `neccrit` – command line client.

mod chat;
mod display;
mod store;

use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use neccrit_core::contact::validate_contact_name;
use neccrit_core::{Contact, Identity, Invite, PeerAddress, Profile, PublicKey, SafetyNumber};

use crate::display::sanitize;
use crate::store::{PassphraseSource, Store};

/// Default Tor SOCKS port.
const TOR_SOCKS: &str = "127.0.0.1:9050";
const DEFAULT_PORT: u16 = 7878;

#[derive(Parser, Debug)]
#[command(name = "neccrit", version, about = "End-to-end encrypted peer-to-peer messenger", long_about = None)]
struct Cli {
    /// Profile directory (default: the platform data directory).
    #[arg(long, global = true, env = "NECCRIT_PROFILE")]
    profile: Option<PathBuf>,

    /// Read the passphrase from the first line of this file instead of
    /// prompting. Intended for scripting; keep the file private.
    #[arg(long, global = true, env = "NECCRIT_PASSPHRASE_FILE")]
    passphrase_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new profile with a fresh identity key.
    Init(InitArgs),
    /// Show the profile's settings.
    Status,
    /// Print your invite code for contacts to add you.
    Invite,
    /// Change network settings.
    Config(ConfigArgs),
    /// Manage contacts.
    #[command(subcommand)]
    Contact(ContactCommand),
    /// Change the profile passphrase.
    Passwd,
    /// Start chatting (optionally with a specific contact).
    Chat {
        /// Contact to talk to first.
        contact: Option<String>,
    },
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Name suggested to contacts in your invite code.
    #[arg(long)]
    name: Option<String>,
    /// Use Tor: outgoing connections via the Tor SOCKS proxy, listening on
    /// localhost for an onion service.
    #[arg(long)]
    tor: bool,
    /// Local address to accept connections on, e.g. 0.0.0.0:7878.
    #[arg(long)]
    listen: Option<SocketAddr>,
    /// Address contacts use to reach you (host:port or onion:port).
    #[arg(long)]
    address: Option<PeerAddress>,
}

#[derive(Args, Debug)]
struct ConfigArgs {
    /// Name suggested in invite codes ("none" to remove).
    #[arg(long)]
    name: Option<String>,
    /// Listen address ("none" to disable listening).
    #[arg(long)]
    listen: Option<String>,
    /// Address advertised in invite codes ("none" to remove).
    #[arg(long)]
    address: Option<String>,
    /// SOCKS5 proxy for all outgoing connections ("none" for direct).
    #[arg(long)]
    socks5: Option<String>,
}

#[derive(Subcommand, Debug)]
enum ContactCommand {
    /// Add a contact from an invite code (or a raw public key).
    Add {
        /// Local name for the contact (no spaces).
        name: String,
        /// The contact's invite code ("neccrit:...") or public key.
        code: String,
        /// Override or supply the contact's address.
        #[arg(long)]
        address: Option<PeerAddress>,
    },
    /// List contacts.
    List,
    /// Show details and the safety number of a contact.
    Show { name: String },
    /// Compare safety numbers and mark a contact as verified.
    Verify { name: String },
    /// Remove the verified mark.
    Unverify { name: String },
    /// Rename a contact.
    Rename { old: String, new: String },
    /// Set the address of a contact ("none" to remove).
    SetAddress { name: String, address: String },
    /// Delete a contact.
    Remove { name: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let passphrase = match cli.passphrase_file {
        Some(path) => PassphraseSource::File(path),
        None => PassphraseSource::Prompt,
    };
    let store = Store::new(cli.profile, passphrase)?;

    match cli.command {
        Command::Init(args) => init(&store, args),
        Command::Status => status(&store),
        Command::Invite => invite(&store),
        Command::Config(args) => config(&store, args),
        Command::Contact(cmd) => contact(&store, cmd),
        Command::Passwd => {
            let _lock = store.lock()?;
            let (mut vault, profile) = store.open()?;
            store.change_passphrase(&mut vault, &profile)?;
            println!("Passphrase changed.");
            Ok(())
        }
        Command::Chat { contact } => {
            let (_vault, profile) = store.open()?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(chat::run(profile, contact))
        }
    }
}

fn init(store: &Store, args: InitArgs) -> Result<()> {
    let _lock = store.lock()?;
    if store.exists() {
        bail!("a profile already exists in {}", store.dir().display());
    }
    let mut profile = Profile::new(Identity::generate()?);
    if let Some(name) = args.name {
        profile.display_name = Some(validate_contact_name(&name)?);
    }
    if args.tor {
        profile.socks5_proxy = Some(TOR_SOCKS.parse()?);
        profile.listen = Some(SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)));
    }
    if let Some(listen) = args.listen {
        profile.listen = Some(listen);
    }
    profile.advertised_address = args.address;
    store.create(&profile)?;

    println!("Profile created in {}", store.dir().display());
    println!("Your key: {}", profile.public_key().short_id());
    if args.tor {
        println!();
        println!("Tor mode: outgoing connections use {TOR_SOCKS}.");
        println!("To be reachable, add an onion service to your torrc:");
        println!();
        println!("    HiddenServiceDir /var/lib/tor/neccrit/");
        println!("    HiddenServicePort {DEFAULT_PORT} 127.0.0.1:{DEFAULT_PORT}");
        println!();
        println!("then restart Tor and run:");
        println!("    neccrit config --address $(sudo cat /var/lib/tor/neccrit/hostname):{DEFAULT_PORT}");
    } else if profile.listen.is_none() {
        println!();
        println!("Not listening for connections: contacts cannot reach you, you can only call them.");
        println!("Recommended: `neccrit config --socks5 {TOR_SOCKS} --listen 127.0.0.1:{DEFAULT_PORT}` with a Tor");
        println!("onion service (see README), or a direct address with --listen/--address.");
    }
    Ok(())
}

fn status(store: &Store) -> Result<()> {
    let (_vault, profile) = store.open()?;
    println!("Profile:     {}", store.dir().display());
    println!("Key:         {}", profile.public_key().short_id());
    println!("Name hint:   {}", profile.display_name.as_deref().unwrap_or("-"));
    println!("Listen:      {}", profile.listen.map_or("- (not reachable)".into(), |a| a.to_string()));
    println!("Address:     {}", profile.advertised_address.as_ref().map_or("-".into(), ToString::to_string));
    println!(
        "Proxy:       {}",
        profile.socks5_proxy.map_or("- (direct connections: your IP address is visible to contacts)".into(), |a| {
            format!("socks5://{a}")
        })
    );
    let verified = profile.contacts().iter().filter(|c| c.verified).count();
    println!("Contacts:    {} ({verified} verified)", profile.contacts().len());
    Ok(())
}

fn invite(store: &Store) -> Result<()> {
    let (_vault, profile) = store.open()?;
    if profile.advertised_address.is_none() {
        eprintln!("Note: no address configured, contacts will not be able to call you.");
        eprintln!("      Set one with `neccrit config --address host:port`.");
    }
    println!("{}", profile.invite().encode()?);
    eprintln!();
    eprintln!("Send this code to your contact. It is not secret, but after adding each other");
    eprintln!("you must compare safety numbers over a trusted channel: `neccrit contact verify <name>`.");
    Ok(())
}

fn none_or<T: std::str::FromStr>(value: &str) -> Result<Option<T>>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    if value.eq_ignore_ascii_case("none") { Ok(None) } else { Ok(Some(value.parse::<T>()?)) }
}

fn config(store: &Store, args: ConfigArgs) -> Result<()> {
    let _lock = store.lock()?;
    let (vault, mut profile) = store.open()?;
    if let Some(name) = args.name {
        profile.display_name =
            if name.eq_ignore_ascii_case("none") { None } else { Some(validate_contact_name(&name)?) };
    }
    if let Some(listen) = args.listen {
        profile.listen = none_or(&listen).context("invalid --listen")?;
    }
    if let Some(address) = args.address {
        profile.advertised_address = none_or(&address).context("invalid --address")?;
    }
    if let Some(proxy) = args.socks5 {
        profile.socks5_proxy = none_or(&proxy).context("invalid --socks5")?;
    }
    vault.save(&profile)?;
    println!("Saved.");
    Ok(())
}

fn parse_code(code: &str) -> Result<Invite> {
    let code = code.trim();
    if code.to_ascii_lowercase().starts_with(neccrit_core::contact::INVITE_PREFIX) {
        Ok(Invite::decode(code)?)
    } else {
        let key = PublicKey::from_base32(code).context("neither an invite code nor a public key")?;
        Ok(Invite { public_key: key, address: None, name_hint: None })
    }
}

fn print_safety_number(own: &PublicKey, other: &PublicKey) {
    for line in SafetyNumber::new(own, other).to_lines() {
        println!("    {line}");
    }
}

fn confirm(question: &str) -> Result<bool> {
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes" | "j" | "ja"))
}

fn contact(store: &Store, cmd: ContactCommand) -> Result<()> {
    match cmd {
        ContactCommand::List => {
            let (_vault, profile) = store.open()?;
            if profile.contacts().is_empty() {
                println!("No contacts yet. Add one with `neccrit contact add <name> <invite-code>`.");
            }
            for c in profile.contacts() {
                println!(
                    "{:<20} {}  {:<12} {}",
                    c.name,
                    c.public_key.short_id(),
                    if c.verified { "verified" } else { "UNVERIFIED" },
                    c.address.as_ref().map_or("-".into(), ToString::to_string)
                );
            }
            Ok(())
        }
        ContactCommand::Show { name } => {
            let (_vault, profile) = store.open()?;
            let c = profile.contact(&name).context("no such contact")?;
            println!("Name:      {}", c.name);
            println!("Key:       {}", c.public_key.to_base32());
            println!("Address:   {}", c.address.as_ref().map_or("-".into(), ToString::to_string));
            println!("Verified:  {}", if c.verified { "yes" } else { "NO" });
            println!("Safety number:");
            print_safety_number(profile.public_key(), &c.public_key);
            Ok(())
        }
        ContactCommand::Add { name, code, address } => {
            let _lock = store.lock()?;
            let (vault, mut profile) = store.open()?;
            let invite = parse_code(&code)?;
            let contact = Contact::new(&name, invite.public_key, address.or(invite.address))?;
            if let Some(hint) = &invite.name_hint
                && *hint != contact.name
            {
                println!("(The invite suggests the name \"{}\".)", sanitize(hint, ""));
            }
            profile.add_contact(contact)?;
            vault.save(&profile)?;
            println!("Added {name}. The contact is NOT verified yet.");
            println!("Compare this safety number with {name} in person or over a call you trust:");
            print_safety_number(profile.public_key(), &invite.public_key);
            println!("Then run `neccrit contact verify {name}`.");
            Ok(())
        }
        ContactCommand::Verify { name } => {
            let _lock = store.lock()?;
            let (vault, mut profile) = store.open()?;
            let key = profile.contact(&name).context("no such contact")?.public_key;
            println!("Safety number for you and {name}:");
            print_safety_number(profile.public_key(), &key);
            println!();
            println!("Compare ALL digits with {name} over a channel where you can be sure it is really them");
            println!("(in person, or a call where you recognise their voice). Do not compare via the same");
            println!("channel you received the invite code through.");
            if confirm("Do the numbers match exactly?")? {
                profile.contact_mut(&name).context("no such contact")?.verified = true;
                vault.save(&profile)?;
                println!("{name} is now verified.");
            } else {
                println!("Not verified. If the numbers differ, someone may be intercepting: remove the contact");
                println!("and exchange invite codes again over a different channel.");
            }
            Ok(())
        }
        ContactCommand::Unverify { name } => {
            let _lock = store.lock()?;
            let (vault, mut profile) = store.open()?;
            profile.contact_mut(&name).context("no such contact")?.verified = false;
            vault.save(&profile)?;
            println!("{name} is no longer marked as verified.");
            Ok(())
        }
        ContactCommand::Rename { old, new } => {
            let _lock = store.lock()?;
            let (vault, mut profile) = store.open()?;
            profile.rename_contact(&old, &new)?;
            vault.save(&profile)?;
            println!("Renamed.");
            Ok(())
        }
        ContactCommand::SetAddress { name, address } => {
            let _lock = store.lock()?;
            let (vault, mut profile) = store.open()?;
            let address = none_or(&address).context("invalid address")?;
            profile.contact_mut(&name).context("no such contact")?.address = address;
            vault.save(&profile)?;
            println!("Saved.");
            Ok(())
        }
        ContactCommand::Remove { name } => {
            let _lock = store.lock()?;
            let (vault, mut profile) = store.open()?;
            profile.remove_contact(&name)?;
            vault.save(&profile)?;
            println!("Removed {name}.");
            Ok(())
        }
    }
}
