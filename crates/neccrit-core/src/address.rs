//! Network addresses of peers.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// Maximum length of the textual form of an address.
pub const MAX_ADDRESS_LEN: usize = 255;

/// Where a peer can be reached: an IP address, a DNS name or a Tor v3 onion
/// address, plus a TCP port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerAddress {
    host: Host,
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Host {
    Ip(IpAddr),
    Name(String),
}

impl PeerAddress {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Host part in the form expected by resolvers and SOCKS proxies
    /// (IPv6 without brackets).
    pub fn host(&self) -> String {
        match &self.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Name(name) => name.clone(),
        }
    }

    /// `true` for Tor onion service addresses, which can only be reached
    /// through a Tor SOCKS proxy.
    pub fn is_onion(&self) -> bool {
        matches!(&self.host, Host::Name(name) if name.ends_with(".onion"))
    }

    /// `true` if the host is a DNS name that would need to be resolved
    /// (which leaks the name to the configured DNS resolver unless a proxy
    /// is used).
    pub fn needs_dns(&self) -> bool {
        matches!(&self.host, Host::Name(_)) && !self.is_onion()
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            Host::Ip(IpAddr::V4(ip)) => write!(f, "{ip}:{}", self.port),
            Host::Name(name) => write!(f, "{name}:{}", self.port),
        }
    }
}

impl FromStr for PeerAddress {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_ADDRESS_LEN {
            return Err(Error::InvalidAddress("empty or too long"));
        }

        let (host_part, port_part) = if let Some(rest) = text.strip_prefix('[') {
            let (v6, after) = rest.split_once(']').ok_or(Error::InvalidAddress("unclosed '['"))?;
            let port = after.strip_prefix(':').ok_or(Error::InvalidAddress("missing port"))?;
            let ip = Ipv6Addr::from_str(v6).map_err(|_| Error::InvalidAddress("bad IPv6 address"))?;
            (Host::Ip(IpAddr::V6(ip)), port)
        } else {
            let (host, port) = text.rsplit_once(':').ok_or(Error::InvalidAddress("missing port"))?;
            if host.contains(':') {
                return Err(Error::InvalidAddress("IPv6 addresses must be written as [addr]:port"));
            }
            match IpAddr::from_str(host) {
                Ok(ip) => (Host::Ip(ip), port),
                Err(_) => (Host::Name(parse_hostname(host)?), port),
            }
        };

        let port: u16 = port_part.parse().map_err(|_| Error::InvalidAddress("bad port"))?;
        if port == 0 {
            return Err(Error::InvalidAddress("port must not be 0"));
        }
        Ok(Self { host: host_part, port })
    }
}

fn parse_hostname(host: &str) -> Result<String> {
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
    if host.is_empty() || host.len() > 253 {
        return Err(Error::InvalidAddress("bad host name length"));
    }
    for label in host.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !valid {
            return Err(Error::InvalidAddress("bad host name"));
        }
    }
    if let Some(onion) = host.strip_suffix(".onion") {
        // Only v3 onion services (56 base32 characters) are supported; the
        // service name may be preceded by subdomain labels.
        let service = onion.rsplit('.').next().unwrap_or(onion);
        let v3 = service.len() == 56 && service.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
        if !v3 {
            return Err(Error::InvalidAddress("only Tor v3 onion addresses are supported"));
        }
    }
    Ok(host)
}

impl Serialize for PeerAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PeerAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";

    #[test]
    fn parses_common_forms() {
        let a: PeerAddress = "192.0.2.1:7878".parse().unwrap();
        assert_eq!(a.to_string(), "192.0.2.1:7878");
        assert!(!a.needs_dns());

        let b: PeerAddress = "[2001:db8::1]:7878".parse().unwrap();
        assert_eq!(b.host(), "2001:db8::1");
        assert_eq!(b.to_string(), "[2001:db8::1]:7878");

        let c: PeerAddress = "Chat.Example.org:443".parse().unwrap();
        assert_eq!(c.host(), "chat.example.org");
        assert!(c.needs_dns());

        let d: PeerAddress = format!("{ONION}:7878").parse().unwrap();
        assert!(d.is_onion());
        assert!(!d.needs_dns());
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "host",
            "host:",
            "host:0",
            "host:70000",
            "2001:db8::1:7878",
            "[2001:db8::1]7878",
            "bad_host:1",
            "-bad.example:1",
            "short.onion:1",
            "a b:1",
            "host:1\u{202e}",
        ] {
            assert!(bad.parse::<PeerAddress>().is_err(), "accepted {bad:?}");
        }
        let long = format!("{}:1", "a".repeat(300));
        assert!(long.parse::<PeerAddress>().is_err());
    }
}
