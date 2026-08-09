//! Network address utilities shared across Zentinel crates.
//!
//! Currently provides [`Cidr`], a minimal CIDR block used for trusted-source
//! allow-lists (e.g. which load balancers may send a PROXY protocol header).
//! Kept dependency-free on purpose: matching is a prefix comparison on the
//! integer form of the address.

use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

/// Errors produced while parsing a [`Cidr`] from text.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CidrParseError {
    /// The string did not contain exactly one `/` separating address and prefix.
    #[error("expected 'address/prefix' form, got '{0}'")]
    MissingPrefix(String),

    /// The address part did not parse as an IPv4 or IPv6 address.
    #[error("invalid IP address '{0}'")]
    InvalidAddress(String),

    /// The prefix part did not parse as a number.
    #[error("invalid prefix length '{0}'")]
    InvalidPrefix(String),

    /// The prefix length exceeds the address family's bit width.
    #[error("prefix length {prefix} exceeds maximum {max} for this address family")]
    PrefixTooLong {
        /// The prefix length given.
        prefix: u8,
        /// Maximum for the family (32 for IPv4, 128 for IPv6).
        max: u8,
    },
}

/// An IP network in CIDR notation, e.g. `10.0.0.0/8` or `fd00::/8`.
///
/// Matching normalizes IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to IPv4
/// first, so a `10.0.0.0/8` block matches a client that a dual-stack socket
/// reports as `::ffff:10.1.2.3`. Families never cross otherwise: an IPv4
/// block does not match a real IPv6 address and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Returns true when `ip` falls inside this block.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = prefix_mask_v4(self.prefix);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = prefix_mask_v6(self.prefix);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((addr, prefix)) = s.split_once('/') else {
            return Err(CidrParseError::MissingPrefix(s.to_string()));
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| CidrParseError::InvalidAddress(addr.to_string()))?;
        // Canonicalize so "::ffff:10.0.0.0/104"-style blocks behave as their
        // author intended only when written as the real family.
        let addr = addr.to_canonical();
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| CidrParseError::InvalidPrefix(prefix.to_string()))?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(CidrParseError::PrefixTooLong { prefix, max });
        }
        Ok(Cidr { addr, prefix })
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr {
        s.parse().expect("test CIDR must parse")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP must parse")
    }

    #[test]
    fn v4_prefix_match_and_boundary() {
        let block = cidr("10.0.0.0/8");
        assert!(block.contains(ip("10.0.0.1")));
        assert!(block.contains(ip("10.255.255.255")));
        assert!(!block.contains(ip("11.0.0.0")));
        assert!(!block.contains(ip("9.255.255.255")));
    }

    #[test]
    fn v4_host_route_matches_only_itself() {
        let block = cidr("192.0.2.7/32");
        assert!(block.contains(ip("192.0.2.7")));
        assert!(!block.contains(ip("192.0.2.8")));
    }

    #[test]
    fn zero_prefix_matches_everything_in_family() {
        assert!(cidr("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(cidr("::/0").contains(ip("2001:db8::1")));
        // /0 does not cross families.
        assert!(!cidr("0.0.0.0/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn v6_prefix_match() {
        let block = cidr("2001:db8::/32");
        assert!(block.contains(ip("2001:db8::1")));
        assert!(block.contains(ip("2001:db8:ffff::1")));
        assert!(!block.contains(ip("2001:db9::1")));
    }

    #[test]
    fn v4_mapped_v6_client_matches_v4_block() {
        let block = cidr("10.0.0.0/8");
        assert!(block.contains(ip("::ffff:10.1.2.3")));
        assert!(!block.contains(ip("::ffff:11.1.2.3")));
    }

    #[test]
    fn families_do_not_cross() {
        assert!(!cidr("10.0.0.0/8").contains(ip("fd00::1")));
        assert!(!cidr("fd00::/8").contains(ip("10.0.0.1")));
    }

    #[test]
    fn parse_rejects_malformed_input() {
        assert_eq!(
            "10.0.0.0".parse::<Cidr>(),
            Err(CidrParseError::MissingPrefix("10.0.0.0".to_string()))
        );
        assert_eq!(
            "banana/8".parse::<Cidr>(),
            Err(CidrParseError::InvalidAddress("banana".to_string()))
        );
        assert_eq!(
            "10.0.0.0/x".parse::<Cidr>(),
            Err(CidrParseError::InvalidPrefix("x".to_string()))
        );
        assert_eq!(
            "10.0.0.0/33".parse::<Cidr>(),
            Err(CidrParseError::PrefixTooLong {
                prefix: 33,
                max: 32
            })
        );
        assert_eq!(
            "::/129".parse::<Cidr>(),
            Err(CidrParseError::PrefixTooLong {
                prefix: 129,
                max: 128
            })
        );
    }

    #[test]
    fn display_round_trips() {
        assert_eq!(cidr("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(cidr("2001:db8::/32").to_string(), "2001:db8::/32");
    }
}
