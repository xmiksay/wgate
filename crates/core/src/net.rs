//! Company networks: naming, addressing and allocation (design.md → Topology).

use std::fmt;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::str::FromStr;

use ipnet::Ipv4Net;

/// Every company network lives inside this; the hub SNATs it towards the nodes.
pub const TENANT_CIDR: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(10, 50, 0, 0), 16);
/// Allocatable `net_index` values. 0 is reserved; 1..=9 map to UDP 51831–51839, the
/// range the firewall opens.
pub const NET_INDEX_RANGE: RangeInclusive<u8> = 1..=9;
const PORT_BASE: u16 = 51830;
/// `.1` is the hub, `.255` broadcast.
const DEVICE_HOSTS: RangeInclusive<u8> = 2..=254;

/// Company slug, `[a-z0-9-]{1,11}`, so `wg-<slug>` fits the 15-byte IFNAMSIZ limit.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slug(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("slug must be 1–11 characters of a-z, 0-9 and -: `{0}`")]
pub struct InvalidSlug(pub String);

impl Slug {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn iface(&self) -> String {
        format!("wg-{}", self.0)
    }
}

impl FromStr for Slug {
    type Err = InvalidSlug;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ok = (1..=11).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(InvalidSlug(s.to_owned()))
        }
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `10.50.n.0/24`.
pub fn company_subnet(n: u8) -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(10, 50, n, 0), 24)
}

/// `10.50.n.1`, the hub's address on `wg-<slug>`.
pub fn hub_ip(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 50, n, 1)
}

/// `51830 + n`.
pub fn listen_port(n: u8) -> u16 {
    PORT_BASE + u16::from(n)
}

/// Lowest free `net_index`, or `None` when all are taken.
pub fn next_net_index(used: &[u8]) -> Option<u8> {
    NET_INDEX_RANGE.clone().find(|n| !used.contains(n))
}

/// Lowest free device address in `10.50.n.2–254`, or `None` when the subnet is full.
pub fn next_device_ip(n: u8, used: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    DEVICE_HOSTS
        .map(|h| Ipv4Addr::new(10, 50, n, h))
        .find(|ip| !used.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_validation() {
        assert_eq!("nexial".parse::<Slug>().unwrap().iface(), "wg-nexial");
        assert_eq!("a-1".parse::<Slug>().unwrap().as_str(), "a-1");
        let longest: Slug = "abcdefghijk".parse().unwrap();
        assert_eq!(longest.iface().len(), 14);
        for bad in ["", "abcdefghijkl", "Nexial", "a_b", "a.b", "čau"] {
            assert!(bad.parse::<Slug>().is_err(), "{bad}");
        }
    }

    #[test]
    fn addressing() {
        assert_eq!(company_subnet(1).to_string(), "10.50.1.0/24");
        assert_eq!(hub_ip(2), Ipv4Addr::new(10, 50, 2, 1));
        assert_eq!(listen_port(1), 51831);
        assert_eq!(listen_port(9), 51839);
        assert!(TENANT_CIDR.contains(&company_subnet(9)));
    }

    #[test]
    fn net_index_allocation() {
        assert_eq!(next_net_index(&[]), Some(1));
        assert_eq!(next_net_index(&[1, 2, 4]), Some(3));
        assert_eq!(next_net_index(&[0]), Some(1));
        assert_eq!(next_net_index(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), None);
    }

    #[test]
    fn device_ip_allocation() {
        let ip = |h| Ipv4Addr::new(10, 50, 3, h);
        assert_eq!(next_device_ip(3, &[]), Some(ip(2)));
        assert_eq!(next_device_ip(3, &[ip(2), ip(4)]), Some(ip(3)));
        // Addresses of other companies do not count.
        assert_eq!(
            next_device_ip(3, &[Ipv4Addr::new(10, 50, 1, 2)]),
            Some(ip(2))
        );
        let full: Vec<_> = (2..=254).map(ip).collect();
        assert_eq!(next_device_ip(3, &full), None);
    }
}
