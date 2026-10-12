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

/// Company slug, `[a-z0-9-]{1,11}` starting and ending alphanumeric, so `wg-<slug>` fits the 15-byte IFNAMSIZ limit.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slug(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "slug must be 1–11 characters of a-z, 0-9 and -, starting and ending with a letter or digit: `{0}`"
)]
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
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let b = s.as_bytes();
        let ok = (1..=11).contains(&b.len())
            && b.iter().all(|&c| alnum(c) || c == b'-')
            && b.first().is_some_and(|&c| alnum(c))
            && b.last().is_some_and(|&c| alnum(c));
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

/// A company's network number `n`, within [`NET_INDEX_RANGE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetIndex(u8);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("net_index {0} is outside {lo}..={hi}", lo = NET_INDEX_RANGE.start(), hi = NET_INDEX_RANGE.end())]
pub struct InvalidNetIndex(pub i32);

impl TryFrom<i32> for NetIndex {
    type Error = InvalidNetIndex;

    fn try_from(n: i32) -> Result<Self, Self::Error> {
        u8::try_from(n)
            .ok()
            .filter(|n| NET_INDEX_RANGE.contains(n))
            .map(Self)
            .ok_or(InvalidNetIndex(n))
    }
}

impl NetIndex {
    pub fn get(self) -> u8 {
        self.0
    }

    /// `10.50.n.0/24`.
    pub fn subnet(self) -> Ipv4Net {
        Ipv4Net::new_assert(Ipv4Addr::new(10, 50, self.0, 0), 24)
    }

    /// `10.50.n.1`, the hub's address on `wg-<slug>`.
    pub fn hub_ip(self) -> Ipv4Addr {
        Ipv4Addr::new(10, 50, self.0, 1)
    }

    /// `51830 + n`.
    pub fn listen_port(self) -> u16 {
        PORT_BASE + u16::from(self.0)
    }

    /// Lowest free device address in `10.50.n.2–254`, or `None` when the subnet is
    /// full.
    pub fn next_device_ip(self, used: &[Ipv4Addr]) -> Option<Ipv4Addr> {
        DEVICE_HOSTS
            .map(|h| Ipv4Addr::new(10, 50, self.0, h))
            .find(|ip| !used.contains(ip))
    }
}

/// Whether `ip` is an assignable device address: `10.50.n.2–254` of a valid `n`.
pub fn is_device_ip(ip: Ipv4Addr) -> bool {
    let [a, b, n, h] = ip.octets();
    (a, b) == (10, 50) && NET_INDEX_RANGE.contains(&n) && DEVICE_HOSTS.contains(&h)
}

/// Lowest free `net_index`, or `None` when all are taken.
pub fn next_net_index(used: &[NetIndex]) -> Option<NetIndex> {
    NET_INDEX_RANGE
        .clone()
        .map(NetIndex)
        .find(|n| !used.contains(n))
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
        for bad in [
            "",
            "abcdefghijkl",
            "Nexial",
            "a_b",
            "a.b",
            "čau",
            "-",
            "-a",
            "a-",
        ] {
            assert!(bad.parse::<Slug>().is_err(), "{bad}");
        }
    }

    fn n(i: i32) -> NetIndex {
        NetIndex::try_from(i).unwrap()
    }

    #[test]
    fn net_index_range_is_enforced() {
        for bad in [-1, 0, 10, 256] {
            assert_eq!(NetIndex::try_from(bad), Err(InvalidNetIndex(bad)));
        }
        assert_eq!(n(9).get(), 9);
    }

    #[test]
    fn addressing() {
        assert_eq!(n(1).subnet().to_string(), "10.50.1.0/24");
        assert_eq!(n(2).hub_ip(), Ipv4Addr::new(10, 50, 2, 1));
        assert_eq!(n(1).listen_port(), 51831);
        assert_eq!(n(9).listen_port(), 51839);
        assert!(TENANT_CIDR.contains(&n(9).subnet()));
    }

    #[test]
    fn net_index_allocation() {
        assert_eq!(next_net_index(&[]), Some(n(1)));
        assert_eq!(next_net_index(&[n(1), n(2), n(4)]), Some(n(3)));
        let all: Vec<_> = (1..=9).map(n).collect();
        assert_eq!(next_net_index(&all), None);
    }

    #[test]
    fn device_ip_validity() {
        for ok in ["10.50.1.2", "10.50.9.254"] {
            assert!(is_device_ip(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "10.50.1.1",
            "10.50.1.0",
            "10.50.1.255",
            "10.50.0.5",
            "10.50.10.5",
            "10.49.1.2",
        ] {
            assert!(!is_device_ip(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn device_ip_allocation() {
        let ip = |h| Ipv4Addr::new(10, 50, 3, h);
        assert_eq!(n(3).next_device_ip(&[]), Some(ip(2)));
        assert_eq!(n(3).next_device_ip(&[ip(2), ip(4)]), Some(ip(3)));
        // Addresses of other companies do not count.
        assert_eq!(
            n(3).next_device_ip(&[Ipv4Addr::new(10, 50, 1, 2)]),
            Some(ip(2))
        );
        let full: Vec<_> = (2..=254).map(ip).collect();
        assert_eq!(n(3).next_device_ip(&full), None);
    }
}
