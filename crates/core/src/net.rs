//! Addressing: slugs, the global pool, blocks, network ranges, peer IPs and ports
//! (design.md → Decisions).

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::str::FromStr;

use ipnet::Ipv4Net;

use crate::rights::merge_nets;

/// Network listen ports; the firewall opens exactly this range.
pub const PORT_RANGE: RangeInclusive<u16> = 51800..=51899;
/// wg0's port, kept for when wg0 becomes a network (phase 3).
pub const RESERVED_PORT: u16 = 51820;
/// Smallest network: hub + one peer.
pub const MAX_NETWORK_PREFIX: u8 = 30;

/// Tenant or network slug, `[a-z0-9-]{1,11}` starting and ending alphanumeric, so
/// `wg-<slug>` fits the 15-byte IFNAMSIZ limit.
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

/// Whether `key` is a WireGuard key as `wg` prints it: 32 bytes of standard base64,
/// 44 characters (the last group carries 2 padding bits, hence the narrow 43rd).
pub fn is_wg_key(key: &str) -> bool {
    let b = key.as_bytes();
    let b64 = |c: &u8| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/';
    b.len() == 44
        && b[..42].iter().all(b64)
        && b"AEIMQUYcgkosw480".contains(&b[42])
        && b[43] == b'='
}

/// Whether two networks share any address.
pub fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// The first of `others` that shares an address with `net`.
pub fn first_overlap(net: Ipv4Net, others: &[Ipv4Net]) -> Option<Ipv4Net> {
    others.iter().copied().find(|&o| overlaps(net, o))
}

/// Whether `net` lies entirely inside `within`; adjacent entries count as one range.
pub fn is_inside(net: Ipv4Net, within: &[Ipv4Net]) -> bool {
    merge_nets(within).iter().any(|w| w.contains(&net))
}

/// The lowest `/prefix` inside one of `within` that overlaps none of `taken`: a block
/// in the pool for a tenant, or a network range in a tenant's blocks.
pub fn next_free_net(within: &[Ipv4Net], taken: &[Ipv4Net], prefix: u8) -> Option<Ipv4Net> {
    // Merged (and so sorted), like compile sees them: adjacent blocks form one range.
    merge_nets(within)
        .iter()
        .filter_map(|w| w.subnets(prefix).ok())
        .flatten()
        .find(|n| first_overlap(*n, taken).is_none())
}

/// The hub's address in a network: its first host.
pub fn hub_address(net: Ipv4Net) -> Ipv4Addr {
    // Saturating only matters for /32 at the top of the space, which no valid
    // network is (`MAX_NETWORK_PREFIX`).
    Ipv4Addr::from(u32::from(net.network()).saturating_add(1))
}

/// Whether `ip` is assignable to a peer of `net`: a host other than the hub address.
pub fn is_peer_ip(net: Ipv4Net, ip: Ipv4Addr) -> bool {
    net.prefix_len() <= MAX_NETWORK_PREFIX
        && net.contains(&ip)
        && ip != net.network()
        && ip != net.broadcast()
        && ip != hub_address(net)
}

/// Lowest free peer address in `net`, or `None` when it is full.
pub fn next_peer_ip(net: Ipv4Net, used: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    if net.prefix_len() > MAX_NETWORK_PREFIX {
        return None;
    }
    let used: HashSet<&Ipv4Addr> = used.iter().collect();
    // prefix <= 30, so network + 2 < broadcast and nothing overflows.
    let (lo, hi) = (u32::from(net.network()) + 2, u32::from(net.broadcast()));
    (lo..hi).map(Ipv4Addr::from).find(|ip| !used.contains(ip))
}

/// Lowest free listen port, or `None` when all 99 are taken.
pub fn next_port(used: &[u16]) -> Option<u16> {
    PORT_RANGE
        .clone()
        .find(|p| *p != RESERVED_PORT && !used.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::net;

    #[test]
    fn wireguard_keys() {
        assert!(is_wg_key("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));
        for bad in [
            "",
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk",
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmB=",
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBm!=",
        ] {
            assert!(!is_wg_key(bad), "{bad}");
        }
    }

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

    #[test]
    fn overlap_and_containment() {
        assert!(overlaps(net("10.50.0.0/16"), net("10.50.4.0/24")));
        assert!(overlaps(net("10.50.4.0/24"), net("10.50.0.0/16")));
        assert!(!overlaps(net("10.50.4.0/24"), net("10.50.5.0/24")));
        assert_eq!(
            first_overlap(
                net("10.50.4.128/25"),
                &[net("10.50.5.0/24"), net("10.50.4.0/24")]
            ),
            Some(net("10.50.4.0/24"))
        );
        assert!(is_inside(net("10.50.4.0/26"), &[net("10.50.4.0/24")]));
        assert!(!is_inside(net("10.50.4.0/23"), &[net("10.50.4.0/24")]));
    }

    #[test]
    fn free_net_allocation() {
        let pool = [net("10.50.0.0/16")];
        assert_eq!(next_free_net(&pool, &[], 24), Some(net("10.50.0.0/24")));
        let taken = [net("10.50.0.0/24"), net("10.50.1.0/25")];
        assert_eq!(next_free_net(&pool, &taken, 24), Some(net("10.50.2.0/24")));
        assert_eq!(
            next_free_net(&pool, &taken, 25),
            Some(net("10.50.1.128/25"))
        );
        // A prefix wider than the space fits nowhere.
        assert_eq!(next_free_net(&[net("10.50.4.0/24")], &[], 23), None);
        let full = [net("10.50.4.0/24")];
        assert_eq!(next_free_net(&full, &full, 28), None);
        // Adjacent blocks form one range, as compile sees them.
        let adjacent = [net("10.50.3.0/24"), net("10.50.2.0/24")];
        assert_eq!(next_free_net(&adjacent, &[], 23), Some(net("10.50.2.0/23")));
        assert!(is_inside(net("10.50.2.0/23"), &adjacent));
        // Several blocks: the lowest one wins regardless of order.
        let blocks = [net("10.50.9.0/24"), net("10.50.4.0/24")];
        assert_eq!(next_free_net(&blocks, &[], 26), Some(net("10.50.4.0/26")));
    }

    #[test]
    fn peer_addressing() {
        let n = net("10.50.4.0/29");
        assert_eq!(hub_address(n), Ipv4Addr::new(10, 50, 4, 1));
        assert_eq!(next_peer_ip(n, &[]), Some(Ipv4Addr::new(10, 50, 4, 2)));
        let used: Vec<_> = (2..=5).map(|h| Ipv4Addr::new(10, 50, 4, h)).collect();
        assert_eq!(next_peer_ip(n, &used), Some(Ipv4Addr::new(10, 50, 4, 6)));
        let used: Vec<_> = (2..=6).map(|h| Ipv4Addr::new(10, 50, 4, h)).collect();
        assert_eq!(next_peer_ip(n, &used), None);
        for bad in [0, 1, 7] {
            assert!(!is_peer_ip(n, Ipv4Addr::new(10, 50, 4, bad)), "{bad}");
        }
        assert!(!is_peer_ip(n, Ipv4Addr::new(10, 50, 5, 2)));
        assert!(!is_peer_ip(
            net("10.50.4.0/31"),
            Ipv4Addr::new(10, 50, 4, 1)
        ));
        assert_eq!(next_peer_ip(net("255.255.255.254/31"), &[]), None);
        assert_eq!(next_peer_ip(net("255.255.255.255/32"), &[]), None);
        let top = net("255.255.255.252/30");
        assert_eq!(
            next_peer_ip(top, &[]),
            Some(Ipv4Addr::new(255, 255, 255, 254))
        );
        let tiny = net("10.50.4.0/30");
        assert_eq!(next_peer_ip(tiny, &[]), Some(Ipv4Addr::new(10, 50, 4, 2)));
    }

    #[test]
    fn port_allocation() {
        assert_eq!(next_port(&[]), Some(51800));
        let used: Vec<u16> = (51800..51820).collect();
        assert_eq!(next_port(&used), Some(51821));
        let all: Vec<u16> = PORT_RANGE.collect();
        assert_eq!(next_port(&all), None);
        assert_eq!(PORT_RANGE.filter(|p| *p != RESERVED_PORT).count(), 99);
    }
}
