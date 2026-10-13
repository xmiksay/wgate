//! WireGuard peers: `wg show <if> dump` and the diff against the compiled peers.

use std::collections::HashMap;

use anyhow::{Context, bail};
use ipnet::Ipv4Net;

/// A peer as WireGuard has it: its key and its `AllowedIPs`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WgPeer {
    pub public_key: String,
    pub allowed: Vec<Ipv4Net>,
    /// Entries wgate never sets (IPv6, put there by another tool): always replaced.
    pub foreign: bool,
}

/// The peers of `wg show <if> allowed-ips` (`<key>\t<ip> <ip>…` or `(none)`). Not
/// `dump`: that carries the hub's private key and the peers' preshared keys.
pub fn parse_allowed_ips(out: &str) -> anyhow::Result<Vec<WgPeer>> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let Some((key, allowed)) = line.split_once('\t') else {
                bail!("unexpected wg allowed-ips line: {line}");
            };
            let entries: Vec<&str> = match allowed.trim() {
                "(none)" => vec![],
                list => list.split([' ', ',']).filter(|a| !a.is_empty()).collect(),
            };
            let (v6, v4): (Vec<&str>, Vec<&str>) = entries.iter().partition(|a| a.contains(':'));
            Ok(WgPeer {
                public_key: key.to_owned(),
                allowed: v4
                    .iter()
                    .map(|a| a.parse().with_context(|| format!("allowed ip {a}")))
                    .collect::<anyhow::Result<_>>()?,
                foreign: !v6.is_empty(),
            })
        })
        .collect()
}

/// What to change so the interface has exactly `desired`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PeerDiff {
    /// Keys to remove.
    pub remove: Vec<String>,
    /// Kept peers cut down to what they keep (`allowed` = current ∩ desired); with
    /// `remove`, applied before the network's rules change, so no address is ever
    /// held by a peer the rules no longer give it to.
    pub narrow: Vec<WgPeer>,
    /// Peers to add or whose `AllowedIPs` grow; applied after the rules.
    pub set: Vec<WgPeer>,
}

pub fn diff(current: &[WgPeer], desired: &[WgPeer]) -> PeerDiff {
    let want: HashMap<&str, &WgPeer> = desired.iter().map(|p| (p.public_key.as_str(), p)).collect();
    let have: HashMap<&str, &WgPeer> = current.iter().map(|p| (p.public_key.as_str(), p)).collect();
    let mut d = PeerDiff::default();
    for p in current {
        let Some(w) = want.get(p.public_key.as_str()) else {
            d.remove.push(p.public_key.clone());
            continue;
        };
        if p.foreign || p.allowed.iter().any(|a| !w.allowed.contains(a)) {
            let kept: Vec<Ipv4Net> = p
                .allowed
                .iter()
                .filter(|a| w.allowed.contains(a))
                .copied()
                .collect();
            if kept.is_empty() {
                // Re-added with its new addresses by `set`.
                d.remove.push(p.public_key.clone());
            } else {
                d.narrow.push(WgPeer {
                    allowed: sorted(&kept),
                    ..WgPeer::clone(w)
                });
            }
        }
    }
    for w in desired {
        let narrowed = d.narrow.iter().find(|n| n.public_key == w.public_key);
        let now = match (narrowed, have.get(w.public_key.as_str())) {
            _ if d.remove.contains(&w.public_key) => None,
            (Some(n), _) => Some(n.allowed.clone()),
            (None, Some(h)) => Some(sorted(&h.allowed)),
            (None, None) => None,
        };
        if now != Some(sorted(&w.allowed)) {
            d.set.push(w.clone());
        }
    }
    d.remove.sort();
    d.narrow.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    d.set.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    d
}

fn sorted(nets: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let mut nets = nets.to_vec();
    nets.sort();
    nets
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOWN: &str =
        "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\t10.50.0.2/32 fd00::/64 192.168.1.0/24
yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\t(none)
";

    fn peer(key: &str, allowed: &[&str]) -> WgPeer {
        WgPeer {
            public_key: key.into(),
            allowed: allowed.iter().map(|a| a.parse().unwrap()).collect(),
            foreign: false,
        }
    }

    #[test]
    fn parses_allowed_ips() {
        let mut router = peer(
            "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
            &["10.50.0.2/32", "192.168.1.0/24"],
        );
        router.foreign = true;
        assert_eq!(
            parse_allowed_ips(SHOWN).unwrap(),
            [
                router,
                peer("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", &[])
            ]
        );
        assert!(parse_allowed_ips("broken").is_err());
        assert!(parse_allowed_ips("").unwrap().is_empty());
    }

    #[test]
    fn diff_removes_unknown_and_sets_new_or_changed() {
        let current = [
            peer("a", &["10.50.0.2/32"]),
            peer("b", &["10.50.0.3/32", "192.168.1.0/24"]),
            peer("gone", &["10.50.0.4/32"]),
        ];
        let desired = [
            peer("a", &["10.50.0.2/32"]),
            peer("b", &["192.168.1.0/24", "10.50.0.3/32"]),
            peer("c", &["10.50.0.5/32"]),
        ];
        assert_eq!(
            diff(&current, &desired),
            PeerDiff {
                remove: vec!["gone".into()],
                narrow: vec![],
                set: vec![peer("c", &["10.50.0.5/32"])],
            }
        );
    }

    #[test]
    fn what_a_peer_loses_goes_before_what_it_gains() {
        let current = [
            peer("a", &["10.50.0.2/32", "192.168.1.0/24"]),
            peer("b", &["10.50.0.3/32"]),
        ];
        // a's LAN moves to b; b's address changes entirely.
        let desired = [
            peer("a", &["10.50.0.2/32"]),
            peer("b", &["10.50.0.9/32", "192.168.1.0/24"]),
        ];
        assert_eq!(
            diff(&current, &desired),
            PeerDiff {
                remove: vec!["b".into()],
                narrow: vec![peer("a", &["10.50.0.2/32"])],
                set: vec![peer("b", &["10.50.0.9/32", "192.168.1.0/24"])],
            }
        );
        // Growing needs no narrowing; foreign entries always go.
        let mut foreign = peer("a", &["10.50.0.2/32"]);
        foreign.foreign = true;
        let grown = [peer("a", &["10.50.0.2/32", "192.168.1.0/24"])];
        let d = diff(&[foreign], &grown);
        assert_eq!(d.narrow, [peer("a", &["10.50.0.2/32"])]);
        assert_eq!(d.set, grown);
        assert_eq!(diff(&grown, &grown), PeerDiff::default());
    }
}
