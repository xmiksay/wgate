//! WireGuard peers: `wg show <if> dump` and the diff against the compiled peers.

use std::collections::HashMap;

use anyhow::{Context, bail};
use ipnet::Ipv4Net;

/// A peer as WireGuard has it: its key and its `AllowedIPs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgPeer {
    pub public_key: String,
    pub allowed: Vec<Ipv4Net>,
}

/// The peers of `wg show <if> dump` (its first line is the interface itself).
pub fn parse_dump(dump: &str) -> anyhow::Result<Vec<WgPeer>> {
    dump.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            let (Some(key), Some(allowed)) = (fields.first(), fields.get(3)) else {
                bail!("unexpected wg dump line: {line}");
            };
            let allowed = match *allowed {
                "(none)" => vec![],
                // Another tool's IPv6 entries are not ours to keep: skipped here, the
                // peer's allowed-ips differ and the next set replaces them.
                list => list
                    .split(',')
                    .filter(|a| !a.contains(':'))
                    .map(|a| {
                        a.parse::<Ipv4Net>()
                            .with_context(|| format!("allowed ip {a}"))
                    })
                    .collect::<anyhow::Result<_>>()?,
            };
            Ok(WgPeer {
                public_key: (*key).to_owned(),
                allowed,
            })
        })
        .collect()
}

/// What to change so the interface has exactly `desired`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PeerDiff {
    /// Keys to remove; applied before `set`, so revocations come first.
    pub remove: Vec<String>,
    /// Peers to add or whose `AllowedIPs` changed.
    pub set: Vec<WgPeer>,
}

pub fn diff(current: &[WgPeer], desired: &[WgPeer]) -> PeerDiff {
    let have: HashMap<&str, Vec<Ipv4Net>> = current
        .iter()
        .map(|p| (p.public_key.as_str(), sorted(&p.allowed)))
        .collect();
    let want: HashMap<&str, &WgPeer> = desired.iter().map(|p| (p.public_key.as_str(), p)).collect();
    let mut remove: Vec<String> = current
        .iter()
        .filter(|p| !want.contains_key(p.public_key.as_str()))
        .map(|p| p.public_key.clone())
        .collect();
    remove.sort();
    let mut set: Vec<WgPeer> = desired
        .iter()
        .filter(|p| have.get(p.public_key.as_str()) != Some(&sorted(&p.allowed)))
        .cloned()
        .collect();
    set.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    PeerDiff { remove, set }
}

fn sorted(nets: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let mut nets = nets.to_vec();
    nets.sort();
    nets
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "KBYZNCjZpIdMSbByMkpfXquYSPRjaE0rXT5NzgGWtXM=\tUmQVw2/HRh5qyJf64Am2w7Ra1R6mY9PaAu1w6F3MQnE=\t51900\toff
HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\t(none)\t(none)\t10.50.0.2/32,fd00::/64,192.168.1.0/24\t0\t0\t0\toff
yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\t(none)\t1.2.3.4:5\t(none)\t0\t0\t0\toff
";

    fn peer(key: &str, allowed: &[&str]) -> WgPeer {
        WgPeer {
            public_key: key.into(),
            allowed: allowed.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn parses_a_dump() {
        assert_eq!(
            parse_dump(DUMP).unwrap(),
            [
                peer(
                    "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
                    &["10.50.0.2/32", "192.168.1.0/24"]
                ),
                peer("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", &[]),
            ]
        );
        assert!(parse_dump("iface\nbroken").is_err());
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
                set: vec![peer("c", &["10.50.0.5/32"])],
            }
        );
        let changed = [peer("a", &["10.50.0.9/32"])];
        assert_eq!(diff(&current[..1], &changed).set, changed);
    }
}
