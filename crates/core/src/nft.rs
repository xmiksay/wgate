//! Rendering of `table inet wgate` (design.md → Enforcement on the hub).

use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::net::TENANT_CIDR;
use crate::rights::RuleSet;
use crate::rule::Proto;

/// A device's address and its effective rights.
#[derive(Clone, Debug)]
pub struct NftDevice {
    pub ip: Ipv4Addr,
    pub rights: RuleSet,
}

#[derive(Clone, Debug)]
pub struct NftState {
    /// Hub address the tenants are SNATed to towards `node_cidrs`.
    pub snat_source: Ipv4Addr,
    /// Networks whose hosts have no route back to the tenant subnets.
    pub node_cidrs: Vec<Ipv4Net>,
    /// Active devices only; a missing device has no access.
    pub devices: Vec<NftDevice>,
}

/// A complete `nft -f` script. It creates the table if missing, then deletes and
/// redefines it, so applying it is one atomic transaction that replaces the whole
/// table whether or not it existed.
pub fn render_nft(state: &NftState) -> String {
    // Merged per address: two entries for one IP would render overlapping elements,
    // and nft would then reject the whole transaction, revocations included.
    let mut by_ip: BTreeMap<Ipv4Addr, RuleSet> = BTreeMap::new();
    for d in &state.devices {
        let rights = by_ip.entry(d.ip).or_default();
        *rights = rights.union(&d.rights);
    }

    let mut allow = Vec::new();
    let mut allow_icmp = Vec::new();
    for (ip, rights) in &by_ip {
        for e in rights.elements() {
            match (e.proto, e.ports) {
                (Proto::Icmp, _) => allow_icmp.push(format!("{ip} . {}", e.dst)),
                (proto, Some(ports)) => {
                    allow.push(format!("{ip} . {} . {proto} . {ports}", e.dst));
                }
                (_, None) => {}
            }
        }
    }

    let mut out = String::from("table inet wgate {}\ndelete table inet wgate\n\n");
    out.push_str("table inet wgate {\n");
    set(
        &mut out,
        "allow",
        "ipv4_addr . ipv4_addr . inet_proto . inet_service",
        &allow,
    );
    set(&mut out, "allow_icmp", "ipv4_addr . ipv4_addr", &allow_icmp);
    // Tenant space is dropped before @allow: a broad rule (e.g. 0.0.0.0/0) must not
    // reach other companies or the hub's tenant addresses, and the accept below
    // would otherwise end the forward chain before its cross-tenant drop.
    //
    // The only conntrack exemptions are reply-direction packets of connections the
    // hub itself or the admin (from wg0) opened towards a tenant. Everything a tenant
    // originates is still filtered per packet, so revoking a rule cuts its open flows.
    let _ = write!(
        out,
        "\tchain tenant {{
\t\tip daddr {TENANT_CIDR} counter drop
\t\tip saddr . ip daddr . meta l4proto . th dport @allow accept"
    );
    out.push_str(
        "
\t\tmeta l4proto icmp ip saddr . ip daddr @allow_icmp accept
\t\tcounter drop
\t}

\tchain input {
\t\ttype filter hook input priority filter - 5; policy accept;
\t\tiifname \"wg-*\" ct direction reply ct state established,related accept
\t\tiifname \"wg-*\" jump tenant
\t}

\tchain forward {
\t\ttype filter hook forward priority filter - 5; policy accept;
\t\tiifname \"wg-*\" oifname \"wg0\" ct direction reply ct state established,related accept
\t\tiifname \"wg-*\" jump tenant
\t\toifname \"wg-*\" iifname \"wg0\" accept
\t\toifname \"wg-*\" ct state established,related accept
\t\toifname \"wg-*\" drop
\t}

\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
",
    );
    if !state.node_cidrs.is_empty() {
        let nodes: Vec<String> = state.node_cidrs.iter().map(Ipv4Net::to_string).collect();
        let _ = writeln!(
            out,
            "\t\tip saddr {TENANT_CIDR} ip daddr {{ {} }} snat ip to {}",
            nodes.join(", "),
            state.snat_source
        );
    }
    out.push_str("\t}\n}\n");
    out
}

fn set(out: &mut String, name: &str, ty: &str, elements: &[String]) {
    let _ = write!(out, "\tset {name} {{\n\t\ttype {ty}\n\t\tflags interval\n");
    // nft rejects an empty `elements = { }`.
    if !elements.is_empty() {
        out.push_str("\t\telements = {\n");
        for (i, e) in elements.iter().enumerate() {
            let sep = if i + 1 < elements.len() { "," } else { "" };
            let _ = writeln!(out, "\t\t\t{e}{sep}");
        }
        out.push_str("\t\t}\n");
    }
    out.push_str("\t}\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{assert_golden, rule_set as rights};

    /// Two companies; overlapping rules on one device must render as disjoint
    /// elements. The netns tests load this exact file into a kernel.
    fn sample() -> NftState {
        NftState {
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: vec!["172.19.9.0/24".parse().unwrap()],
            devices: vec![
                NftDevice {
                    ip: Ipv4Addr::new(10, 50, 2, 2),
                    rights: rights(&["tcp 172.16.16.1/32 6443"]),
                },
                NftDevice {
                    ip: Ipv4Addr::new(10, 50, 1, 2),
                    rights: rights(&[
                        "tcp 172.16.16.1/32 6443",
                        "icmp 172.19.9.10/32",
                        "icmp 172.19.9.11/32",
                        "icmp 172.19.9.12/32",
                        "tcp 10.0.0.0/8 80-90",
                        "tcp 10.1.0.0/16 85-100",
                        "udp 172.19.9.0/24 53",
                    ]),
                },
                NftDevice {
                    ip: Ipv4Addr::new(10, 50, 1, 3),
                    rights: RuleSet::new(),
                },
            ],
        }
    }

    #[test]
    fn ruleset_golden() {
        assert_golden("ruleset.nft", &render_nft(&sample()));
    }

    #[test]
    fn devices_sharing_an_ip_are_merged() {
        let ip = Ipv4Addr::new(10, 50, 1, 2);
        let out = render_nft(&NftState {
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: vec![],
            devices: vec![
                NftDevice {
                    ip,
                    rights: rights(&["tcp 10.0.0.0/8 80-90"]),
                },
                NftDevice {
                    ip,
                    rights: rights(&["tcp 10.1.0.0/16 85-100"]),
                },
            ],
        });
        assert_eq!(out.matches("10.50.1.2 . ").count(), 3);
    }

    #[test]
    fn empty_state_has_no_elements_or_snat() {
        let out = render_nft(&NftState {
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: vec![],
            devices: vec![],
        });
        assert!(!out.contains("elements"));
        assert!(!out.contains("snat"));
        assert!(out.contains("counter drop"));
    }
}
