//! Rendering of `table inet wgate` (design.md → Enforcement on the hub).

use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::net::TENANT_CIDR;
use crate::rights::RuleSet;
use crate::rule::Service;

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

/// The rendered script plus the device addresses left out of it.
#[derive(Clone, Debug)]
pub struct NftRender {
    pub script: String,
    /// Addresses claimed by more than one device. WireGuard routes a /32 to one peer
    /// only, so either device could end up with the other's rights: both are left
    /// out (fail closed) and the caller reports them.
    pub duplicate_ips: Vec<Ipv4Addr>,
}

/// A complete `nft -f` script. It creates the table if missing, then deletes and
/// redefines it, so applying it is one atomic transaction that replaces the whole
/// table whether or not it existed.
pub fn render_nft(state: &NftState) -> NftRender {
    let mut by_ip: BTreeMap<Ipv4Addr, Vec<&RuleSet>> = BTreeMap::new();
    for d in &state.devices {
        by_ip.entry(d.ip).or_default().push(&d.rights);
    }
    // Merged so overlapping or repeated CIDRs cannot make nft reject the set.
    let node_cidrs = Ipv4Net::aggregate(&state.node_cidrs);

    let mut allow = Vec::new();
    let mut allow_icmp = Vec::new();
    let mut duplicate_ips = Vec::new();
    for (ip, rights) in &by_ip {
        let [rights] = rights.as_slice() else {
            duplicate_ips.push(*ip);
            continue;
        };
        for e in rights.elements() {
            match e.service {
                Service::Icmp => allow_icmp.push(format!("{ip} . {}", e.dst)),
                Service::Tcp(ports) | Service::Udp(ports) => {
                    let proto = e.service.proto();
                    allow.push(format!("{ip} . {} . {proto} . {ports}", e.dst));
                }
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
    // Revocation must not depend on conntrack, so @allow is checked on every packet
    // in both directions: `tenant` for what a tenant sends, `tenant_reply` (tuple
    // swapped) for replies coming back to it. Conntrack only decides *which* check
    // applies. Replies a tenant sends to connections the hub or the admin (wg0)
    // opened skip the check; a tenant cannot open those itself. ICMP errors related
    // to a tracked flow pass both ways: they carry no data and PMTU discovery and
    // port-unreachable depend on them.
    let _ = write!(
        out,
        "\tchain tenant {{
\t\tct state related meta l4proto icmp accept
\t\tip daddr {TENANT_CIDR} counter drop
\t\tip saddr . ip daddr . meta l4proto . th dport @allow accept"
    );
    out.push_str(
        "
\t\tmeta l4proto icmp ip saddr . ip daddr @allow_icmp accept
\t\tcounter drop
\t}

\tchain tenant_reply {
\t\tip daddr . ip saddr . meta l4proto . th sport @allow accept
\t\tmeta l4proto icmp ip daddr . ip saddr @allow_icmp accept
\t\tct state related meta l4proto icmp accept
\t\tcounter drop
\t}

\tchain input {
\t\ttype filter hook input priority filter - 5; policy accept;
\t\tiifname \"wg-*\" ct direction reply ct state established accept
\t\tiifname \"wg-*\" jump tenant
\t}

\tchain forward {
\t\ttype filter hook forward priority filter - 5; policy accept;
\t\tiifname \"wg-*\" oifname \"wg0\" ct direction reply ct state established accept
\t\tiifname \"wg-*\" jump tenant
\t\toifname \"wg-*\" iifname \"wg0\" accept
\t\toifname \"wg-*\" ct direction reply ct state established,related jump tenant_reply
\t\toifname \"wg-*\" drop
\t}

\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
",
    );
    if !node_cidrs.is_empty() {
        let nodes: Vec<String> = node_cidrs.iter().map(Ipv4Net::to_string).collect();
        let _ = writeln!(
            out,
            "\t\tip saddr {TENANT_CIDR} ip daddr {{ {} }} snat ip to {}",
            nodes.join(", "),
            state.snat_source
        );
    }
    out.push_str("\t}\n}\n");
    NftRender {
        script: out,
        duplicate_ips,
    }
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
        let out = render_nft(&sample());
        assert!(out.duplicate_ips.is_empty());
        assert_golden("ruleset.nft", &out.script);
    }

    #[test]
    fn devices_sharing_an_ip_are_left_out() {
        let ip = Ipv4Addr::new(10, 50, 1, 2);
        let out = render_nft(&NftState {
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: vec![],
            devices: vec![
                NftDevice {
                    ip,
                    rights: rights(&["tcp 10.0.0.0/8 22"]),
                },
                NftDevice {
                    ip,
                    rights: rights(&["icmp 172.19.9.10/32"]),
                },
                NftDevice {
                    ip: Ipv4Addr::new(10, 50, 1, 3),
                    rights: rights(&["icmp 172.19.9.10/32"]),
                },
            ],
        });
        assert_eq!(out.duplicate_ips, [ip]);
        assert!(!out.script.contains("10.50.1.2 . "));
        assert!(out.script.contains("10.50.1.3 . "));
    }

    #[test]
    fn node_cidrs_are_merged() {
        let out = render_nft(&NftState {
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: [
                "172.19.9.0/24",
                "172.19.0.0/16",
                "172.19.9.0/24",
                "10.0.0.0/8",
            ]
            .iter()
            .map(|n| n.parse().unwrap())
            .collect(),
            devices: vec![],
        });
        assert!(
            out.script
                .contains("ip daddr { 10.0.0.0/8, 172.19.0.0/16 } snat")
        );
    }

    #[test]
    fn empty_state_has_no_elements_or_snat() {
        let out = render_nft(&NftState {
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: vec![],
            devices: vec![],
        })
        .script;
        assert!(!out.contains("elements"));
        assert!(!out.contains("snat"));
        assert!(out.contains("counter drop"));
    }
}
