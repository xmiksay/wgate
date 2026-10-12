//! Rendering of `table inet wgate` (design.md → Enforcement on the hub).

use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::net::{TENANT_CIDR, is_device_ip};
use crate::rights::{RuleSet, subtract_nets};
use crate::rule::Service;

/// A device's address and its effective access.
#[derive(Clone, Debug)]
pub struct NftDevice {
    pub ip: Ipv4Addr,
    /// What the device may open (addresses = destinations).
    pub outbound: RuleSet,
    /// Who may open connections to the device (addresses = sources, ports = the
    /// device's ports).
    pub inbound: RuleSet,
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

/// Why a device was left out of the ruleset (fail closed; the caller reports it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// Not a `10.50.n.2–254` address of a valid `n`: not SNATed, and it could
    /// shadow a hub address.
    InvalidIp,
    /// Claimed by more than one device. WireGuard routes a /32 to one peer only, so
    /// either device could end up with the other's rights.
    DuplicateIp,
}

/// The rendered script plus the devices left out of it.
#[derive(Clone, Debug)]
pub struct NftRender {
    pub script: String,
    pub skipped: Vec<(Ipv4Addr, Skip)>,
}

/// Set elements, keyed `device . addr . proto . port` (outbound) and
/// `addr . device . proto . port` (inbound), so a packet's
/// `saddr . daddr . proto . dport` looks up either set the same way.
#[derive(Default)]
struct Sets {
    allow: Vec<String>,
    allow_icmp: Vec<String>,
    inbound: Vec<String>,
    inbound_icmp: Vec<String>,
}

impl Sets {
    fn add(&mut self, ip: Ipv4Addr, d: &NftDevice) {
        for e in d.outbound.elements() {
            match e.service {
                Service::Icmp => self.allow_icmp.push(format!("{ip} . {}", e.addrs)),
                Service::Tcp(p) | Service::Udp(p) => {
                    let proto = e.service.proto();
                    self.allow
                        .push(format!("{ip} . {} . {proto} . {p}", e.addrs));
                }
            }
        }
        for e in d.inbound.elements() {
            match e.service {
                Service::Icmp => self.inbound_icmp.push(format!("{} . {ip}", e.addrs)),
                Service::Tcp(p) | Service::Udp(p) => {
                    let proto = e.service.proto();
                    self.inbound
                        .push(format!("{} . {ip} . {proto} . {p}", e.addrs));
                }
            }
        }
    }
}

/// A complete `nft -f` script. It creates the table if missing, then deletes and
/// redefines it, so applying it is one atomic transaction that replaces the whole
/// table whether or not it existed.
pub fn render_nft(state: &NftState) -> NftRender {
    let mut by_ip: BTreeMap<Ipv4Addr, Vec<&NftDevice>> = BTreeMap::new();
    for d in &state.devices {
        by_ip.entry(d.ip).or_default().push(d);
    }

    let mut sets = Sets::default();
    let mut skipped = Vec::new();
    for (&ip, devices) in &by_ip {
        if !is_device_ip(ip) {
            skipped.push((ip, Skip::InvalidIp));
        } else if let [d] = devices.as_slice() {
            sets.add(ip, d);
        } else {
            skipped.push((ip, Skip::DuplicateIp));
        }
    }

    // Tenant space never needs SNAT, and SNATing hub→tenant traffic would break it.
    let node_cidrs = subtract_nets(&state.node_cidrs, &[TENANT_CIDR]);
    let snat = if node_cidrs.is_empty() {
        String::new()
    } else {
        let nodes: Vec<String> = node_cidrs.iter().map(Ipv4Net::to_string).collect();
        format!(
            "\t\tip saddr {TENANT_CIDR} ip daddr {{ {} }} snat ip to {}\n",
            nodes.join(", "),
            state.snat_source
        )
    };
    let quad = "ipv4_addr . ipv4_addr . inet_proto . inet_service";
    let pair = "ipv4_addr . ipv4_addr";
    let sets = [
        set("allow", quad, &sets.allow),
        set("allow_icmp", pair, &sets.allow_icmp),
        set("inbound", quad, &sets.inbound),
        set("inbound_icmp", pair, &sets.inbound_icmp),
    ]
    .concat();

    // Revocation must not depend on conntrack, so every packet to or from a tenant
    // is checked against the current sets; conntrack only picks *which* check:
    // - from_tenant / to_tenant: whoever opens the connection. A tenant opening
    //   into another tenant needs both its outbound right and the target's inbound
    //   grant.
    // - tenant_answers / to_tenant_reply: the same lookups with the tuple swapped.
    // There is no related-ICMP shortcut (ICMP errors can carry payload and match
    // flows that outlive a revocation); only ICMP errors the hub itself generates
    // pass unchecked. Untracked or invalid packets fall through to the drops.
    let fwd = "ip saddr . ip daddr . meta l4proto . th dport";
    let rev = "ip daddr . ip saddr . meta l4proto . th sport";
    let script = format!(
        "table inet wgate {{}}
delete table inet wgate

table inet wgate {{
{sets}\tchain from_tenant {{
\t\tip daddr {TENANT_CIDR} jump tenant_to_tenant
\t\t{fwd} @allow accept
\t\tmeta l4proto icmp ip saddr . ip daddr @allow_icmp accept
\t\tcounter drop
\t}}

\tchain tenant_to_tenant {{
\t\t{fwd} @allow {fwd} @inbound accept
\t\tmeta l4proto icmp ip saddr . ip daddr @allow_icmp ip saddr . ip daddr @inbound_icmp accept
\t\tcounter drop
\t}}

\tchain tenant_answers {{
\t\tip daddr {TENANT_CIDR} jump tenant_answers_tenant
\t\t{rev} @inbound accept
\t\tmeta l4proto icmp ip daddr . ip saddr @inbound_icmp accept
\t\tcounter drop
\t}}

\tchain tenant_answers_tenant {{
\t\t{rev} @allow {rev} @inbound accept
\t\tmeta l4proto icmp ip daddr . ip saddr @allow_icmp ip daddr . ip saddr @inbound_icmp accept
\t\tcounter drop
\t}}

\tchain to_tenant {{
\t\t{fwd} @inbound accept
\t\tmeta l4proto icmp ip saddr . ip daddr @inbound_icmp accept
\t\tcounter drop
\t}}

\tchain to_tenant_reply {{
\t\t{rev} @allow accept
\t\tmeta l4proto icmp ip daddr . ip saddr @allow_icmp accept
\t\tcounter drop
\t}}

\tchain input {{
\t\ttype filter hook input priority filter - 5; policy accept;
\t\tiifname \"wg-*\" ct direction original jump from_tenant
\t\tiifname \"wg-*\" ct direction reply jump tenant_answers
\t\tiifname \"wg-*\" counter drop
\t}}

\tchain output {{
\t\ttype filter hook output priority filter - 5; policy accept;
\t\toifname \"wg-*\" icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
\t\toifname \"wg-*\" ct direction original jump to_tenant
\t\toifname \"wg-*\" ct direction reply jump to_tenant_reply
\t\toifname \"wg-*\" counter drop
\t}}

\tchain forward {{
\t\ttype filter hook forward priority filter - 5; policy accept;
\t\tiifname \"wg-*\" ct direction original jump from_tenant
\t\tiifname \"wg-*\" ct direction reply jump tenant_answers
\t\tiifname \"wg-*\" counter drop
\t\toifname \"wg-*\" ct direction original jump to_tenant
\t\toifname \"wg-*\" ct direction reply jump to_tenant_reply
\t\toifname \"wg-*\" counter drop
\t}}

\tchain postrouting {{
\t\ttype nat hook postrouting priority srcnat; policy accept;
{snat}\t}}
}}
"
    );
    NftRender { script, skipped }
}

fn set(name: &str, ty: &str, elements: &[String]) -> String {
    let mut out = format!("\tset {name} {{\n\t\ttype {ty}\n\t\tflags interval\n");
    // nft rejects an empty `elements = { }`.
    if !elements.is_empty() {
        let _ = write!(
            out,
            "\t\telements = {{\n\t\t\t{}\n\t\t}}\n",
            elements.join(",\n\t\t\t")
        );
    }
    out.push_str("\t}\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{assert_golden, rule_set as rights};

    fn device(ip: [u8; 4], outbound: &[&str], inbound: &[&str]) -> NftDevice {
        NftDevice {
            ip: ip.into(),
            outbound: rights(outbound),
            inbound: rights(inbound),
        }
    }

    fn state(devices: Vec<NftDevice>, node_cidrs: &[&str]) -> NftState {
        NftState {
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: node_cidrs.iter().map(|n| n.parse().unwrap()).collect(),
            devices,
        }
    }

    /// Two companies; overlapping rules on one device must render as disjoint
    /// elements; 10.50.1.2 may SSH into 10.50.2.2 (both sides consent) and a k8s
    /// pod network may reach it on 8080. The netns tests load this exact file.
    fn sample() -> NftState {
        state(
            vec![
                device(
                    [10, 50, 2, 2],
                    &["tcp 172.16.16.1/32 6443"],
                    &["tcp 10.50.1.2/32 22", "tcp 10.244.0.0/16 8080"],
                ),
                device(
                    [10, 50, 1, 2],
                    &[
                        "tcp 172.16.16.1/32 6443",
                        "icmp 172.19.9.10/32",
                        "icmp 172.19.9.11/32",
                        "icmp 172.19.9.12/32",
                        "tcp 10.0.0.0/8 80-90",
                        "tcp 10.1.0.0/16 85-100",
                        "udp 172.19.9.0/24 53",
                        "tcp 10.50.2.0/24 22",
                    ],
                    &[],
                ),
                device([10, 50, 1, 3], &[], &[]),
            ],
            &["172.19.9.0/24"],
        )
    }

    #[test]
    fn ruleset_golden() {
        let out = render_nft(&sample());
        assert!(out.skipped.is_empty());
        assert_golden("ruleset.nft", &out.script);
    }

    #[test]
    fn invalid_and_duplicate_ips_are_left_out() {
        let ssh = &["tcp 10.0.0.0/8 22"][..];
        let out = render_nft(&state(
            vec![
                device([10, 50, 1, 2], ssh, &[]),
                device([10, 50, 1, 2], &["icmp 172.19.9.10/32"], &[]),
                device([10, 50, 1, 3], &["icmp 172.19.9.10/32"], &[]),
                device([10, 49, 0, 2], ssh, &[]),
                device([10, 49, 0, 2], ssh, &[]),
                device([10, 50, 1, 1], ssh, &[]),
            ],
            &[],
        ));
        assert_eq!(
            out.skipped,
            [
                ([10, 49, 0, 2].into(), Skip::InvalidIp),
                ([10, 50, 1, 1].into(), Skip::InvalidIp),
                ([10, 50, 1, 2].into(), Skip::DuplicateIp),
            ]
        );
        for gone in ["10.50.1.2 . ", "10.49.0.2", "10.50.1.1 . "] {
            assert!(!out.script.contains(gone), "{gone}");
        }
        assert!(out.script.contains("10.50.1.3 . "));
    }

    #[test]
    fn node_cidrs_are_merged_without_tenant_space() {
        let out = render_nft(&state(
            vec![],
            &[
                "172.19.9.0/24",
                "172.19.0.0/16",
                "172.19.9.0/24",
                "10.48.0.0/14",
            ],
        ));
        assert!(
            out.script
                .contains("ip daddr { 10.48.0.0/15, 10.51.0.0/16, 172.19.0.0/16 } snat")
        );
    }

    #[test]
    fn empty_state_has_no_elements_or_snat() {
        let out = render_nft(&state(vec![], &[])).script;
        assert!(!out.contains("elements"));
        assert!(!out.contains("snat"));
        assert!(out.contains("counter drop"));
    }
}
