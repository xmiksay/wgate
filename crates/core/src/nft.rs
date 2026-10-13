//! Rendering of `table inet wgate` (design.md → Enforcement on the hub): a base plus
//! one fragment per network, each an `nft -f` transaction of its own.

use std::fmt::Write;

use ipnet::Ipv4Net;

use crate::compile::{Compiled, CompiledNetwork, CompiledPeer, Id};
use crate::rights::{AddrRange, RuleSet, subtract_nets};
use crate::rule::Service;

const TABLE: &str = "inet wgate";
const QUAD: &str = "ipv4_addr . ipv4_addr . inet_proto . inet_service";
const PAIR: &str = "ipv4_addr . ipv4_addr";
/// The dispatch maps and the per-network chain each one jumps to.
const CHAINS: [(&str, &str); 3] = [
    ("ingress", "ingress"),
    ("from_net", "from"),
    ("to_net", "to"),
];
/// A network's sets (`n<id>_<name>`) and their types; created, filled and removed
/// from this one list.
const SETS: [(&str, &str); 5] = [
    ("peers", "ipv4_addr"),
    ("allow", QUAD),
    ("allow_icmp", PAIR),
    ("inbound", QUAD),
    ("inbound_icmp", PAIR),
];

/// The base: global sets, the dispatch maps and the hook chains. Idempotent: it creates
/// what is missing and refills only what it owns, never the networks' map entries, so
/// re-applying it leaves every network's fragment in place.
pub fn render_base(c: &Compiled) -> String {
    let mut out = format!("add table {TABLE}\n");
    let _ = writeln!(
        out,
        "add set {TABLE} tenant_space {{ type ipv4_addr; flags interval; }}"
    );
    let _ = writeln!(out, "add set {TABLE} wg_ifaces {{ type ifname; }}");
    for (map, _) in CHAINS {
        let _ = writeln!(out, "add map {TABLE} {map} {{ type ifname : verdict; }}");
    }
    for (name, spec) in [
        ("prerouting", "type filter hook prerouting priority raw"),
        ("input", "type filter hook input priority filter - 5"),
        ("forward", "type filter hook forward priority filter - 5"),
        ("output", "type filter hook output priority filter - 5"),
        ("postrouting", "type nat hook postrouting priority srcnat"),
    ] {
        let _ = writeln!(out, "add chain {TABLE} {name} {{ {spec}; policy accept; }}");
    }

    let tenant_space: Vec<String> = c.tenant_space.iter().map(|n| range(*n)).collect();
    fill(&mut out, "tenant_space", &tenant_space);
    // Tenant sources are believed only on their own network's interface (each
    // fragment's ingress chain); anywhere else, or from a local socket that is no hub
    // address, they are spoofed. These run before forwarding could answer a spoofed
    // packet with an ICMP error related to the real peer's flow.
    rules(
        &mut out,
        "prerouting",
        &[
            "iifname != \"wg-*\" iifname != \"lo\" ip saddr @tenant_space counter drop",
            "iifname \"wg-*\" iifname != @wg_ifaces counter drop",
            "iifname vmap @ingress",
        ],
    );
    // Every packet from a member passes its network's `from` chain, every packet to a
    // member its network's `to` chain; they `return` when allowed, so device to device
    // passes both. Revocation never depends on conntrack: it only picks the direction.
    rules(&mut out, "input", &["iifname vmap @from_net"]);
    rules(
        &mut out,
        "forward",
        &[
            "oifname \"wg-*\" oifname != @wg_ifaces counter drop",
            "iifname vmap @from_net",
            "oifname vmap @to_net",
        ],
    );
    // No related-ICMP shortcut (ICMP errors can carry payload and match flows that
    // outlive a revocation); only errors the hub itself generates for a tracked flow.
    rules(
        &mut out,
        "output",
        &[
            "ip saddr @tenant_space fib saddr type != local counter drop",
            "oifname \"wg-*\" oifname != @wg_ifaces counter drop",
            "oifname \"wg-*\" ct state related icmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
            "oifname vmap @to_net",
        ],
    );
    out
}

/// SNAT of tenant traffic to the node networks, a transaction of its own: a broken
/// SNAT setting must not hold back the spoof guard and the revocations behind it.
/// Needs the base.
pub fn render_snat(c: &Compiled) -> String {
    let mut out = String::new();
    // Tenant space never needs SNAT, and SNATing hub→peer traffic would break it.
    let nodes = subtract_nets(&c.node_cidrs, &c.tenant_space);
    let snat: Vec<String> = if nodes.is_empty() {
        vec![]
    } else {
        let nodes: Vec<String> = nodes.iter().map(Ipv4Net::to_string).collect();
        vec![format!(
            "ip saddr @tenant_space ip daddr {{ {} }} snat ip to {}",
            nodes.join(", "),
            c.snat_source
        )]
    };
    rules(&mut out, "postrouting", &snat);
    out
}

/// One network's fragment: its sets and chains (created if missing, flushed and
/// refilled) and its interface's entries in the dispatch maps. Needs the base.
pub fn render_network(c: &Compiled, n: &CompiledNetwork) -> String {
    let p = prefix(n.id);
    let mut out = format!("add table {TABLE}\n");
    for (set, ty) in SETS {
        let _ = writeln!(
            out,
            "add set {TABLE} {p}_{set} {{ type {ty}; flags interval; }}"
        );
    }
    for (_, chain) in CHAINS {
        let _ = writeln!(out, "add chain {TABLE} {p}_{chain}");
    }

    let mut sets = Sets::default();
    for peer in c.peers_of(n.id) {
        sets.add(peer);
    }
    let elements = [
        &sets.peers,
        &sets.allow,
        &sets.allow_icmp,
        &sets.inbound,
        &sets.inbound_icmp,
    ];
    for ((set, _), elements) in SETS.iter().zip(elements) {
        fill(&mut out, &format!("{p}_{set}"), elements);
    }

    let fwd = "ip saddr . ip daddr . meta l4proto . th dport";
    let rev = "ip daddr . ip saddr . meta l4proto . th sport";
    let icmp_fwd = "meta l4proto icmp ip saddr . ip daddr";
    let icmp_rev = "meta l4proto icmp ip daddr . ip saddr";
    rules(
        &mut out,
        &format!("{p}_ingress"),
        &[format!("ip saddr != @{p}_peers counter drop")],
    );
    // From a member: what it opens needs its outbound right, what it answers needs the
    // inbound right of whoever opened it (the tuple swapped).
    rules(
        &mut out,
        &format!("{p}_from"),
        &[
            format!("ct direction original {fwd} @{p}_allow return"),
            format!("ct direction original {icmp_fwd} @{p}_allow_icmp return"),
            format!("ct direction reply {rev} @{p}_inbound return"),
            format!("ct direction reply {icmp_rev} @{p}_inbound_icmp return"),
            "counter drop".to_owned(),
        ],
    );
    // To a member: the mirror image.
    rules(
        &mut out,
        &format!("{p}_to"),
        &[
            format!("ct direction original {fwd} @{p}_inbound return"),
            format!("ct direction original {icmp_fwd} @{p}_inbound_icmp return"),
            format!("ct direction reply {rev} @{p}_allow return"),
            format!("ct direction reply {icmp_rev} @{p}_allow_icmp return"),
            "counter drop".to_owned(),
        ],
    );

    let iface = &n.iface;
    let _ = writeln!(out, "add element {TABLE} wg_ifaces {{ \"{iface}\" }}");
    for (map, chain) in CHAINS {
        let _ = writeln!(
            out,
            "add element {TABLE} {map} {{ \"{iface}\" : jump {p}_{chain} }}"
        );
    }
    out
}

/// Takes a network out: its map entries first (a chain still referenced cannot be
/// deleted), then its chains and sets. Each is added before it is deleted, so the
/// transaction also succeeds when some are already gone (nft before 1.0.8 has no
/// `destroy`).
pub fn render_network_removal(id: Id, iface: &str) -> String {
    let p = prefix(id);
    let mut out = ensure_parts(id);
    let _ = writeln!(out, "add element {TABLE} wg_ifaces {{ \"{iface}\" }}");
    for (map, chain) in CHAINS {
        let _ = writeln!(
            out,
            "add element {TABLE} {map} {{ \"{iface}\" : jump {p}_{chain} }}"
        );
    }
    let _ = writeln!(out, "delete element {TABLE} wg_ifaces {{ \"{iface}\" }}");
    for (map, _) in CHAINS {
        let _ = writeln!(out, "delete element {TABLE} {map} {{ \"{iface}\" }}");
    }
    delete_parts(&mut out, id);
    out
}

/// A network's chains and sets alone, for one whose map entries are already gone (a
/// flushed map).
pub fn render_network_purge(id: Id) -> String {
    let mut out = ensure_parts(id);
    delete_parts(&mut out, id);
    out
}

/// Makes a network drop everything (its chains end in `drop`), for one whose
/// unregistration failed: its old rights must not outlive it.
pub fn render_network_cutoff(id: Id) -> String {
    let p = prefix(id);
    let mut out = ensure_parts(id);
    for (_, chain) in CHAINS {
        rules(&mut out, &format!("{p}_{chain}"), &["counter drop"]);
    }
    out
}

/// `add` for a network's chains and sets: a no-op for those that exist.
fn ensure_parts(id: Id) -> String {
    let p = prefix(id);
    let mut out = format!("add table {TABLE}\n");
    for (set, ty) in SETS {
        let _ = writeln!(
            out,
            "add set {TABLE} {p}_{set} {{ type {ty}; flags interval; }}"
        );
    }
    for (_, chain) in CHAINS {
        let _ = writeln!(out, "add chain {TABLE} {p}_{chain}");
    }
    out
}

fn delete_parts(out: &mut String, id: Id) {
    let p = prefix(id);
    for (_, chain) in CHAINS {
        let _ = writeln!(out, "delete chain {TABLE} {p}_{chain}");
    }
    for (set, _) in SETS {
        let _ = writeln!(out, "delete set {TABLE} {p}_{set}");
    }
}

/// The base, SNAT and every network's fragment as one script (tests, a first install).
pub fn render_all(c: &Compiled) -> String {
    let mut out = render_base(c);
    out.push_str(&render_snat(c));
    for n in &c.networks {
        out.push('\n');
        out.push_str(&render_network(c, n));
    }
    out
}

/// The network a per-network chain name (`n<id>_from`, …) belongs to.
pub fn network_of_chain(chain: &str) -> Option<Id> {
    chain.strip_prefix('n')?.split_once('_')?.0.parse().ok()
}

fn prefix(id: Id) -> String {
    format!("n{id}")
}

/// `flush` + refill; nft rejects an empty `add element … { }`.
fn fill(out: &mut String, set: &str, elements: &[String]) {
    let _ = writeln!(out, "flush set {TABLE} {set}");
    if !elements.is_empty() {
        let _ = writeln!(
            out,
            "add element {TABLE} {set} {{\n\t{}\n}}",
            elements.join(",\n\t")
        );
    }
}

fn rules<R: AsRef<str>>(out: &mut String, chain: &str, rules: &[R]) {
    let _ = writeln!(out, "flush chain {TABLE} {chain}");
    for rule in rules {
        let _ = writeln!(out, "add rule {TABLE} {chain} {}", rule.as_ref());
    }
}

/// Set elements, keyed `peer . addr . proto . port` (outbound) and
/// `addr . peer . proto . port` (inbound), so a packet's
/// `saddr . daddr . proto . dport` looks up either set the same way. A router's LAN
/// ranges are keyed like its own address.
#[derive(Default)]
struct Sets {
    peers: Vec<String>,
    allow: Vec<String>,
    allow_icmp: Vec<String>,
    inbound: Vec<String>,
    inbound_icmp: Vec<String>,
}

impl Sets {
    fn add(&mut self, p: &CompiledPeer) {
        let shown = |s: &RuleSet| -> Vec<(Service, String)> {
            s.elements()
                .iter()
                .map(|e| (e.service, e.addrs.to_string()))
                .collect()
        };
        let (outbound, inbound) = (shown(&p.outbound), shown(&p.inbound));
        for own in &p.addrs {
            let own = range(*own);
            self.peers.push(own.clone());
            for (service, addrs) in &outbound {
                push(
                    &mut self.allow,
                    &mut self.allow_icmp,
                    *service,
                    [&own, addrs],
                );
            }
            for (service, addrs) in &inbound {
                push(
                    &mut self.inbound,
                    &mut self.inbound_icmp,
                    *service,
                    [addrs, &own],
                );
            }
        }
    }
}

/// In the same element syntax as `RuleSet` elements.
fn range(net: Ipv4Net) -> String {
    AddrRange::from(net).to_string()
}

/// `saddr . daddr` plus `. proto . port` for tcp/udp, into the matching set.
fn push(quads: &mut Vec<String>, pairs: &mut Vec<String>, service: Service, [s, d]: [&str; 2]) {
    match service {
        Service::Icmp => pairs.push(format!("{s} . {d}")),
        Service::Tcp(p) | Service::Udp(p) => {
            quads.push(format!("{s} . {d} . {} . {p}", service.proto()));
        }
    }
}

#[cfg(test)]
mod tests;
