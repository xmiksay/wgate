//! Rendering of `table inet wgate` (design.md → Enforcement on the hub).

use std::fmt::Write;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::compile::{CompiledPeer, Id, conflicting};
use crate::rights::{AddrRange, RuleSet, merge_nets, subtract_nets};
use crate::rule::Service;

#[derive(Clone, Debug)]
pub struct NftState {
    /// Hub address peers are SNATed to towards `node_cidrs`.
    pub snat_source: Ipv4Addr,
    /// Networks whose hosts have no route back to tenant space.
    pub node_cidrs: Vec<Ipv4Net>,
    /// [`crate::Compiled::tenant_space`]: the pool plus every declared routed LAN.
    pub tenant_space: Vec<Ipv4Net>,
    /// From [`crate::compile`]; a missing peer has no access.
    pub peers: Vec<CompiledPeer>,
}

/// The rendered script plus the peers left out of it.
#[derive(Clone, Debug)]
pub struct NftRender {
    pub script: String,
    /// Peers whose addresses overlap an older peer's (compile already drops those;
    /// this guards the transaction, which nft would reject whole, revocations
    /// included).
    pub skipped: Vec<Id>,
}

/// Set elements, keyed `peer . addr . proto . port` (outbound) and
/// `addr . peer . proto . port` (inbound), so a packet's
/// `saddr . daddr . proto . dport` looks up either set the same way. A router's LAN
/// ranges are keyed like its own address.
#[derive(Default)]
struct Sets {
    /// `iface . addr`: the only sources believed on each wg interface.
    ingress: Vec<String>,
    peer_addrs: Vec<String>,
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
            self.ingress.push(format!("\"{}\" . {own}", p.iface));
            self.peer_addrs.push(own.clone());
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
    AddrRange {
        lo: net.network(),
        hi: net.broadcast(),
    }
    .to_string()
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

/// A complete `nft -f` script. It creates the table if missing, then deletes and
/// redefines it, so applying it is one atomic transaction that replaces the whole
/// table whether or not it existed.
pub fn render_nft(state: &NftState) -> NftRender {
    let mut peers: Vec<&CompiledPeer> = state.peers.iter().collect();
    peers.sort_by_key(|p| p.ip);
    let skipped = conflicting(
        &peers
            .iter()
            .map(|p| (p.id, p.addrs.clone()))
            .collect::<Vec<_>>(),
    );
    let mut sets = Sets::default();
    let mut tenant_space = state.tenant_space.clone();
    for p in peers
        .iter()
        .filter(|p| skipped.binary_search(&p.id).is_err())
    {
        sets.add(p);
        // Already in compile's tenant space; repeated in case peers came from elsewhere.
        tenant_space.extend(p.addrs.iter().copied());
    }
    let tenant_space = merge_nets(&tenant_space);

    // Tenant space never needs SNAT, and SNATing hub→peer traffic would break it.
    let node_cidrs = subtract_nets(&state.node_cidrs, &tenant_space);
    let snat = if node_cidrs.is_empty() {
        String::new()
    } else {
        let nodes: Vec<String> = node_cidrs.iter().map(Ipv4Net::to_string).collect();
        format!(
            "\t\tip saddr @peer_addrs ip daddr {{ {} }} snat ip to {}\n",
            nodes.join(", "),
            state.snat_source
        )
    };
    let quad = "ipv4_addr . ipv4_addr . inet_proto . inet_service";
    let pair = "ipv4_addr . ipv4_addr";
    let tenant_space: Vec<String> = tenant_space.into_iter().map(range).collect();
    let sets = [
        set("tenant_space", "ipv4_addr", &tenant_space),
        set("ingress", "ifname . ipv4_addr", &sets.ingress),
        set("peer_addrs", "ipv4_addr", &sets.peer_addrs),
        set("allow", quad, &sets.allow),
        set("allow_icmp", pair, &sets.allow_icmp),
        set("inbound", quad, &sets.inbound),
        set("inbound_icmp", pair, &sets.inbound_icmp),
    ]
    .concat();

    // Revocation must not depend on conntrack, so every packet to or from a peer is
    // checked against the current sets; conntrack only picks *which* check:
    // - from_tenant / to_tenant: whoever opens the connection. A peer opening to
    //   another peer needs both its outbound right and the target's inbound right.
    // - tenant_answers / to_tenant_reply: the same lookups with the tuple swapped.
    // Peer-to-peer is told apart by @peer_addrs, not by tenant space: a network's hub
    // address is tenant space but no peer. A peer's addresses are only believed on
    // its own network's interface (@ingress; WireGuard additionally checks them
    // against the peer's AllowedIPs), so a leftover or misconfigured wg-* interface
    // cannot pose as a peer either. Tenant space arriving on any other interface is
    // spoofed, and the hub itself never sends from a peer address. The ingress checks
    // run in prerouting, before forwarding can answer a spoofed packet with an ICMP
    // error that conntrack would relate to the real peer's flow.
    // There is no related-ICMP shortcut (ICMP errors can carry payload and match
    // flows that outlive a revocation); only ICMP errors the hub itself generates
    // for a tracked flow pass unchecked. Untracked or invalid packets hit the drops.
    let fwd = "ip saddr . ip daddr . meta l4proto . th dport";
    let rev = "ip daddr . ip saddr . meta l4proto . th sport";
    let script = format!(
        "table inet wgate {{}}
delete table inet wgate

table inet wgate {{
{sets}\tchain prerouting {{
\t\ttype filter hook prerouting priority raw; policy accept;
\t\tiifname != \"wg-*\" iifname != \"lo\" ip saddr @tenant_space counter drop
\t\tiifname \"wg-*\" iifname . ip saddr != @ingress counter drop
\t}}

\tchain from_tenant {{
\t\tip daddr @peer_addrs jump tenant_to_tenant
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
\t\tip daddr @peer_addrs jump tenant_answers_tenant
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
\t\tip saddr @peer_addrs counter drop
\t\toifname \"wg-*\" ct state related icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
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
mod tests;
