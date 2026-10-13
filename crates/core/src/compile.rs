//! Desired state → per-peer access sets (design.md → Rights).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::net::{Slug, hub_address};
use crate::rights::{RuleSet, merge_nets, subtract_nets};
use crate::rule::{Rule, Service};

pub type Id = i64;

/// Everything active: disabled tenants, networks and revoked peers are left out by
/// the caller.
#[derive(Clone, Debug)]
pub struct DesiredState {
    pub pool: Vec<Ipv4Net>,
    /// Hub address peers are SNATed to towards `node_cidrs`.
    pub snat_source: Ipv4Addr,
    /// Networks whose hosts have no route back to tenant space (the k8s nodes).
    pub node_cidrs: Vec<Ipv4Net>,
    /// Where routed LANs may lie (global admin): private ranges minus the pool and
    /// infrastructure. A LAN becomes tenant space, which the hub drops as a source
    /// on non-wg interfaces, so it must never cover anything else.
    pub routed_space: Vec<Ipv4Net>,
    /// Further infrastructure no routed LAN may cover (e.g. wg0), on top of
    /// `node_cidrs` and `snat_source`, whatever `routed_space` says.
    pub reserved: Vec<Ipv4Net>,
    pub tenants: Vec<Tenant>,
    pub networks: Vec<Network>,
    pub peers: Vec<Peer>,
    pub federations: Vec<Federation>,
}

#[derive(Clone, Debug)]
pub struct Tenant {
    pub id: Id,
    /// Pool blocks the global admin assigned; the tenant's networks lie inside them.
    pub blocks: Vec<Claim>,
    /// External destinations the tenant's networks may be granted (global admin).
    pub ceiling: RuleSet,
}

#[derive(Clone, Debug)]
pub struct Network {
    pub id: Id,
    pub tenant: Id,
    /// The interface is `wg-<slug>`.
    pub slug: Slug,
    /// Listen port, in `PORT_RANGE` except `RESERVED_PORT`.
    pub port: u16,
    pub cidr: Ipv4Net,
    /// Members reach each other on every service.
    pub mesh: bool,
    /// What members may open (tenant admin).
    pub rules: Vec<NetRule>,
    /// Sources outside the network's tenant that may open to members (global admin
    /// inbound grants; addresses = sources).
    pub inbound: RuleSet,
}

#[derive(Clone, Debug)]
pub enum NetRule {
    /// An external destination, capped by the tenant's ceiling.
    External(Rule),
    /// Another network of the same tenant (or this one).
    To { network: Id, service: Service },
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub id: Id,
    pub network: Id,
    pub ip: Ipv4Addr,
    /// Its WireGuard public key, passed through to the agent.
    pub public_key: String,
    /// The tenant of the device's owner; `None` for a global admin, who may join any
    /// network.
    pub owner_tenant: Option<Id>,
    /// LANs routed behind this peer (a router).
    pub routed: Vec<Claim>,
}

/// An address range somebody claims (a tenant block, a routed LAN). Its id is its
/// claim order: on a conflict the older claim keeps the range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub id: Id,
    pub cidr: Ipv4Net,
}

/// Members of `from` may open to members of `to` (global admin, cross-tenant).
#[derive(Clone, Debug)]
pub struct Federation {
    pub from: Id,
    pub to: Id,
    pub service: Service,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPeer {
    pub id: Id,
    pub ip: Ipv4Addr,
    pub public_key: String,
    /// The interface its packets must arrive on.
    pub iface: String,
    /// `ip/32` plus routed subnets: the hub-side `AllowedIPs`.
    pub addrs: Vec<Ipv4Net>,
    /// What the peer (and its routed LANs) may open; addresses = destinations.
    pub outbound: RuleSet,
    /// Who may open to the peer; addresses = sources.
    pub inbound: RuleSet,
}

/// Why a peer was left out (fail closed; the caller reports it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    UnknownNetwork,
    /// Its network is invalid: outside its tenant's blocks, unknown tenant, host
    /// bits, longer than `MAX_NETWORK_PREFIX`, or its range or slug taken by an older
    /// network (see `valid`).
    InvalidNetwork,
    /// Not a peer address of its network (outside it, the hub address, network or
    /// broadcast).
    InvalidIp,
    /// Its device belongs to another tenant's user: that would be cross-tenant access
    /// without a federation.
    ForeignDevice,
    /// Its address (a peer) or range (a route) is held by an older claim, or a
    /// route overlaps another route of the same peer.
    Overlap,
    /// Its public key is an older active peer's.
    DuplicateKey,
    /// Its public key is not a WireGuard key; the interface would refuse it.
    InvalidKey,
    /// A routed subnet outside `routed_space`, over the pool or reserved
    /// infrastructure, or with host bits.
    RoutedNotAllowed,
}

/// One compile run; render it with [`crate::render_nft`]. Its peers' addresses are
/// disjoint, which nft requires (it rejects overlapping elements, and with them the
/// whole transaction).
#[derive(Clone, Debug)]
pub struct Compiled {
    pub peers: Vec<CompiledPeer>,
    /// Tenant blocks that lost (outside the pool, host bits, an older block's range).
    pub invalid_blocks: Vec<Id>,
    /// Networks that failed validation (their peers are in `skipped`); no interface
    /// may be brought up for them.
    pub invalid_networks: Vec<Id>,
    pub skipped: Vec<(Id, Problem)>,
    /// Routes left out (their peer still compiles), by route claim id.
    pub dropped_routes: Vec<(Id, Problem)>,
    /// The pool plus the routed LANs of compiled peers, merged: what nft treats as
    /// tenant space.
    pub tenant_space: Vec<Ipv4Net>,
    pub snat_source: Ipv4Addr,
    pub node_cidrs: Vec<Ipv4Net>,
}

pub fn compile(state: &DesiredState) -> Compiled {
    let valid::Networks {
        valid: networks,
        invalid,
        invalid_blocks,
    } = valid::networks(state);
    let valid::Peers {
        valid,
        skipped,
        dropped_routes,
    } = valid::peers(state, &networks, &invalid);

    let mut members: HashMap<Id, Vec<Ipv4Net>> = HashMap::new();
    for v in &valid {
        members.entry(v.peer.network).or_default().extend(&v.addrs);
    }
    let empty = Vec::new();
    let members_of = |id: Id| members.get(&id).unwrap_or(&empty);
    // LANs of valid routers only: a rejected or stale row must not change the
    // firewall for everyone, and a router that is down routes nothing anyway.
    let tenant_nets: Vec<Ipv4Net> = state
        .pool
        .iter()
        .copied()
        .chain(valid.iter().flat_map(|v| v.routes.iter().copied()))
        .collect();
    let tenant_nets = merge_nets(&tenant_nets);
    let tenant_space = RuleSet::everything(&tenant_nets);

    // Per network first; every member then only loses its own addresses.
    let mut by_network: HashMap<Id, Vec<valid::ValidPeer>> = HashMap::new();
    for v in valid {
        by_network.entry(v.peer.network).or_default().push(v);
    }
    let mut peers = Vec::new();
    for (&id, n) in &networks {
        let same_tenant = |other: Id| {
            networks
                .get(&other)
                .is_some_and(|m| m.net.tenant == n.net.tenant)
        };
        let mut outbound = RuleSet::new();
        let mut external = Vec::new();
        for rule in &n.net.rules {
            match rule {
                NetRule::External(r) => external.push(*r),
                NetRule::To { network, service } if same_tenant(*network) => {
                    outbound = outbound.union(&RuleSet::for_nets(members_of(*network), *service));
                }
                NetRule::To { .. } => {}
            }
        }
        let external = RuleSet::from_rules(&external)
            .intersect(n.ceiling)
            .difference(&tenant_space);
        outbound = outbound.union(&external);

        // Inbound grants are for sources outside tenant space; the one in-pool source
        // that is no peer is this network's own hub address (hub-opened connections).
        let hub = Ipv4Net::from(hub_address(n.net.cidr));
        let not_grantable = RuleSet::everything(&subtract_nets(&tenant_nets, &[hub]));
        let mut inbound = n.net.inbound.difference(&not_grantable);
        for m in networks.values().filter(|m| m.net.tenant == n.net.tenant) {
            for rule in &m.net.rules {
                if let NetRule::To { network, service } = rule
                    && *network == id
                {
                    inbound = inbound.union(&RuleSet::for_nets(members_of(m.net.id), *service));
                }
            }
        }
        for f in &state.federations {
            if f.from == id && networks.contains_key(&f.to) {
                outbound = outbound.union(&RuleSet::for_nets(members_of(f.to), f.service));
            }
            if f.to == id && networks.contains_key(&f.from) {
                inbound = inbound.union(&RuleSet::for_nets(members_of(f.from), f.service));
            }
        }
        if n.net.mesh {
            let all = RuleSet::everything(members_of(id));
            outbound = outbound.union(&all);
            inbound = inbound.union(&all);
        }
        for v in by_network.remove(&id).unwrap_or_default() {
            let own = RuleSet::everything(&v.addrs);
            peers.push(CompiledPeer {
                id: v.peer.id,
                ip: v.peer.ip,
                public_key: v.peer.public_key.clone(),
                iface: n.net.slug.iface(),
                outbound: outbound.difference(&own),
                inbound: inbound.difference(&own),
                addrs: v.addrs,
            });
        }
    }
    peers.sort_by_key(|p| p.id);
    let mut invalid_networks: Vec<Id> = invalid.into_iter().collect();
    invalid_networks.sort_unstable();
    Compiled {
        peers,
        invalid_blocks,
        invalid_networks,
        skipped,
        dropped_routes,
        tenant_space: tenant_nets,
        snat_source: state.snat_source,
        node_cidrs: state.node_cidrs.clone(),
    }
}

mod valid;

#[cfg(test)]
mod tests;
