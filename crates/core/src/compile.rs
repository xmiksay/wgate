//! Desired state → per-peer access sets (design.md → Rights).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::net::{Slug, first_overlap, hub_address, is_inside, is_peer_ip};
use crate::rights::{RuleSet, merge_nets, subtract_nets};
use crate::rule::{Rule, Service};

pub type Id = i64;

/// Everything active: disabled tenants, networks and revoked peers are left out by
/// the caller.
#[derive(Clone, Debug, Default)]
pub struct DesiredState {
    pub pool: Vec<Ipv4Net>,
    /// Where routed LANs may lie (global admin): private ranges minus the pool and
    /// infrastructure. A LAN becomes tenant space, which the hub drops as a source
    /// on non-wg interfaces, so it must never cover anything else.
    pub routed_space: Vec<Ipv4Net>,
    pub tenants: Vec<Tenant>,
    pub networks: Vec<Network>,
    pub peers: Vec<Peer>,
    pub federations: Vec<Federation>,
}

#[derive(Clone, Debug)]
pub struct Tenant {
    pub id: Id,
    /// External destinations the tenant's networks may be granted (global admin).
    pub ceiling: RuleSet,
}

#[derive(Clone, Debug)]
pub struct Network {
    pub id: Id,
    pub tenant: Id,
    /// The interface is `wg-<slug>`.
    pub slug: Slug,
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
    /// LANs routed behind this peer (a router).
    pub routed: Vec<Ipv4Net>,
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
    /// Its network lies outside the pool, has an unknown tenant or overlaps an older
    /// network.
    InvalidNetwork,
    /// Not a peer address of its network (outside it, the hub address, network or
    /// broadcast).
    InvalidIp,
    /// A routed subnet outside `routed_space` (or inside the pool).
    RoutedNotAllowed,
    /// Its addresses overlap another peer's.
    Overlap,
}

#[derive(Clone, Debug, Default)]
pub struct Compiled {
    pub peers: Vec<CompiledPeer>,
    pub skipped: Vec<(Id, Problem)>,
    /// The pool plus every allowed declared routed LAN (also of skipped routers), merged:
    /// what nft treats as tenant space.
    pub tenant_space: Vec<Ipv4Net>,
}

pub fn compile(state: &DesiredState) -> Compiled {
    // A network outside the pool, with an unknown tenant or overlapping an older one
    // fails closed. Only networks that could be valid compete for addresses, so a bad
    // row cannot knock out a good one.
    let tenants: HashSet<Id> = state.tenants.iter().map(|t| t.id).collect();
    let (eligible, mut invalid): (Vec<&Network>, Vec<&Network>) = state
        .networks
        .iter()
        .partition(|n| is_inside(n.cidr, &state.pool) && tenants.contains(&n.tenant));
    let ranges: Vec<(Id, Vec<Ipv4Net>)> = eligible.iter().map(|n| (n.id, vec![n.cidr])).collect();
    let clashing = conflicting(&ranges);
    let (networks, clashed): (Vec<&Network>, Vec<&Network>) = eligible
        .into_iter()
        .partition(|n| clashing.binary_search(&n.id).is_err());
    invalid.extend(clashed);
    let invalid: HashSet<Id> = invalid.iter().map(|n| n.id).collect();
    let networks: HashMap<Id, &Network> = networks.into_iter().map(|n| (n.id, n)).collect();
    let mut skipped = Vec::new();
    let routable =
        |r: Ipv4Net| is_inside(r, &state.routed_space) && first_overlap(r, &state.pool).is_none();

    let mut candidates = Vec::new();
    for p in &state.peers {
        let problem = match networks.get(&p.network) {
            None if invalid.contains(&p.network) => Some(Problem::InvalidNetwork),
            None => Some(Problem::UnknownNetwork),
            Some(n) if !is_peer_ip(n.cidr, p.ip) => Some(Problem::InvalidIp),
            Some(_) if !p.routed.iter().all(|r| routable(*r)) => Some(Problem::RoutedNotAllowed),
            Some(_) => None,
        };
        match problem {
            Some(problem) => skipped.push((p.id, problem)),
            None => candidates.push(p),
        }
    }
    let candidate_addrs: Vec<(Id, Vec<Ipv4Net>)> =
        candidates.iter().map(|p| (p.id, addrs(p))).collect();
    let conflicts = conflicting(&candidate_addrs);
    let valid: Vec<&Peer> = candidates
        .into_iter()
        .filter(|p| {
            let bad = conflicts.binary_search(&p.id).is_ok();
            if bad {
                skipped.push((p.id, Problem::Overlap));
            }
            !bad
        })
        .collect();

    let mut members: HashMap<Id, Vec<Ipv4Net>> = HashMap::new();
    for p in &valid {
        members.entry(p.network).or_default().extend(addrs(p));
    }
    let empty = Vec::new();
    let members_of = |id: Id| members.get(&id).unwrap_or(&empty);
    // Every declared LAN, also of skipped routers: a conflict must not turn a LAN
    // into an external destination or drop it from the spoof guard.
    let tenant_nets: Vec<Ipv4Net> = state
        .pool
        .iter()
        .copied()
        .chain(
            state
                .peers
                .iter()
                .flat_map(|p| p.routed.iter().copied())
                .filter(|r| routable(*r)),
        )
        .collect();
    let tenant_nets = merge_nets(&tenant_nets);
    let tenant_space = RuleSet::everything(&tenant_nets);
    // Inbound grants are for sources outside tenant space; the only in-pool source
    // that is no peer is a hub address (hub-opened connections).
    let hubs: Vec<Ipv4Net> = networks
        .values()
        .map(|n| Ipv4Net::from(hub_address(n.cidr)))
        .collect();
    let not_grantable = RuleSet::everything(&subtract_nets(&tenant_nets, &hubs));
    let ceilings: HashMap<Id, &RuleSet> =
        state.tenants.iter().map(|t| (t.id, &t.ceiling)).collect();

    // Per network first; every member then only loses its own addresses.
    let mut per_network: HashMap<Id, (RuleSet, RuleSet)> = HashMap::new();
    for n in networks.values() {
        let same_tenant = |id: Id| networks.get(&id).is_some_and(|m| m.tenant == n.tenant);
        let mut outbound = RuleSet::new();
        let mut external = Vec::new();
        for rule in &n.rules {
            match rule {
                NetRule::External(r) => external.push(*r),
                NetRule::To { network, service } if same_tenant(*network) => {
                    outbound = outbound.union(&RuleSet::for_nets(members_of(*network), *service));
                }
                NetRule::To { .. } => {}
            }
        }
        let ceiling = ceilings
            .get(&n.tenant)
            .map_or_else(RuleSet::new, |c| (*c).clone());
        let external = RuleSet::from_rules(&external)
            .intersect(&ceiling)
            .difference(&tenant_space);
        outbound = outbound.union(&external);

        let mut inbound = n.inbound.difference(&not_grantable);
        for m in networks.values() {
            if m.tenant != n.tenant {
                continue;
            }
            for rule in &m.rules {
                if let NetRule::To { network, service } = rule
                    && *network == n.id
                {
                    inbound = inbound.union(&RuleSet::for_nets(members_of(m.id), *service));
                }
            }
        }
        for f in &state.federations {
            if f.from == n.id && networks.contains_key(&f.to) {
                outbound = outbound.union(&RuleSet::for_nets(members_of(f.to), f.service));
            }
            if f.to == n.id && networks.contains_key(&f.from) {
                inbound = inbound.union(&RuleSet::for_nets(members_of(f.from), f.service));
            }
        }
        if n.mesh {
            let all = RuleSet::everything(members_of(n.id));
            outbound = outbound.union(&all);
            inbound = inbound.union(&all);
        }
        per_network.insert(n.id, (outbound, inbound));
    }

    let peers = valid
        .iter()
        .filter_map(|p| {
            let (outbound, inbound) = per_network.get(&p.network)?;
            let addrs = addrs(p);
            let own = RuleSet::everything(&addrs);
            Some(CompiledPeer {
                id: p.id,
                ip: p.ip,
                iface: networks.get(&p.network)?.slug.iface(),
                outbound: outbound.difference(&own),
                inbound: inbound.difference(&own),
                addrs,
            })
        })
        .collect();
    Compiled {
        peers,
        skipped,
        tenant_space: tenant_nets,
    }
}

fn addrs(p: &Peer) -> Vec<Ipv4Net> {
    std::iter::once(Ipv4Net::from(p.ip))
        .chain(p.routed.iter().copied())
        .collect()
}

/// Sorted ids that lose an address conflict. The lowest id keeps its addresses, so
/// a newcomer that overlaps (e.g. another tenant's router claiming the same LAN)
/// fails closed alone instead of knocking out what already works. An item whose own
/// addresses overlap each other always loses.
pub(crate) fn conflicting(items: &[(Id, Vec<Ipv4Net>)]) -> Vec<Id> {
    let mut items: Vec<&(Id, Vec<Ipv4Net>)> = items.iter().collect();
    items.sort_by_key(|(id, _)| *id);
    let mut taken: Vec<Ipv4Net> = Vec::new();
    let mut bad = Vec::new();
    for (id, addrs) in items {
        let clash = addrs.iter().enumerate().any(|(i, a)| {
            first_overlap(*a, &taken).is_some() || first_overlap(*a, &addrs[i + 1..]).is_some()
        });
        if clash {
            bad.push(*id);
        } else {
            taken.extend(addrs);
        }
    }
    bad
}

#[cfg(test)]
mod tests;
