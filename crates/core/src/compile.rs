//! Desired state → per-peer access sets (design.md → Rights).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::net::{first_overlap, is_peer_ip};
use crate::rights::RuleSet;
use crate::rule::{Rule, Service};

pub type Id = i64;

/// Everything active: disabled tenants, networks and revoked peers are left out by
/// the caller.
#[derive(Clone, Debug, Default)]
pub struct DesiredState {
    pub pool: Vec<Ipv4Net>,
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
    /// Not a peer address of its network (outside it, the hub address, network or
    /// broadcast).
    InvalidIp,
    /// A routed subnet inside the pool.
    RoutedInPool,
    /// Its addresses overlap another peer's.
    Overlap,
}

#[derive(Clone, Debug, Default)]
pub struct Compiled {
    pub peers: Vec<CompiledPeer>,
    pub skipped: Vec<(Id, Problem)>,
}

pub fn compile(state: &DesiredState) -> Compiled {
    let networks: HashMap<Id, &Network> = state.networks.iter().map(|n| (n.id, n)).collect();
    let mut skipped = Vec::new();

    let mut candidates = Vec::new();
    for p in &state.peers {
        let problem = match networks.get(&p.network) {
            None => Some(Problem::UnknownNetwork),
            Some(n) if !is_peer_ip(n.cidr, p.ip) => Some(Problem::InvalidIp),
            Some(_)
                if p.routed
                    .iter()
                    .any(|r| first_overlap(*r, &state.pool).is_some()) =>
            {
                Some(Problem::RoutedInPool)
            }
            Some(_) => None,
        };
        match problem {
            Some(problem) => skipped.push((p.id, problem)),
            None => candidates.push(p),
        }
    }
    let candidate_addrs: Vec<(Id, Vec<Ipv4Net>)> =
        candidates.iter().map(|p| (p.id, addrs(p))).collect();
    let overlapping = overlapping(&candidate_addrs);
    let valid: Vec<&Peer> = candidates
        .into_iter()
        .filter(|p| {
            let bad = overlapping.contains(&p.id);
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
    let tenant_space: Vec<Ipv4Net> = state
        .pool
        .iter()
        .copied()
        .chain(valid.iter().flat_map(|p| p.routed.iter().copied()))
        .collect();
    let tenant_space = RuleSet::everything(&tenant_space);
    let ceilings: HashMap<Id, &RuleSet> =
        state.tenants.iter().map(|t| (t.id, &t.ceiling)).collect();

    // Per network first; every member then only loses its own addresses.
    let mut per_network: HashMap<Id, (RuleSet, RuleSet)> = HashMap::new();
    for n in &state.networks {
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

        let mut inbound = n.inbound.clone();
        for m in &state.networks {
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
                outbound: outbound.difference(&own),
                inbound: inbound.difference(&own),
                addrs,
            })
        })
        .collect();
    Compiled { peers, skipped }
}

fn addrs(p: &Peer) -> Vec<Ipv4Net> {
    std::iter::once(Ipv4Net::from(p.ip))
        .chain(p.routed.iter().copied())
        .collect()
}

/// Ids whose addresses overlap another id's (or each other's).
pub(crate) fn overlapping(items: &[(Id, Vec<Ipv4Net>)]) -> Vec<Id> {
    let mut all: Vec<(Ipv4Net, Id)> = items
        .iter()
        .flat_map(|(id, addrs)| addrs.iter().map(move |a| (*a, *id)))
        .collect();
    all.sort_by_key(|(a, _)| (a.network(), std::cmp::Reverse(a.prefix_len())));
    let mut bad = Vec::new();
    // CIDRs either nest or are disjoint. Sorted by start, widest first, every overlap
    // is a CIDR nested in the last one that was not nested itself.
    let mut outer: Option<(Ipv4Net, Id)> = None;
    for (a, id) in all {
        match outer {
            Some((o, oid)) if o.contains(&a.network()) => bad.extend([oid, id]),
            _ => outer = Some((a, id)),
        }
    }
    bad.sort_unstable();
    bad.dedup();
    bad
}

#[cfg(test)]
mod tests;
