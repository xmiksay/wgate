//! Which blocks, networks, peers and routes of a desired state are valid. Every
//! conflict is resolved the same way: the older claim (lower id) keeps what it holds
//! and only the newcomer is dropped, so a bad or late row never knocks out one that
//! already works.

use std::collections::{HashMap, HashSet};

use ipnet::Ipv4Net;

use super::{DesiredState, Id, Network, Peer, Problem};
use crate::net::{
    MAX_NETWORK_PREFIX, PORT_RANGE, RESERVED_PORT, first_overlap, is_inside, is_peer_ip,
};
use crate::rights::RuleSet;
use crate::rights::merge_nets;

/// A network that compiles, with its tenant's ceiling.
pub(super) struct ValidNetwork<'a> {
    pub net: &'a Network,
    pub ceiling: &'a RuleSet,
}

pub(super) struct Networks<'a> {
    pub valid: HashMap<Id, ValidNetwork<'a>>,
    pub invalid: HashSet<Id>,
    /// Blocks that lost (outside the pool, host bits, or an older block's range).
    pub invalid_blocks: Vec<Id>,
}

/// Valid networks: inside their tenant's valid blocks, known tenant, no host bits,
/// at most /30, a listen port in range, and a range, slug and port no older network
/// already holds.
pub(super) fn networks(state: &DesiredState) -> Networks<'_> {
    let ceilings: HashMap<Id, &RuleSet> =
        state.tenants.iter().map(|t| (t.id, &t.ceiling)).collect();
    let pool = merge_nets(&state.pool);
    // Blocks compete one by one, so a single bad block costs only itself.
    let mut blocks: Vec<(Id, Id, Ipv4Net)> = state
        .tenants
        .iter()
        .flat_map(|t| t.blocks.iter().map(move |b| (b.id, t.id, b.cidr)))
        .filter(|(_, _, cidr)| *cidr == cidr.trunc() && is_inside(*cidr, &pool))
        .collect();
    blocks.sort_by_key(|(id, _, _)| *id);
    let mut taken = Vec::new();
    let mut owned: HashMap<Id, Vec<Ipv4Net>> = HashMap::new();
    let mut invalid_blocks: Vec<Id> = state
        .tenants
        .iter()
        .flat_map(|t| &t.blocks)
        .filter(|b| b.cidr != b.cidr.trunc() || !is_inside(b.cidr, &pool))
        .map(|b| b.id)
        .collect();
    for (id, tenant, cidr) in blocks {
        if first_overlap(cidr, &taken).is_none() {
            taken.push(cidr);
            owned.entry(tenant).or_default().push(cidr);
        } else {
            invalid_blocks.push(id);
        }
    }
    invalid_blocks.sort_unstable();
    let owned: HashMap<Id, Vec<Ipv4Net>> = owned
        .into_iter()
        .map(|(t, b)| (t, merge_nets(&b)))
        .collect();

    let mut candidates: Vec<&Network> = state.networks.iter().collect();
    candidates.sort_by_key(|n| n.id);
    let (mut valid, mut invalid) = (HashMap::new(), HashSet::new());
    let (mut ranges, mut slugs, mut ports) = (Vec::new(), HashSet::new(), HashSet::new());
    for n in candidates {
        let ok = n.cidr == n.cidr.trunc()
            && n.cidr.prefix_len() <= MAX_NETWORK_PREFIX
            && owned.get(&n.tenant).is_some_and(|b| is_inside(n.cidr, b))
            && PORT_RANGE.contains(&n.port)
            && n.port != RESERVED_PORT
            && first_overlap(n.cidr, &ranges).is_none()
            && !slugs.contains(n.slug.as_str())
            && !ports.contains(&n.port);
        match ceilings.get(&n.tenant) {
            Some(ceiling) if ok => {
                ranges.push(n.cidr);
                slugs.insert(n.slug.as_str());
                ports.insert(n.port);
                valid.insert(n.id, ValidNetwork { net: n, ceiling });
            }
            _ => {
                invalid.insert(n.id);
            }
        }
    }
    Networks {
        valid,
        invalid,
        invalid_blocks,
    }
}

/// A peer that compiles, with the routes it was granted.
pub(super) struct ValidPeer<'a> {
    pub peer: &'a Peer,
    /// Its accepted routes.
    pub routes: Vec<Ipv4Net>,
    /// `ip/32` plus `routes`.
    pub addrs: Vec<Ipv4Net>,
}

pub(super) struct Peers<'a> {
    pub valid: Vec<ValidPeer<'a>>,
    /// Peers left out entirely, by peer id.
    pub skipped: Vec<(Id, Problem)>,
    /// Routes left out (their peer still compiles), by route id.
    pub dropped_routes: Vec<(Id, Problem)>,
}

pub(super) fn peers<'a>(
    state: &'a DesiredState,
    networks: &HashMap<Id, ValidNetwork<'_>>,
    invalid: &HashSet<Id>,
) -> Peers<'a> {
    let mut out = Peers {
        valid: Vec::new(),
        skipped: Vec::new(),
        dropped_routes: Vec::new(),
    };
    let mut by_id: Vec<&Peer> = state.peers.iter().collect();
    by_id.sort_by_key(|p| p.id);
    let mut ips = HashSet::new();
    // WireGuard keys peers by public key: a second peer with the same key on one
    // interface would take over the first one's addresses.
    let mut keys = HashSet::new();
    let mut accepted = Vec::new();
    for p in by_id {
        let problem = match networks.get(&p.network) {
            None if invalid.contains(&p.network) => Some(Problem::InvalidNetwork),
            None => Some(Problem::UnknownNetwork),
            Some(n) if p.owner_tenant.is_some_and(|t| t != n.net.tenant) => {
                Some(Problem::ForeignDevice)
            }
            Some(n) if !is_peer_ip(n.net.cidr, p.ip) => Some(Problem::InvalidIp),
            // Networks are disjoint, so a duplicate is always an older peer's address.
            Some(_) if !ips.insert(p.ip) => Some(Problem::Overlap),
            Some(_) if !keys.insert((p.network, p.public_key.as_str())) => Some(Problem::Overlap),
            Some(_) => None,
        };
        match problem {
            Some(problem) => out.skipped.push((p.id, problem)),
            None => accepted.push(p),
        }
    }

    // Routes compete by their own id: adding a LAN to an old router cannot take it
    // from the newer router that already routes it. Peer addresses are in the pool
    // and routes never are, so routes only compete with each other.
    let routable = routable(state);
    let mut routes: Vec<(Id, Id, Ipv4Net)> = accepted
        .iter()
        .flat_map(|p| p.routed.iter().map(move |r| (r.id, p.id, r.cidr)))
        .collect();
    routes.sort_by_key(|(id, _, _)| *id);
    let mut taken = Vec::new();
    let mut granted: HashMap<Id, Vec<Ipv4Net>> = HashMap::new();
    for (id, peer, cidr) in routes {
        if !routable(cidr) {
            out.dropped_routes.push((id, Problem::RoutedNotAllowed));
        } else if first_overlap(cidr, &taken).is_some() {
            out.dropped_routes.push((id, Problem::Overlap));
        } else {
            taken.push(cidr);
            granted.entry(peer).or_default().push(cidr);
        }
    }
    out.valid = accepted
        .into_iter()
        .map(|peer| {
            let routes = granted.remove(&peer.id).unwrap_or_default();
            let mut addrs = vec![Ipv4Net::from(peer.ip)];
            addrs.extend(&routes);
            ValidPeer {
                peer,
                routes,
                addrs,
            }
        })
        .collect();
    out
}

/// Whether a routed LAN is acceptable: a network address, inside `routed_space`,
/// clear of the pool and of infrastructure (node networks, the SNAT source,
/// `reserved`).
fn routable(state: &DesiredState) -> impl Fn(Ipv4Net) -> bool {
    let space = merge_nets(&state.routed_space);
    let forbidden: Vec<Ipv4Net> = state
        .pool
        .iter()
        .chain(&state.reserved)
        .chain(&state.node_cidrs)
        .copied()
        .chain([Ipv4Net::from(state.snat_source)])
        .collect();
    move |r| r == r.trunc() && is_inside(r, &space) && first_overlap(r, &forbidden).is_none()
}
