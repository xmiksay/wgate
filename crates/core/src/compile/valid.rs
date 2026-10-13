//! Which networks and routed LANs of a desired state are valid. Every conflict is
//! resolved the same way: the lowest id keeps what it holds and only newcomers fail
//! closed, so a bad or late row never knocks out one that already works.

use std::collections::{HashMap, HashSet};

use ipnet::Ipv4Net;

use super::{DesiredState, Id, Network};
use crate::net::{MAX_NETWORK_PREFIX, first_overlap, is_inside};
use crate::rights::merge_nets;

/// Valid networks by id, plus the ids of the invalid ones: outside their tenant's
/// (valid) blocks, with an unknown tenant, with host bits, longer than /30, or
/// clashing with an older network's range or interface name.
pub(super) fn networks(state: &DesiredState) -> (HashMap<Id, &Network>, HashSet<Id>) {
    let pool = merge_nets(&state.pool);
    let claims: Vec<(Id, Vec<Ipv4Net>)> = state
        .tenants
        .iter()
        .map(|t| (t.id, t.blocks.clone()))
        .collect();
    let losing_tenants = conflicting(&claims);
    let blocks: HashMap<Id, Vec<Ipv4Net>> = state
        .tenants
        .iter()
        .filter(|t| losing_tenants.binary_search(&t.id).is_err())
        .map(|t| {
            let inside: Vec<Ipv4Net> = t
                .blocks
                .iter()
                .copied()
                .filter(|b| is_inside(*b, &pool))
                .collect();
            (t.id, merge_nets(&inside))
        })
        .collect();

    let (eligible, mut invalid): (Vec<&Network>, Vec<&Network>) =
        state.networks.iter().partition(|n| {
            n.cidr == n.cidr.trunc()
                && n.cidr.prefix_len() <= MAX_NETWORK_PREFIX
                && blocks.get(&n.tenant).is_some_and(|b| is_inside(n.cidr, b))
        });
    let mut by_id = eligible;
    by_id.sort_by_key(|n| n.id);
    let mut slugs = HashSet::new();
    let (eligible, clashed): (Vec<&Network>, Vec<&Network>) = by_id
        .into_iter()
        .partition(|n| slugs.insert(n.slug.as_str()));
    invalid.extend(clashed);

    let ranges: Vec<(Id, Vec<Ipv4Net>)> = eligible.iter().map(|n| (n.id, vec![n.cidr])).collect();
    let clashing = conflicting(&ranges);
    let (valid, clashed): (Vec<&Network>, Vec<&Network>) = eligible
        .into_iter()
        .partition(|n| clashing.binary_search(&n.id).is_err());
    invalid.extend(clashed);
    (
        valid.into_iter().map(|n| (n.id, n)).collect(),
        invalid.iter().map(|n| n.id).collect(),
    )
}

/// Whether a routed LAN is acceptable: a network address, inside `routed_space`,
/// clear of the pool and of reserved infrastructure.
pub(super) fn routable(state: &DesiredState) -> impl Fn(Ipv4Net) -> bool {
    let space = merge_nets(&state.routed_space);
    let forbidden: Vec<Ipv4Net> = state.pool.iter().chain(&state.reserved).copied().collect();
    move |r| r == r.trunc() && is_inside(r, &space) && first_overlap(r, &forbidden).is_none()
}

/// Sorted ids that lose an address conflict: the lowest id keeps its addresses. An
/// item whose own addresses overlap each other always loses.
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
