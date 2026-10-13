//! One reconcile: the base, what is gone, what every peer loses, then network by
//! network (an error in one never stops the others).
//!
//! An interface is wgate's when it carries its mark (`wgate:n<id>` in its alias); a
//! network's rights live in `from_net` and the other maps only while its own interface
//! is there or about to be made.

use std::path::Path;

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{
    Compiled, CompiledNetwork, Id, render_base, render_network, render_network_cutoff, render_snat,
    subtract_nets,
};

use crate::keys::Keys;
use crate::nftmap;
use crate::routes;
use crate::runner::Runner;
use crate::wg::{self, PeerDiff};

mod gone;
mod network;
mod steps;

use gone::{remove_gone_links, unregister};
use network::{free_ports, network};
use steps::{
    Link, SCRATCH, current_routes, desired_peers, lans, link_exists, links, nft, peer_diff,
    registered, removals, route_deletions,
};

#[derive(Debug, Default)]
pub struct Outcome {
    /// The hub public key of every network whose key is in place.
    pub hub_keys: Vec<(Id, String)>,
    pub errors: Vec<String>,
}

/// What one network's peers and LAN routes need, read once from the kernel.
struct Plan {
    peers: anyhow::Result<PeerDiff>,
    /// (to add, to delete)
    routes: anyhow::Result<(Vec<Ipv4Net>, Vec<Ipv4Net>)>,
}

const NOT_MADE: &str = "an interface wgate did not make holds the name; left alone";

pub fn reconcile(r: &dyn Runner, c: &Compiled, keys_dir: &Path) -> Outcome {
    let mut out = Outcome::default();
    let keys = &Keys::new(r, keys_dir);
    let base = nft(r, &render_base(c)).context("base");
    // What the spoof guard leaves out: nothing once the base applied. A stale one
    // guards what its tenant space covers; unreadable, it guards nothing known.
    let unguarded = if base.is_ok() {
        Some(vec![])
    } else {
        unguarded_space(r, c)
    };
    let guarded = unguarded.as_ref().is_some_and(Vec::is_empty);
    note(base, &mut out.errors);
    note(nft(r, &render_snat(c)).context("snat"), &mut out.errors);
    let mut links = note(links(r).context("inventory"), &mut out.errors);
    let registry = note(registered(r).context("inventory"), &mut out.errors);
    // Nothing grows where spoofed sources may not be dropped, nor without knowing what
    // is gone, free or registered.
    let grow = guarded && links.is_some() && registry.is_some();
    let registered = registry.unwrap_or_default();
    let gone = match &mut links {
        Some(links) => remove_gone_links(r, c, links, &mut out.errors),
        _ => Default::default(),
    };
    let stuck: Vec<String> = gone.stuck.iter().map(|(name, _)| name.clone()).collect();

    let mut owned = vec![];
    let mut new = vec![];
    let mut unknown = vec![];
    for n in &c.networks {
        match iface_of(r, n, links.as_deref(), &stuck) {
            Ok(Iface::Owned) => owned.push(n),
            Ok(Iface::New) => new.push(n),
            Ok(Iface::Unknown) => unknown.push(n),
            Err(why) => out.errors.push(format!("{}: {why}", n.iface)),
        }
    }

    let active: Vec<_> = owned
        .iter()
        .map(|&n| (n, true))
        .chain(new.iter().filter(|_| grow).map(|&n| (n, false)))
        .map(|(n, exists)| (n, exists, plan(r, c, n, exists)))
        .collect();
    // What anyone loses, in every network, goes before any network's rules change or
    // grow: an address or LAN moving between peers or networks is never held twice.
    // What failed to be released stays held, and is nobody's this pass: no peer, no
    // route and no right takes it.
    let mut held = gone.held;
    for (n, _, plan) in &active {
        let (result, still) = match &plan.peers {
            Ok(d) => removals(r, &n.iface, d),
            // Who holds what on it is unknown: all its peers' addresses are.
            Err(e) => (
                Err(anyhow::anyhow!("{e:#}")),
                c.peers_of(n.id).flat_map(|p| p.addrs.clone()).collect(),
            ),
        };
        held.extend(still);
        note(
            result.with_context(|| format!("{}: peers", n.iface)),
            &mut out.errors,
        );
        let (result, still) = match &plan.routes {
            Ok((_, del)) => route_deletions(r, &n.iface, del),
            Err(e) => (Err(anyhow::anyhow!("{e:#}")), vec![]),
        };
        held.extend(still);
        note(
            result.with_context(|| format!("{}: routes", n.iface)),
            &mut out.errors,
        );
    }

    // With some network's peers or routes unknown, or what a stuck interface keeps,
    // nothing is known to be free.
    let grow = grow
        && !gone.blind
        && active
            .iter()
            .all(|(_, _, plan)| plan.peers.is_ok() && plan.routes.is_ok());
    // A registration stays only for a network compiled on that interface whose own
    // interface is there or about to be made (or that cannot be told, without the
    // links): otherwise nothing on that name keeps its rights.
    // A deleted interface's own pair too: its chains may have outlived its
    // registration (never a scratch one's: it was never registered).
    let extra = gone
        .deleted
        .iter()
        .filter(|(name, _)| !name.starts_with(SCRATCH))
        .filter(|p| !registered.contains(p))
        .cloned();
    for (iface, id) in &registered.iter().cloned().chain(extra).collect::<Vec<_>>() {
        let pair = |n: &&CompiledNetwork| n.iface == *iface && n.id == *id;
        // A network not made this pass keeps no registration.
        let made = new.iter().filter(|_| grow);
        let kept = owned.iter().chain(&unknown).chain(made).any(pair);
        if !kept {
            unregister(r, iface, *id, &mut out.errors);
        }
    }

    if !grow {
        // Rights revoked in a fragment still apply, cut down to what the guard covers;
        // with the guard unknown, every network is cut off. A network whose link could
        // not be read holds all its peers' addresses: who holds what on it is unknown.
        let blind: Vec<Ipv4Net> = unknown
            .iter()
            .flat_map(|n| c.peers_of(n.id).flat_map(|p| p.addrs.clone()))
            .collect();
        let within = unguarded.map(|unguarded| c.within_guard(&[unguarded, held, blind].concat()));
        let existing = active
            .iter()
            .filter(|(_, exists, _)| *exists)
            .map(|(n, _, _)| *n);
        // Without the links, only what is already registered is refreshed: who holds
        // a name not registered yet is unknown.
        let registered_unknown = unknown.iter().copied().filter(|n| {
            registered
                .iter()
                .any(|(i, id)| *i == n.iface && *id == n.id)
        });
        for n in existing.chain(registered_unknown) {
            let script = match &within {
                Some(within) => render_network(within, n),
                None => render_network_cutoff(n.id),
            };
            let result = nft(r, &script);
            note(
                result.with_context(|| format!("{}: nft", n.iface)),
                &mut out.errors,
            );
        }
        warn_unknown(c, links.as_deref());
        return out;
    }
    // Also the ports of gone interfaces that would not go.
    let holders: Vec<&str> = owned
        .iter()
        .map(|n| n.iface.as_str())
        .chain(stuck.iter().map(String::as_str))
        .collect();
    free_ports(r, c, &holders, &mut out.errors);

    let within;
    let rules = if held.is_empty() {
        c
    } else {
        within = c.within_guard(&held);
        &within
    };
    for (n, exists, plan) in active {
        let (key, errors) = network(r, rules, n, keys, exists, plan, &held);
        if let Some(key) = key {
            out.hub_keys.push((n.id, key));
        }
        out.errors
            .extend(errors.into_iter().map(|e| format!("{}: {e}", n.iface)));
    }

    warn_unknown(c, links.as_deref());
    out
}

/// `wg-*` interfaces that are neither wgate's nor a compiled network's name: their
/// traffic is dropped; not ours to delete.
fn warn_unknown(c: &Compiled, links: Option<&[Link]>) {
    for link in links.into_iter().flatten() {
        let known = link.owner.is_some() || c.networks.iter().any(|n| n.iface == link.name);
        if link.name.starts_with("wg-") && !known {
            // Not ours to delete; its traffic is dropped (an unknown wg-*).
            tracing::warn!(link = %link.name, "unknown wg- interface left alone");
        }
    }
}

/// What of the compiled tenant space the kernel's `tenant_space` (the spoof guard's)
/// leaves out; `None` when it cannot be read.
fn unguarded_space(r: &dyn Runner, c: &Compiled) -> Option<Vec<Ipv4Net>> {
    r.run(
        &["nft", "-j", "list", "set", "inet", "wgate", "tenant_space"],
        None,
    )
    .and_then(|json| nftmap::parse_ranges(&json))
    .ok()
    .map(|kernel| subtract_nets(&c.tenant_space, &kernel))
}

/// What a compiled network's interface is to the agent.
enum Iface {
    /// It exists and carries the network's mark.
    Owned,
    /// No link has its name: the agent may make it.
    New,
    /// Its link could not be read.
    Unknown,
}

/// Decided once, from the links read; `Err`
/// is why it is left alone.
fn iface_of(
    r: &dyn Runner,
    n: &CompiledNetwork,
    links: Option<&[Link]>,
    stuck: &[String],
) -> Result<Iface, String> {
    let Some(links) = links else {
        return Ok(Iface::Unknown);
    };
    if stuck.contains(&n.iface) {
        return Err("waits for the gone network's interface to be removed".into());
    }
    match links.iter().find(|l| l.name == n.iface) {
        Some(l) if l.owner == Some(n.id) => Ok(Iface::Owned),
        Some(_) => Err(NOT_MADE.into()),
        None if link_exists(r, &n.iface) => {
            Err("the name is taken by a link that is not WireGuard; left alone".into())
        }
        None => Ok(Iface::New),
    }
}

fn plan(r: &dyn Runner, c: &Compiled, n: &CompiledNetwork, exists: bool) -> Plan {
    if !exists {
        return Plan {
            peers: Ok(wg::diff(&[], &desired_peers(c, n))),
            routes: Ok(routes::diff(&[], &lans(c, n))),
        };
    }
    let routes = current_routes(r, &n.iface).map(|current| routes::diff(&current, &lans(c, n)));
    Plan {
        peers: peer_diff(r, c, n),
        routes,
    }
}

/// Records a failure; the value on success.
fn note<T>(result: anyhow::Result<T>, errors: &mut Vec<String>) -> Option<T> {
    result.map_err(|e| errors.push(format!("{e:#}"))).ok()
}

#[cfg(test)]
mod tests;
