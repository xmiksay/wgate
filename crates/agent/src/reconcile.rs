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
use crate::routes;
use crate::runner::Runner;
use crate::wg::{self, PeerDiff};

mod gone;
mod holdings;
mod network;
mod steps;

use gone::{remove_gone_links, unregister};
use holdings::{Ledger, revoke_all};
use network::{Around, free_ports, network};
use steps::{
    Link, SCRATCH, clear_stray, current_routes, desired_peers, lans, link_exists, links, nft,
    peer_diff, registered, set_ranges,
};

#[derive(Debug, Default)]
pub struct Outcome {
    /// The hub public key of every network whose key is in place.
    pub hub_keys: Vec<(Id, String)>,
    pub errors: Vec<String>,
    /// What stayed held this pass (a failed release, what an unreadable or invalid
    /// network may hold): the next pass still keeps it from others while it cannot see.
    pub held: Vec<Ipv4Net>,
}

/// What one network's peers and LAN routes need, read once from the kernel.
struct Plan {
    peers: anyhow::Result<PeerDiff>,
    /// (to add, to delete)
    routes: anyhow::Result<(Vec<Ipv4Net>, Vec<Ipv4Net>)>,
}

const NOT_MADE: &str = "an interface wgate did not make holds the name; left alone";

/// A reconcile with nothing left held from before (tests).
#[cfg(test)]
pub fn reconcile(r: &dyn Runner, c: &Compiled, keys_dir: &Path) -> Outcome {
    reconcile_after(r, c, keys_dir, &[])
}

/// A reconcile that knows what the previous pass left held.
pub fn reconcile_after(
    r: &dyn Runner,
    c: &Compiled,
    keys_dir: &Path,
    previously_held: &[Ipv4Net],
) -> Outcome {
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
    let steps::Dispatch {
        networks: registered,
        stray,
        entries,
    } = registry.unwrap_or_default();
    // An element that is not wgate's has no place in wgate's table: on a network's
    // name it would keep that network's own entries out, on any other it would let an
    // interface past the dispatch unchecked.
    for (map, iface) in &stray {
        let result = clear_stray(r, map, iface);
        note(
            result.with_context(|| format!("{iface}: element not wgate's")),
            &mut out.errors,
        );
    }
    let gone = match &mut links {
        Some(links) => remove_gone_links(r, c, links, &mut out.errors),
        _ => Default::default(),
    };
    let stuck = gone.stuck.clone();

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
    let mut ledger = Ledger::new(&gone, previously_held);
    // An invalid network keeps its interface as it is (see `remove_gone_links`).
    for link in links.iter().flatten() {
        if link
            .owner
            .is_some_and(|id| c.invalid_networks.contains(&id))
        {
            ledger.kept(r, link);
        }
    }
    let unreadable = revoke_all(r, c, &active, &mut ledger, &mut out.errors);
    let grow = grow && ledger.grows();
    let (unread, active): (Vec<_>, Vec<_>) = active
        .into_iter()
        .filter(|(_, exists, _)| grow || *exists)
        .partition(|(n, _, _)| unreadable.contains(&n.id));
    // Whose peers could not be read: rules that give them nothing (with the guard
    // known; unknown, the kernel is left as it is).
    if let Some(unguarded) = unguarded.as_ref().filter(|_| !unread.is_empty()) {
        let within = c.within_guard(&[unguarded.as_slice(), &ledger.cut_unread()].concat());
        for (n, _, _) in &unread {
            apply_or_cut(r, &within, n, &mut out.errors);
        }
    }

    // A registration stays only for a network compiled on that interface whose own
    // interface is there, about to be made, or cannot be told: otherwise nothing on
    // that name keeps its rights. A deleted interface's own pair too: its chains may
    // have outlived its registration (never a scratch one's: it was never registered).
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
            unregister(r, c, &entries, iface, *id, &mut out.errors);
        }
    }

    if !grow {
        // Rights revoked in a fragment still apply, cut down to what the stale guard
        // covers. With the guard unknown, the kernel is left as it is: the VPN keeps
        // running and revocations wait for a pass that can see.
        if let Some(unguarded) = unguarded {
            let within = c.within_guard(&[unguarded.as_slice(), ledger.cut()].concat());
            for (n, _, _) in &active {
                apply_or_cut(r, &within, n, &mut out.errors);
            }
        }
        warn_unknown(c, links.as_deref());
        out.held = ledger.taken();
        return out;
    }
    // Also the ports of gone interfaces that would not go, and of invalid networks'
    // kept interfaces.
    let invalid_links = links
        .iter()
        .flatten()
        .filter(|l| l.owner.is_some_and(|id| c.invalid_networks.contains(&id)));
    let holders: Vec<&str> = active
        .iter()
        .filter(|(_, exists, _)| *exists)
        .map(|(n, _, _)| n.iface.as_str())
        .chain(stuck.iter().map(String::as_str))
        .chain(invalid_links.map(|l| l.name.as_str()))
        .collect();
    free_ports(r, c, &holders, &mut out.errors);

    let taken = ledger.taken();
    let rules = c.within_guard(ledger.cut());
    let around = Around {
        held: &taken,
        entries: &entries,
    };
    for (n, exists, plan) in active {
        let (key, errors) = network(r, &rules, n, keys, exists, plan, &around);
        if let Some(key) = key {
            out.hub_keys.push((n.id, key));
        }
        out.errors
            .extend(errors.into_iter().map(|e| format!("{}: {e}", n.iface)));
    }

    warn_unknown(c, links.as_deref());
    out.held = taken;
    out
}

/// A network's rules; when they will not go in, the network is cut off: its old rules
/// would keep what was revoked.
fn apply_or_cut(r: &dyn Runner, c: &Compiled, n: &CompiledNetwork, errors: &mut Vec<String>) {
    if let Err(e) = nft(r, &render_network(c, n)) {
        errors.push(format!("{}: nft: {e:#}", n.iface));
        let cut = nft(r, &render_network_cutoff(n.id));
        note(cut.with_context(|| format!("{}: cutoff", n.iface)), errors);
    }
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
    // The rules that use the set must be there too, not only the set.
    let guarding = |chain: &str| {
        r.run(
            &["nft", "-j", "list", "chain", "inet", "wgate", chain],
            None,
        )
        .is_ok_and(|json| json.contains("tenant_space"))
    };
    if !guarding("prerouting") || !guarding("output") {
        return None;
    }
    set_ranges(r, "tenant_space")
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
