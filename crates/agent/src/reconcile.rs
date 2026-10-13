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
    Compiled, CompiledNetwork, Id, render_base, render_network, render_snat, subtract_nets,
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
    Link, desired_peers, lans, link_exists, links, links_of, nft, peer_diff, registered, removals,
    route_deletions,
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
    // Without the full list, each network's own interface is read: enough to keep
    // revoking on wgate's, not to tell what is gone or free.
    let (mut links, complete) = match links(r).context("inventory") {
        Ok(links) => (Some(links), true),
        Err(e) => {
            out.errors.push(format!("{e:#}"));
            (links_of(r, c), false)
        }
    };
    let registered = note(registered(r).context("inventory"), &mut out.errors).unwrap_or_default();
    let (stuck, gone_pairs) = match &mut links {
        Some(links) if complete => remove_gone_links(r, c, links, &mut out.errors),
        _ => (vec![], vec![]),
    };

    let mut owned = vec![];
    let mut new = vec![];
    for n in &c.networks {
        match iface_of(r, n, links.as_deref().filter(|_| complete), &stuck) {
            // Read on its own, wgate's interface is managed (revocations included).
            Ok(None)
                if links
                    .iter()
                    .flatten()
                    .any(|l| l.name == n.iface && l.owner == Some(n.id)) =>
            {
                owned.push(n)
            }
            Ok(Some(true)) => owned.push(n),
            Ok(Some(false)) => new.push(n),
            Ok(None) => {}
            Err(why) => out.errors.push(format!("{}: {why}", n.iface)),
        }
    }
    // A registration stays only for a network compiled on that interface whose own
    // interface is there or about to be made (or that cannot be told, without the
    // links): otherwise nothing on that name keeps its rights.
    // A gone interface's own pair too: its chains may have outlived its registration.
    let extra = gone_pairs.into_iter().filter(|p| !registered.contains(p));
    for (iface, id) in &registered.iter().cloned().chain(extra).collect::<Vec<_>>() {
        let pair = |n: &&CompiledNetwork| n.iface == *iface && n.id == *id;
        let kept = if complete {
            owned.iter().chain(&new).any(pair)
        } else {
            c.networks.iter().any(|n| pair(&n))
        };
        if !kept {
            unregister(r, iface, *id, &mut out.errors);
        }
    }

    if !guarded || !complete {
        // Nothing grows where spoofed sources may not be dropped, nor without knowing
        // what is free. Peer and route revocations need neither; rights revoked in a
        // fragment apply with the fragment cut down to what the guard covers.
        let within = unguarded.map(|space| c.within_guard(&space));
        for &n in &owned {
            if let Some(within) = &within {
                let result = nft(r, &render_network(within, n));
                note(
                    result.with_context(|| format!("{}: nft", n.iface)),
                    &mut out.errors,
                );
            }
            let plan = plan(r, c, n, true);
            let peers = plan.peers.and_then(|d| removals(r, &n.iface, &d).0);
            let routes = plan
                .routes
                .and_then(|(_, del)| route_deletions(r, n, &del).0);
            let result = peers.and(routes);
            note(
                result.with_context(|| format!("{}: revocations", n.iface)),
                &mut out.errors,
            );
        }
        return out;
    }
    // Also the ports of gone interfaces that would not go.
    let holders: Vec<&str> = owned
        .iter()
        .map(|n| n.iface.as_str())
        .chain(stuck.iter().map(String::as_str))
        .collect();
    free_ports(r, c, &holders, &mut out.errors);

    let active: Vec<_> = owned
        .into_iter()
        .map(|n| (n, true))
        .chain(new.into_iter().map(|n| (n, false)))
        .map(|(n, exists)| (n, exists, plan(r, c, n, exists)))
        .collect();
    // What anyone loses, in every network, goes before any network grows: an address
    // or LAN moving between peers or networks is never held twice.
    // What failed to be released stays held: nobody else takes it this pass.
    let mut held = vec![];
    for (n, _, plan) in &active {
        let (result, still) = match &plan.peers {
            Ok(d) => removals(r, &n.iface, d),
            Err(e) => (Err(anyhow::anyhow!("{e:#}")), vec![]),
        };
        held.extend(still);
        note(
            result.with_context(|| format!("{}: peers", n.iface)),
            &mut out.errors,
        );
        if let Ok((_, del)) = &plan.routes {
            let (result, still) = route_deletions(r, n, del);
            held.extend(still);
            note(
                result.with_context(|| format!("{}: routes", n.iface)),
                &mut out.errors,
            );
        }
    }
    for (n, exists, plan) in active {
        let (key, errors) = network(r, c, n, keys, exists, plan, &held);
        if let Some(key) = key {
            out.hub_keys.push((n.id, key));
        }
        out.errors
            .extend(errors.into_iter().map(|e| format!("{}: {e}", n.iface)));
    }

    for link in links.iter().flatten() {
        let known = link.owner.is_some() || c.networks.iter().any(|n| n.iface == link.name);
        if link.name.starts_with("wg-") && !known {
            // Not ours to delete; its traffic is dropped (an unknown wg-*).
            tracing::warn!(link = %link.name, "unknown wg- interface left alone");
        }
    }
    out
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

/// Whether the network's interface is wgate's (`Some(true)`) or to be made
/// (`Some(false)`); `None` without the list of links; `Err` is why it is left alone.
fn iface_of(
    r: &dyn Runner,
    n: &CompiledNetwork,
    links: Option<&[Link]>,
    stuck: &[String],
) -> Result<Option<bool>, String> {
    let Some(links) = links else {
        return Ok(None);
    };
    if stuck.contains(&n.iface) {
        return Err("waits for the gone network's interface to be removed".into());
    }
    match links.iter().find(|l| l.name == n.iface) {
        Some(l) if l.owner == Some(n.id) => Ok(Some(true)),
        Some(_) => Err(NOT_MADE.into()),
        None if link_exists(r, &n.iface) => {
            Err("the name is taken by a link that is not WireGuard; left alone".into())
        }
        None => Ok(Some(false)),
    }
}

fn plan(r: &dyn Runner, c: &Compiled, n: &CompiledNetwork, exists: bool) -> Plan {
    if !exists {
        return Plan {
            peers: Ok(wg::diff(&[], &desired_peers(c, n))),
            routes: Ok(routes::diff(&[], &lans(c, n))),
        };
    }
    let routes = r
        .run(
            &[
                "ip",
                "-j",
                "route",
                "show",
                "dev",
                &n.iface,
                "proto",
                routes::PROTO,
            ],
            None,
        )
        .and_then(|json| routes::parse(&json))
        .map(|current| routes::diff(&current, &lans(c, n)));
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
