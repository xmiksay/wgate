//! One reconcile: the base, the networks that are gone, what every peer loses, then
//! network by network (an error in one never stops the others).

use std::path::Path;

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{
    Compiled, CompiledNetwork, Id, render_base, render_network, render_network_removal,
};

use crate::keys;
use crate::routes;
use crate::runner::Runner;
use crate::wg::{self, PeerDiff};

mod steps;

use steps::{
    additions, desired_peers, lans, link_exists, links, nft, peer_diff, registered, removals,
    route_commands, run,
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

pub fn reconcile(r: &dyn Runner, c: &Compiled, keys_dir: &Path) -> Outcome {
    let mut out = Outcome::default();
    let base = nft(r, &render_base(c)).context("base");
    let links = links(r).context("inventory");
    let registered = registered(r).context("inventory");
    let ready = base.is_ok();
    report(base, &mut out.errors);
    let (mut links, registered) = match (links, registered) {
        (Ok(links), Ok(registered)) => (links, registered),
        (links, registered) => {
            let links = links.map_err(|e| out.errors.push(format!("{e:#}"))).ok();
            report(registered.map(drop), &mut out.errors);
            // A gone network cannot be told from a live one, so nothing is built or
            // removed, but peer revocations need no inventory.
            revoke_peers(r, c, links.as_deref(), &mut out.errors);
            return out;
        }
    };
    // Taking a gone network away needs only the inventory.
    let blocked = remove_gone(r, c, &registered, &mut links, &mut out.errors);
    if !ready {
        // A stale base may lack a new block's spoof guard, so nothing is built and
        // no fragment changes; rights revoked inside a fragment wait for the base.
        revoke_peers(r, c, Some(&links), &mut out.errors);
        return out;
    }
    free_ports(r, c, &mut out.errors);

    let mut active = vec![];
    for n in &c.networks {
        let exists = links.contains(&n.iface);
        let mine = registered
            .iter()
            .any(|(i, id)| *i == n.iface && *id == n.id);
        let refused = if blocked.contains(&n.iface) {
            Some("waits for the previous network on it to be removed")
        } else if exists && !mine && !carries_its_key(r, n, keys_dir) {
            // Registered networks lose their map entries only with the table (a
            // flush); their interfaces still carry the network's key.
            Some("an interface wgate did not make; left alone")
        } else if !exists && link_exists(r, &n.iface) {
            Some("the name is taken by a link that is not WireGuard; left alone")
        } else {
            None
        };
        match refused {
            Some(why) => out.errors.push(format!("{}: {why}", n.iface)),
            None => active.push((n, exists, plan(r, c, n, exists))),
        }
    }
    // What anyone loses, in every network, goes before any network grows: an address
    // or LAN moving between peers or networks is never held twice.
    for (n, _, plan) in &active {
        let result = match &plan.peers {
            Ok(d) => removals(r, n, d),
            Err(e) => Err(anyhow::anyhow!("{e:#}")),
        };
        report(
            result.with_context(|| format!("{}: peers", n.iface)),
            &mut out.errors,
        );
        if let Ok((_, del)) = &plan.routes {
            let result = route_commands(r, n, "del", del);
            report(
                result.with_context(|| format!("{}: routes", n.iface)),
                &mut out.errors,
            );
        }
    }
    for (n, exists, plan) in active {
        let (key, errors) = network(r, c, n, keys_dir, exists, plan);
        if let Some(key) = key {
            out.hub_keys.push((n.id, key));
        }
        out.errors
            .extend(errors.into_iter().map(|e| format!("{}: {e}", n.iface)));
    }

    for link in &links {
        let known = c.networks.iter().any(|n| n.iface == *link);
        if link.starts_with("wg-") && !known {
            // Not ours to delete; its traffic is dropped (an unknown wg-*).
            tracing::warn!(%link, "unknown wg- interface left alone");
        }
    }
    out
}

/// Takes away the registered networks that are not compiled under the same interface
/// *and* id, so a new network that reuses a slug starts on a fresh interface. The
/// interface goes before the map entry: deleting it cuts the traffic at once, and the
/// entry stays as the marker that retries a removal that failed halfway. Returns the
/// interfaces whose removal failed: they are not reused until it succeeds.
fn remove_gone(
    r: &dyn Runner,
    c: &Compiled,
    registered: &[(String, Id)],
    links: &mut Vec<String>,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let mut blocked = vec![];
    for (iface, id) in registered {
        if c.networks.iter().any(|n| n.iface == *iface && n.id == *id) {
            continue;
        }
        let removed = if links.contains(iface) {
            run(r, &["ip", "link", "del", iface])
        } else {
            Ok(())
        }
        .map(|()| links.retain(|l| l != iface))
        .and_then(|()| nft(r, &render_network_removal(*id, iface)));
        match removed {
            Ok(()) => tracing::info!(%iface, network = id, "network removed"),
            Err(e) => {
                errors.push(format!("{iface} (removing network {id}): {e:#}"));
                blocked.push(iface.clone());
            }
        }
    }
    blocked
}

/// Ports can swap: an interface holding the port another network wants lets go of it
/// (it gets its own in its turn). Port 0 is random and can land on a port a later
/// network wants; that network then fails until the next reconcile frees it again.
fn free_ports(r: &dyn Runner, c: &Compiled, errors: &mut Vec<String>) {
    let Ok(ports) = r.run(&["wg", "show", "all", "listen-port"], None) else {
        return;
    };
    for line in ports.lines() {
        let Some((iface, port)) = line.split_once('\t') else {
            continue;
        };
        let wanted_elsewhere = c
            .networks
            .iter()
            .any(|n| n.iface != iface && n.port.to_string() == port.trim());
        if wanted_elsewhere
            && c.networks.iter().any(|n| n.iface == iface)
            && let Err(e) = run(r, &["wg", "set", iface, "listen-port", "0"])
        {
            errors.push(format!("{iface}: free port: {e:#}"));
        }
    }
}

/// Peer removals and narrowings on every compiled network's existing interface (all
/// of them when the interfaces are unknown).
fn revoke_peers(r: &dyn Runner, c: &Compiled, links: Option<&[String]>, errors: &mut Vec<String>) {
    for n in &c.networks {
        if links.is_some_and(|l| !l.contains(&n.iface)) {
            continue;
        }
        if let Err(e) = peer_diff(r, c, n).and_then(|d| removals(r, n, &d)) {
            errors.push(format!("{}: revocations: {e:#}", n.iface));
        }
    }
}

/// Whether an existing interface carries the network's hub key (made by wgate, its
/// registration lost).
fn carries_its_key(r: &dyn Runner, n: &CompiledNetwork, keys_dir: &Path) -> bool {
    let Ok((_, public)) = keys::ensure(r, keys_dir, &key_name(n)) else {
        return false;
    };
    r.run(&["wg", "show", &n.iface, "public-key"], None)
        .is_ok_and(|key| key.trim() == public)
}

/// By network id, not interface: a disabled network keeps its key for when it comes
/// back, and a new network that reuses the slug gets its own.
fn key_name(n: &CompiledNetwork) -> String {
    format!("n{}", n.id)
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

/// Brings one network to its compiled state, after its peers lost what they lose.
/// Every step is attempted even when an earlier one failed, except creating the
/// interface. Returns the hub public key (when the interface has it) and the failed
/// steps.
fn network(
    r: &dyn Runner,
    c: &Compiled,
    n: &CompiledNetwork,
    keys_dir: &Path,
    exists: bool,
    plan: Plan,
) -> (Option<String>, Vec<String>) {
    let iface = n.iface.as_str();
    if !exists {
        // Registered before it exists: every interface the agent creates is one it
        // finds (and removes) again.
        if let Err(e) = nft(r, &render_network(c, n)) {
            return (None, vec![format!("nft: {e:#}")]);
        }
        if let Err(e) = run(r, &["ip", "link", "add", iface, "type", "wireguard"]) {
            return (None, vec![format!("create: {e:#}")]);
        }
    }
    let mut errors = Vec::new();
    let mut step = |what: &str, result: anyhow::Result<()>| {
        let ok = result.is_ok();
        if let Err(e) = result {
            errors.push(format!("{what}: {e:#}"));
        }
        ok
    };
    let key = keys::ensure(r, keys_dir, &key_name(n));
    let address = format!("{}/{}", n.hub, n.cidr.prefix_len());
    step(
        "address",
        run(r, &["ip", "addr", "replace", &address, "dev", iface]),
    );
    // Apart from the port: a port someone else holds must not leave it keyless.
    let key_set = match &key {
        Ok((path, _)) => path
            .to_str()
            .context("key path is not UTF-8")
            .and_then(|path| run(r, &["wg", "set", iface, "private-key", path])),
        Err(e) => Err(anyhow::anyhow!("{e:#}")),
    };
    let keyed = step("hub key", key_set);
    let port = n.port.to_string();
    step("port", run(r, &["wg", "set", iface, "listen-port", &port]));
    step("up", run(r, &["ip", "link", "set", iface, "up"]));
    if exists {
        step("nft", nft(r, &render_network(c, n)));
    }
    // A failed read was reported with the removals.
    if let Ok(d) = &plan.peers {
        step("peers", additions(r, n, d));
    }
    step(
        "routes",
        plan.routes
            .and_then(|(add, _)| route_commands(r, n, "add", &add)),
    );
    let key = key.ok().filter(|_| keyed).map(|(_, public)| public);
    (key, errors)
}

fn report(result: anyhow::Result<()>, errors: &mut Vec<String>) {
    if let Err(e) = result {
        errors.push(format!("{e:#}"));
    }
}

#[cfg(test)]
mod tests;
