//! One reconcile: the base, the networks that are gone, what every peer loses, then
//! network by network (an error in one never stops the others).

use std::path::Path;

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{Compiled, CompiledNetwork, Id, render_base, render_network};

use crate::routes;
use crate::runner::Runner;
use crate::wg::{self, PeerDiff};
use crate::{keys, nftmap};

mod gone;
mod steps;

use gone::{interface_key, remove_gone, remove_unregistered};

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
    // A stale base still guards against spoofing when its tenant space covers today's;
    // then only what else it holds (SNAT, …) waits for it.
    let guarded = base.is_ok() || tenant_space_covered(r, c);
    note(base, &mut out.errors);
    let mut links = note(links(r).context("inventory"), &mut out.errors);
    let registered = note(registered(r).context("inventory"), &mut out.errors);
    // A gone network is told from a live one by both inventories, or by its key.
    let blocked = match (&mut links, &registered) {
        (Some(links), Some(registered)) => {
            remove_gone(r, c, keys_dir, registered, links, &mut out.errors)
        }
        _ => vec![],
    };
    if let Some(links) = &mut links {
        remove_unregistered(
            r,
            c,
            keys_dir,
            registered.as_deref(),
            links,
            &mut out.errors,
        );
    }
    let mut owned = vec![];
    let mut new = vec![];
    for n in &c.networks {
        match iface_of(
            r,
            n,
            keys_dir,
            links.as_deref(),
            registered.as_deref(),
            &blocked,
        ) {
            Ok(Iface::Owned) => owned.push(n),
            Ok(Iface::New) => new.push(n),
            Ok(Iface::Unknown) => {}
            Err(why) => out.errors.push(format!("{}: {why}", n.iface)),
        }
    }
    if !guarded {
        // Nothing grows where spoofed sources may not be dropped, and rights revoked
        // inside a fragment wait for the base; peer revocations need none.
        for n in owned {
            let result = peer_diff(r, c, n).and_then(|d| removals(r, n, &d));
            note(
                result.with_context(|| format!("{}: revocations", n.iface)),
                &mut out.errors,
            );
        }
        return out;
    }
    free_ports(r, c, &owned, &mut out.errors);

    let active: Vec<_> = owned
        .into_iter()
        .map(|n| (n, true))
        .chain(new.into_iter().map(|n| (n, false)))
        .map(|(n, exists)| (n, exists, plan(r, c, n, exists)))
        .collect();
    // What anyone loses, in every network, goes before any network grows: an address
    // or LAN moving between peers or networks is never held twice.
    for (n, _, plan) in &active {
        let result = match &plan.peers {
            Ok(d) => removals(r, n, d),
            Err(e) => Err(anyhow::anyhow!("{e:#}")),
        };
        note(
            result.with_context(|| format!("{}: peers", n.iface)),
            &mut out.errors,
        );
        if let Ok((_, del)) = &plan.routes {
            let result = route_commands(r, n, "del", del);
            note(
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

    for link in links.iter().flatten() {
        let known = c.networks.iter().any(|n| n.iface == *link) || blocked.contains(link);
        if link.starts_with("wg-") && !known {
            // Not ours to delete; its traffic is dropped (an unknown wg-*).
            tracing::warn!(%link, "unknown wg- interface left alone");
        }
    }
    out
}

/// Whether the kernel's `tenant_space` (the spoof guard's) covers the compiled one.
fn tenant_space_covered(r: &dyn Runner, c: &Compiled) -> bool {
    r.run(
        &["nft", "-j", "list", "set", "inet", "wgate", "tenant_space"],
        None,
    )
    .and_then(|json| nftmap::parse_ranges(&json))
    .is_ok_and(|ranges| nftmap::covers(&ranges, &c.tenant_space))
}

/// What a compiled network's interface is to the agent.
enum Iface {
    /// It exists and is wgate's: registered for this network, or carrying its hub key
    /// (map entries are lost only with the table, the key stays on the interface).
    Owned,
    /// No link has its name: the agent may create it.
    New,
    /// Without the list of links, a network neither registered nor keyed.
    Unknown,
}

/// Decided once, before anything touches an interface; `Err` is why it is left alone.
fn iface_of(
    r: &dyn Runner,
    n: &CompiledNetwork,
    keys_dir: &Path,
    links: Option<&[String]>,
    registered: Option<&[(String, Id)]>,
    blocked: &[String],
) -> Result<Iface, String> {
    if blocked.contains(&n.iface) {
        return Err("waits for the previous network on it to be removed".into());
    }
    let exists = links.map(|l| l.contains(&n.iface));
    if exists == Some(false) {
        return if link_exists(r, &n.iface) {
            Err("the name is taken by a link that is not WireGuard; left alone".into())
        } else {
            Ok(Iface::New)
        };
    }
    let mine = registered.is_some_and(|reg| reg.iter().any(|(i, id)| *i == n.iface && *id == n.id));
    if mine {
        return Ok(Iface::Owned);
    }
    let key = keys::load(r, keys_dir, &key_name(n)).map_err(|e| format!("hub key: {e:#}"))?;
    let carried =
        key.is_some_and(|(_, public)| interface_key(r, &n.iface).as_deref() == Some(&public));
    match (carried, exists) {
        (true, _) => Ok(Iface::Owned),
        (false, Some(true)) => Err("an interface wgate did not make; left alone".into()),
        (false, _) => Ok(Iface::Unknown),
    }
}

/// Ports can swap: an interface holding the port another network wants lets go of it
/// (it gets its own in its turn). Port 0 is random and can land on a port a later
/// network wants; that network then fails until the next reconcile frees it again.
fn free_ports(r: &dyn Runner, c: &Compiled, owned: &[&CompiledNetwork], errors: &mut Vec<String>) {
    let ports = match r.run(&["wg", "show", "all", "listen-port"], None) {
        Ok(ports) => ports,
        Err(e) => return errors.push(format!("ports: {e:#}")),
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
            && owned.iter().any(|n| n.iface == iface)
            && let Err(e) = run(r, &["wg", "set", iface, "listen-port", "0"])
        {
            errors.push(format!("{iface}: free port: {e:#}"));
        }
    }
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
        note(result.with_context(|| what.to_owned()), &mut errors).is_some()
    };
    // A key is issued only to an interface without one: anything else would rotate a
    // key clients already have.
    let key = match keys::load(r, keys_dir, &key_name(n)) {
        Ok(Some(found)) => Ok(found),
        Ok(None) if !exists || interface_key(r, iface).is_none() => {
            keys::ensure(r, keys_dir, &key_name(n))
        }
        Ok(None) => Err(anyhow::anyhow!(
            "the interface has a key but its file is missing; restore it, or delete the \
             interface to issue a new one"
        )),
        Err(e) => Err(e),
    };
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

/// Records a failure; the value on success.
fn note<T>(result: anyhow::Result<T>, errors: &mut Vec<String>) -> Option<T> {
    result.map_err(|e| errors.push(format!("{e:#}"))).ok()
}

#[cfg(test)]
mod tests;
