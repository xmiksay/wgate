//! One network brought to its compiled state, and what it takes: its hub key, its
//! interface, its port.

use std::path::PathBuf;

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{Compiled, CompiledNetwork, PORT_RANGE, render_network, render_network_cutoff};

use super::gone::unregister;
use super::steps::{SCRATCH, additions, nft, owner_mark, route_additions, run};
use super::{Plan, note};
use crate::keys::Keys;
use crate::runner::Runner;

/// Brings one network to its compiled state, after its peers lost what they lose.
/// `c` holds its rights (with what is still held elsewhere left out).
/// Every step is attempted even when an earlier one failed, except the hub key and
/// the interface of a new network. Returns the hub public key (when the interface has
/// it) and the failed steps.
pub(super) fn network(
    r: &dyn Runner,
    c: &Compiled,
    n: &CompiledNetwork,
    keys: &Keys,
    exists: bool,
    plan: Plan,
    held: &[Ipv4Net],
) -> (Option<String>, Vec<String>) {
    let iface = n.iface.as_str();
    // Before the interface: one that is never keyed must not be left behind.
    let key = hub_key(r, keys, n, exists);
    if !exists {
        let made = key
            .as_ref()
            .map(drop)
            .map_err(|e| anyhow::anyhow!("hub key: {e:#}"))
            .and_then(|()| create(r, n).context("create"));
        if let Err(e) = made {
            // Not made: a registration left from before must not stay on the name.
            let mut errors = vec![format!("{e:#}")];
            unregister(r, c, &n.iface, n.id, &mut errors);
            return (None, errors);
        }
    }
    let mut errors = Vec::new();
    let mut step = |what: &str, result: anyhow::Result<()>| {
        note(result.with_context(|| what.to_owned()), &mut errors).is_some()
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
    if step("nft", nft(r, &render_network(c, n))) {
        // A failed read was reported with the removals.
        if let Ok(d) = &plan.peers {
            step("peers", additions(r, n, d, held));
        }
        // A failed read was reported with the deletions.
        if let Ok((add, _)) = plan.routes {
            step("routes", route_additions(r, n, &add, held));
        }
    } else {
        // Growing on stale rules would hand a new holder its predecessor's rights,
        // and keeping them would keep what was revoked: cut off until they apply.
        step("cutoff", nft(r, &render_network_cutoff(n.id)));
        errors.push("peers and routes: held back until its rules apply".into());
    }
    let key = key.ok().filter(|_| keyed).map(|(_, public)| public);
    (key, errors)
}

/// Made under a scratch name, marked, then renamed: whatever a crash leaves behind is
/// plainly wgate's (and removed as gone).
fn create(r: &dyn Runner, n: &CompiledNetwork) -> anyhow::Result<()> {
    let scratch = format!("{SCRATCH}{}", n.id);
    // IFNAMSIZ: 15 characters.
    anyhow::ensure!(
        scratch.len() <= 15,
        "network id {} is too long for an interface name",
        n.id
    );
    run(r, &["ip", "link", "add", &scratch, "type", "wireguard"])?;
    let marked = run(
        r,
        &[
            "ip",
            "link",
            "set",
            "dev",
            &scratch,
            "alias",
            &owner_mark(n.id),
        ],
    )
    .and_then(|()| run(r, &["ip", "link", "set", "dev", &scratch, "name", &n.iface]));
    if marked.is_err() {
        let _ = run(r, &["ip", "link", "del", &scratch]);
    }
    marked
}

/// The network's hub key. One is issued only to an interface known to have none:
/// anything else would rotate a key clients already have.
fn hub_key(
    r: &dyn Runner,
    keys: &Keys,
    n: &CompiledNetwork,
    exists: bool,
) -> anyhow::Result<(PathBuf, String)> {
    if let Some(found) = keys.load(n.id)? {
        return Ok(found);
    }
    if exists
        && interface_key(r, &n.iface)
            .context("the interface's key")?
            .is_some()
    {
        anyhow::bail!(
            "the interface has a key but its file is missing; restore it, or delete the \
             interface to issue a new one"
        );
    }
    keys.ensure(n.id)
}

/// The public key an interface has; `None` when it has none.
fn interface_key(r: &dyn Runner, iface: &str) -> anyhow::Result<Option<String>> {
    let key = r.run(&["wg", "show", iface, "public-key"], None)?;
    let key = key.trim();
    Ok((!key.is_empty() && key != "(none)").then(|| key.to_owned()))
}

/// Where a port another network wants is parked meanwhile: outside `PORT_RANGE`.
const SPARE_PORTS: std::ops::RangeInclusive<u16> = 51900..=51999;
const _: () =
    assert!(*SPARE_PORTS.start() > *PORT_RANGE.end() || *SPARE_PORTS.end() < *PORT_RANGE.start());

/// Ports can swap: an interface of wgate's holding the port another network wants lets
/// go of it (it gets its own in its turn).
pub(super) fn free_ports(r: &dyn Runner, c: &Compiled, holders: &[&str], errors: &mut Vec<String>) {
    let ports = match r.run(&["wg", "show", "all", "listen-port"], None) {
        Ok(ports) => ports,
        Err(e) => return errors.push(format!("ports: {e:#}")),
    };
    let wanted = |iface: &str, port: &str| {
        c.networks
            .iter()
            .any(|n| n.iface != iface && n.port.to_string() == port.trim())
    };
    let mut in_use: Vec<u16> = ports
        .lines()
        .filter_map(|l| l.split_once('\t')?.1.trim().parse().ok())
        .collect();
    for line in ports.lines() {
        let Some((iface, port)) = line.split_once('\t') else {
            continue;
        };
        if !wanted(iface, port) || !holders.contains(&iface) {
            continue;
        }
        // Parked on a spare port no network can want (past PORT_RANGE), the first
        // that nothing listed listens on.
        let parked = SPARE_PORTS
            .filter(|spare| !in_use.contains(spare))
            // Free by the listing: a few tries are plenty, more would only repeat
            // whatever else fails.
            .take(3)
            .find(|spare| run(r, &["wg", "set", iface, "listen-port", &spare.to_string()]).is_ok());
        match parked {
            Some(spare) => in_use.push(spare),
            None => errors.push(format!("{iface}: free port: no spare port is free")),
        }
    }
}
