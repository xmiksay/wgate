//! One network brought to its compiled state, and what it takes: its hub key, its
//! interface, its port.

use std::path::PathBuf;

use anyhow::Context;
use wgate_core::{Compiled, CompiledNetwork, render_network};

use super::steps::{SCRATCH, additions, nft, owner_mark, route_commands, run};
use super::{Plan, note};
use crate::keys::Keys;
use crate::runner::Runner;

/// Brings one network to its compiled state, after its peers lost what they lose.
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
) -> (Option<String>, Vec<String>) {
    let iface = n.iface.as_str();
    // Before the interface: one that is never keyed must not be left behind.
    let key = hub_key(r, keys, n, exists);
    if !exists {
        if let Err(e) = &key {
            return (None, vec![format!("hub key: {e:#}")]);
        }
        if let Err(e) = create(r, n) {
            return (None, vec![format!("create: {e:#}")]);
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
            step("peers", additions(r, n, d));
        }
        step(
            "routes",
            plan.routes
                .and_then(|(add, _)| route_commands(r, n, "add", &add)),
        );
    } else {
        // Growing on stale rules would hand a new holder its predecessor's rights.
        errors.push("peers and routes: held back until its rules apply".into());
    }
    let key = key.ok().filter(|_| keyed).map(|(_, public)| public);
    (key, errors)
}

/// Made under a scratch name, marked, then renamed: whatever a crash leaves behind is
/// plainly wgate's (and removed as gone).
fn create(r: &dyn Runner, n: &CompiledNetwork) -> anyhow::Result<()> {
    let scratch = format!("{SCRATCH}{}", n.id);
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
    for line in ports.lines() {
        let Some((iface, port)) = line.split_once('\t') else {
            continue;
        };
        if !wanted(iface, port) || !holders.contains(&iface) {
            continue;
        }
        // Port 0 is random and can land on another wanted port: picked again then.
        let mut freed = false;
        for _ in 0..5 {
            if let Err(e) = run(r, &["wg", "set", iface, "listen-port", "0"]) {
                errors.push(format!("{iface}: free port: {e:#}"));
                freed = true;
                break;
            }
            let now = r.run(&["wg", "show", iface, "listen-port"], None);
            if !now.is_ok_and(|now| wanted(iface, &now)) {
                freed = true;
                break;
            }
        }
        if !freed {
            errors.push(format!("{iface}: free port: every pick was a wanted port"));
        }
    }
}
