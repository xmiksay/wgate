//! One reconcile: the base, the networks that are gone, then network by network (an
//! error in one never stops the others).

use std::path::Path;

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{
    Compiled, CompiledNetwork, Id, render_base, render_network, render_network_removal,
};

use crate::runner::Runner;
use crate::wg::{self, PeerDiff, WgPeer};
use crate::{keys, nftmap, routes};

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
    let registered = base.and_then(|()| {
        r.run(
            &["nft", "-j", "list", "map", "inet", "wgate", "from_net"],
            None,
        )
        .and_then(|json| nftmap::parse(&json))
        .context("inventory")
    });
    let (mut links, registered) = match (links, registered) {
        (Ok(links), Ok(registered)) => (links, registered),
        (links, registered) => {
            for e in [links.as_ref().err(), registered.as_ref().err()]
                .into_iter()
                .flatten()
            {
                out.errors.push(format!("{e:#}"));
            }
            // Nothing is built or removed without the base and an inventory (a gone
            // network cannot be told from a live one), but revocations need neither.
            revoke_only(r, c, links.ok().as_deref(), &mut out.errors);
            return out;
        }
    };

    // Gone first, matched by interface *and* id, so a new network that reuses a slug
    // starts on a fresh interface (no old addresses). The interface goes before the
    // map entry: deleting it cuts the traffic at once, and the entry stays as the
    // marker that retries a removal that failed halfway. Until then the interface is
    // not reused.
    let mut blocked: Vec<&str> = vec![];
    for (iface, id) in &registered {
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
                out.errors
                    .push(format!("{iface} (removing network {id}): {e:#}"));
                blocked.push(iface);
            }
        }
    }

    // Ports can swap: an interface holding the port another network wants lets go of
    // it (it gets its own in its turn below). Port 0 is random and can land on a port
    // a later network wants; that network then fails until the next reconcile frees
    // it again.
    if let Ok(ports) = r.run(&["wg", "show", "all", "listen-port"], None) {
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
                out.errors.push(format!("{iface}: free port: {e:#}"));
            }
        }
    }

    let mut active = vec![];
    for n in &c.networks {
        if blocked.contains(&n.iface.as_str()) {
            out.errors.push(format!(
                "{}: waits for the previous network on it to be removed",
                n.iface
            ));
        } else {
            let exists = links.contains(&n.iface);
            active.push((n, exists, plan(r, c, n, exists)));
        }
    }
    // Stale LAN routes of every network go before any is added, so a LAN can move
    // from one network to another in one reconcile.
    for (n, _, plan) in &active {
        if let Ok((_, del)) = &plan.routes
            && let Err(e) = route_commands(r, n, "del", del)
        {
            out.errors.push(format!("{}: routes: {e:#}", n.iface));
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

/// Peer removals and narrowings on every compiled network's existing interface (all
/// of them when the interfaces are unknown).
fn revoke_only(r: &dyn Runner, c: &Compiled, links: Option<&[String]>, errors: &mut Vec<String>) {
    for n in &c.networks {
        if links.is_some_and(|l| !l.contains(&n.iface)) {
            continue;
        }
        if let Err(e) = peer_diff(r, c, n).and_then(|d| removals(r, n, &d)) {
            errors.push(format!("{}: revocations: {e:#}", n.iface));
        }
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

/// Brings one network to its compiled state. Every step is attempted even when an
/// earlier one failed. Peers lose what they lose before the nft fragment and gain
/// after it: an address taken over in the same revision is never held under the
/// previous holder's rules. Returns the hub public key (when the key is in place) and
/// the failed steps.
fn network(
    r: &dyn Runner,
    c: &Compiled,
    n: &CompiledNetwork,
    keys_dir: &Path,
    exists: bool,
    plan: Plan,
) -> (Option<String>, Vec<String>) {
    let iface = n.iface.as_str();
    let mut errors = Vec::new();
    let mut step = |what: &str, result: anyhow::Result<()>| {
        if let Err(e) = result {
            errors.push(format!("{what}: {e:#}"));
        }
    };
    if !exists {
        // Registered before it exists: every interface the agent creates is one it
        // finds (and removes) again.
        if let Err(e) = nft(r, &render_network(c, n)) {
            return (None, vec![format!("nft: {e:#}")]);
        }
        step(
            "create",
            run(r, &["ip", "link", "add", iface, "type", "wireguard"]),
        );
    }
    // By network id, not interface: a disabled network keeps its key for when it
    // comes back, and a new network that reuses the slug gets its own.
    let key = keys::ensure(r, keys_dir, &format!("n{}", n.id));
    let address = format!("{}/{}", n.hub, n.cidr.prefix_len());
    step(
        "address",
        run(r, &["ip", "addr", "replace", &address, "dev", iface]),
    );
    let port = n.port.to_string();
    let wg_set = match &key {
        Ok((path, _)) => path
            .to_str()
            .context("key path is not UTF-8")
            .and_then(|path| {
                run(
                    r,
                    &[
                        "wg",
                        "set",
                        iface,
                        "listen-port",
                        &port,
                        "private-key",
                        path,
                    ],
                )
            }),
        Err(e) => Err(anyhow::anyhow!("hub key: {e:#}")),
    };
    step("wg", wg_set);
    step("up", run(r, &["ip", "link", "set", iface, "up"]));
    match &plan.peers {
        Ok(d) => step("peers", removals(r, n, d)),
        Err(e) => step("peers", Err(anyhow::anyhow!("{e:#}"))),
    }
    if exists {
        step("nft", nft(r, &render_network(c, n)));
    }
    if let Ok(d) = &plan.peers {
        step("peers", additions(r, n, d));
    }
    step(
        "routes",
        plan.routes
            .and_then(|(add, _)| route_commands(r, n, "add", &add)),
    );
    (key.ok().map(|(_, public)| public), errors)
}

fn desired_peers(c: &Compiled, n: &CompiledNetwork) -> Vec<WgPeer> {
    c.peers
        .iter()
        .filter(|p| p.network == n.id)
        .map(|p| WgPeer {
            public_key: p.public_key.clone(),
            allowed: p.addrs.clone(),
            foreign: false,
        })
        .collect()
}

fn peer_diff(r: &dyn Runner, c: &Compiled, n: &CompiledNetwork) -> anyhow::Result<PeerDiff> {
    let current = wg::parse_dump(&r.run(&["wg", "show", &n.iface, "dump"], None)?)?;
    Ok(wg::diff(&current, &desired_peers(c, n)))
}

fn removals(r: &dyn Runner, n: &CompiledNetwork, d: &PeerDiff) -> anyhow::Result<()> {
    let iface = n.iface.as_str();
    let remove = d
        .remove
        .iter()
        .map(|key| argv(&["wg", "set", iface, "peer", key, "remove"]));
    let narrow = d.narrow.iter().map(|p| allowed_ips(iface, p));
    all(r, &remove.chain(narrow).collect::<Vec<_>>())
}

fn additions(r: &dyn Runner, n: &CompiledNetwork, d: &PeerDiff) -> anyhow::Result<()> {
    let commands: Vec<_> = d.set.iter().map(|p| allowed_ips(&n.iface, p)).collect();
    all(r, &commands)
}

fn allowed_ips(iface: &str, p: &WgPeer) -> Vec<String> {
    let allowed: Vec<String> = p.allowed.iter().map(Ipv4Net::to_string).collect();
    argv(&[
        "wg",
        "set",
        iface,
        "peer",
        &p.public_key,
        "allowed-ips",
        &allowed.join(","),
    ])
}

/// A router's LANs: its addrs beyond its own /32.
fn lans(c: &Compiled, n: &CompiledNetwork) -> Vec<Ipv4Net> {
    c.peers
        .iter()
        .filter(|p| p.network == n.id)
        .flat_map(|p| {
            p.addrs
                .iter()
                .filter(move |a| **a != Ipv4Net::from(p.ip))
                .copied()
        })
        .collect()
}

/// `add`, not `replace`: a route someone else owns is reported, never taken over.
fn route_commands(
    r: &dyn Runner,
    n: &CompiledNetwork,
    verb: &str,
    lans: &[Ipv4Net],
) -> anyhow::Result<()> {
    let commands: Vec<_> = lans
        .iter()
        .map(|lan| {
            argv(&[
                "ip",
                "route",
                verb,
                &lan.to_string(),
                "dev",
                &n.iface,
                "proto",
                routes::PROTO,
            ])
        })
        .collect();
    all(r, &commands)
}

/// Runs every command, also after one fails (one stuck peer must not keep the other
/// revocations from applying); reports all failures.
fn all(r: &dyn Runner, commands: &[Vec<String>]) -> anyhow::Result<()> {
    let failures: Vec<String> = commands
        .iter()
        .filter_map(|cmd| {
            let argv: Vec<&str> = cmd.iter().map(String::as_str).collect();
            run(r, &argv).err().map(|e| format!("{e:#}"))
        })
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(failures.join("; ")))
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}

fn nft(r: &dyn Runner, script: &str) -> anyhow::Result<()> {
    r.run(&["nft", "-f", "-"], Some(script)).map(drop)
}

fn run(r: &dyn Runner, argv: &[&str]) -> anyhow::Result<()> {
    r.run(argv, None).map(drop)
}

/// The kernel's WireGuard interfaces.
fn links(r: &dyn Runner) -> anyhow::Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Link {
        ifname: String,
    }
    let json = r.run(&["ip", "-j", "link", "show", "type", "wireguard"], None)?;
    let links: Vec<Link> = serde_json::from_str(&json).context("ip -j link")?;
    Ok(links.into_iter().map(|l| l.ifname).collect())
}

#[cfg(test)]
mod tests;
