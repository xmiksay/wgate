//! One reconcile: the base, the networks that are gone, then network by network (an
//! error in one never stops the others).

use std::path::Path;

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{
    Compiled, CompiledNetwork, Id, render_base, render_network, render_network_removal,
};

use crate::runner::Runner;
use crate::wg::{self, WgPeer};
use crate::{keys, nftmap, routes};

#[derive(Debug, Default)]
pub struct Outcome {
    /// The hub public key of every network whose key is in place.
    pub hub_keys: Vec<(Id, String)>,
    pub errors: Vec<String>,
}

pub fn reconcile(r: &dyn Runner, c: &Compiled, keys_dir: &Path) -> Outcome {
    let mut out = Outcome::default();
    // Without the base no fragment applies; the kernel keeps what it has.
    if let Err(e) = nft(r, &render_base(c)) {
        out.errors.push(format!("base: {e:#}"));
        return out;
    }
    let registered = r
        .run(
            &["nft", "-j", "list", "map", "inet", "wgate", "from_net"],
            None,
        )
        .and_then(|json| nftmap::parse(&json));
    let links = links(r);
    let (registered, mut links) = match (registered, links) {
        (Ok(registered), Ok(links)) => (registered, links),
        (registered, links) => {
            // Without both, a network that is gone cannot be told from one that is not.
            for e in [
                registered.err(),
                links.as_ref().err().map(|e| anyhow::anyhow!("{e:#}")),
            ]
            .into_iter()
            .flatten()
            {
                out.errors.push(format!("inventory: {e:#}"));
            }
            (vec![], links.unwrap_or_default())
        }
    };

    // Gone first, matched by interface *and* id, so a new network that reuses a slug
    // starts on a fresh interface (no old addresses). The interface goes before the
    // map entry: deleting it cuts the traffic at once, and the entry stays as the
    // marker that retries a removal that failed halfway.
    for (iface, id) in &registered {
        if c.networks.iter().any(|n| n.iface == *iface && n.id == *id) {
            continue;
        }
        let removed = (|| {
            if links.iter().any(|l| l == iface) {
                run(r, &["ip", "link", "del", iface])?;
            }
            nft(r, &render_network_removal(*id, iface))
        })();
        match removed {
            Ok(()) => tracing::info!(%iface, network = id, "network removed"),
            Err(e) => out
                .errors
                .push(format!("{iface} (removing network {id}): {e:#}")),
        }
        links.retain(|l| l != iface);
    }

    // Ports can swap: an interface holding the port another network wants lets go of
    // it (it gets its own in its turn below).
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

    // Stale LAN routes of every network go before any is added, so a LAN can move
    // from one network to another in one reconcile. A new interface has none.
    for n in c.networks.iter().filter(|n| links.contains(&n.iface)) {
        if let Err(e) = lan_routes(r, c, n, Phase::Remove) {
            out.errors.push(format!("{}: routes: {e:#}", n.iface));
        }
    }

    for n in &c.networks {
        let (key, errors) = network(r, c, n, keys_dir, &links);
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Remove,
    Add,
}

/// Brings one network to its compiled state. Every step is attempted even when an
/// earlier one failed. Peers are removed before the nft fragment and added after it:
/// a peer that takes over an address freed in the same revision never meets the
/// previous holder's rules. Returns the hub public key (when the key is in place) and
/// the failed steps.
fn network(
    r: &dyn Runner,
    c: &Compiled,
    n: &CompiledNetwork,
    keys_dir: &Path,
    links: &[String],
) -> (Option<String>, Vec<String>) {
    let iface = n.iface.as_str();
    let mut errors = Vec::new();
    let mut step = |what: &str, result: anyhow::Result<()>| {
        if let Err(e) = result {
            errors.push(format!("{what}: {e:#}"));
        }
    };
    if !links.iter().any(|l| l == iface) {
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
    step("peers", peers(r, c, n, Phase::Remove));
    step("nft", nft(r, &render_network(c, n)));
    step("peers", peers(r, c, n, Phase::Add));
    step("routes", lan_routes(r, c, n, Phase::Add));
    (key.ok().map(|(_, public)| public), errors)
}

fn peers(r: &dyn Runner, c: &Compiled, n: &CompiledNetwork, phase: Phase) -> anyhow::Result<()> {
    let iface = n.iface.as_str();
    let desired: Vec<WgPeer> = c
        .peers
        .iter()
        .filter(|p| p.network == n.id)
        .map(|p| WgPeer {
            public_key: p.public_key.clone(),
            allowed: p.addrs.clone(),
        })
        .collect();
    let current = wg::parse_dump(&r.run(&["wg", "show", iface, "dump"], None)?)?;
    let diff = wg::diff(&current, &desired);
    let commands: Vec<Vec<String>> = match phase {
        Phase::Remove => diff
            .remove
            .iter()
            .map(|key| argv(&["wg", "set", iface, "peer", key, "remove"]))
            .collect(),
        Phase::Add => diff
            .set
            .iter()
            .map(|p| {
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
            })
            .collect(),
    };
    all(r, &commands)
}

/// A router's LANs (its addrs beyond its own /32) are routed via the interface. `add`,
/// not `replace`: a route someone else owns is reported, never taken over.
fn lan_routes(
    r: &dyn Runner,
    c: &Compiled,
    n: &CompiledNetwork,
    phase: Phase,
) -> anyhow::Result<()> {
    let iface = n.iface.as_str();
    let lans: Vec<Ipv4Net> = c
        .peers
        .iter()
        .filter(|p| p.network == n.id)
        .flat_map(|p| {
            p.addrs
                .iter()
                .filter(move |a| **a != Ipv4Net::from(p.ip))
                .copied()
        })
        .collect();
    let current = routes::parse(&r.run(
        &[
            "ip",
            "-j",
            "route",
            "show",
            "dev",
            iface,
            "proto",
            routes::PROTO,
        ],
        None,
    )?)?;
    let (add, del) = routes::diff(&current, &lans);
    let (verb, lans) = match phase {
        Phase::Remove => ("del", del),
        Phase::Add => ("add", add),
    };
    let commands: Vec<Vec<String>> = lans
        .iter()
        .map(|lan| {
            argv(&[
                "ip",
                "route",
                verb,
                &lan.to_string(),
                "dev",
                iface,
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
