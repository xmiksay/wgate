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
        .and_then(|json| nftmap::parse(&json))
        .unwrap_or_else(|e| {
            out.errors.push(format!("registered networks: {e:#}"));
            vec![]
        });
    let mut links = links(r).unwrap_or_else(|e| {
        out.errors.push(format!("links: {e:#}"));
        vec![]
    });

    // Gone first, matched by interface *and* id: a new network that reuses a slug must
    // not inherit the old one's chains, addresses or key.
    for (iface, id) in &registered {
        if c.networks.iter().any(|n| n.iface == *iface && n.id == *id) {
            continue;
        }
        match remove(r, *id, iface, &links, keys_dir) {
            Ok(()) => {
                links.retain(|l| l != iface);
                tracing::info!(%iface, network = id, "network removed");
            }
            Err(e) => out
                .errors
                .push(format!("{iface} (removing network {id}): {e:#}")),
        }
    }

    // A network whose port changes first lets go of its old one, so two networks can
    // swap ports.
    if let Ok(ports) = r.run(&["wg", "show", "all", "listen-port"], None) {
        for n in &c.networks {
            let current = ports
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{}\t", n.iface)));
            if current.is_some_and(|p| p.trim() != n.port.to_string())
                && let Err(e) = r.run(&["wg", "set", &n.iface, "listen-port", "0"], None)
            {
                out.errors.push(format!("{}: free port: {e:#}", n.iface));
            }
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

/// Brings one network to its compiled state. Every step is attempted even when an
/// earlier one failed: above all the nft fragment, which carries every revocation of a
/// right and must never wait for an unrelated error. Returns the hub public key (when
/// the key is in place) and the failed steps.
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
    let key = keys::ensure(r, keys_dir, iface);
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
    step("peers", peers(r, c, n));
    step("routes", lan_routes(r, c, n));
    step("nft", nft(r, &render_network(c, n)));
    (key.ok().map(|(_, public)| public), errors)
}

/// Removals first, then additions and changes.
fn peers(r: &dyn Runner, c: &Compiled, n: &CompiledNetwork) -> anyhow::Result<()> {
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
    for key in &diff.remove {
        run(r, &["wg", "set", iface, "peer", key, "remove"])?;
    }
    for p in &diff.set {
        let allowed: Vec<String> = p.allowed.iter().map(Ipv4Net::to_string).collect();
        run(
            r,
            &[
                "wg",
                "set",
                iface,
                "peer",
                &p.public_key,
                "allowed-ips",
                &allowed.join(","),
            ],
        )?;
    }
    Ok(())
}

/// A router's LANs (its addrs beyond its own /32) are routed via the interface. `add`,
/// not `replace`: a route someone else owns is reported, never taken over.
fn lan_routes(r: &dyn Runner, c: &Compiled, n: &CompiledNetwork) -> anyhow::Result<()> {
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
    for lan in del {
        run(
            r,
            &[
                "ip",
                "route",
                "del",
                &lan.to_string(),
                "dev",
                iface,
                "proto",
                routes::PROTO,
            ],
        )?;
    }
    for lan in add {
        run(
            r,
            &[
                "ip",
                "route",
                "add",
                &lan.to_string(),
                "dev",
                iface,
                "proto",
                routes::PROTO,
            ],
        )?;
    }
    Ok(())
}

/// Takes a network out: its nft fragment, its interface (with its addresses and
/// routes) and its key, so nothing of it survives into a network that reuses the slug.
fn remove(
    r: &dyn Runner,
    id: Id,
    iface: &str,
    links: &[String],
    keys_dir: &Path,
) -> anyhow::Result<()> {
    nft(r, &render_network_removal(id, iface))?;
    if links.iter().any(|l| l == iface) {
        run(r, &["ip", "link", "del", iface])?;
    }
    keys::forget(keys_dir, iface)
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
