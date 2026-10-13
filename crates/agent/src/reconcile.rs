//! One reconcile: the base, then network by network (an error in one never stops the
//! others), then the networks that are gone.

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
    /// The hub public key of every network that was applied.
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
    let registered = match r
        .run(
            &["nft", "-j", "list", "map", "inet", "wgate", "from_net"],
            None,
        )
        .and_then(|json| nftmap::parse(&json))
    {
        Ok(registered) => registered,
        Err(e) => {
            out.errors.push(format!("registered networks: {e:#}"));
            vec![]
        }
    };
    let links = links(r).unwrap_or_else(|e| {
        out.errors.push(format!("links: {e:#}"));
        vec![]
    });

    for n in &c.networks {
        match network(r, c, n, keys_dir, &links) {
            Ok(public) => out.hub_keys.push((n.id, public)),
            Err(e) => out.errors.push(format!("{}: {e:#}", n.iface)),
        }
    }

    for (iface, id) in &registered {
        if c.networks.iter().any(|n| n.iface == *iface) {
            continue;
        }
        let removed = nft(r, &render_network_removal(*id, iface)).and_then(|()| {
            if links.contains(iface) {
                r.run(&["ip", "link", "del", iface], None)?;
            }
            Ok(())
        });
        match removed {
            Ok(()) => tracing::info!(%iface, "network removed"),
            Err(e) => out.errors.push(format!("{iface} (removing): {e:#}")),
        }
    }
    for link in &links {
        let known = c.networks.iter().any(|n| n.iface == *link)
            || registered.iter().any(|(iface, _)| iface == link);
        if link.starts_with("wg-") && !known {
            // Not ours to delete; its traffic is dropped (an unknown wg-*).
            tracing::warn!(%link, "unknown wg- interface left alone");
        }
    }
    out
}

/// Brings one network to its compiled state: interface, key, peers (removals first),
/// routes, then its nft fragment. Returns the hub public key.
fn network(
    r: &dyn Runner,
    c: &Compiled,
    n: &CompiledNetwork,
    keys_dir: &Path,
    links: &[String],
) -> anyhow::Result<String> {
    let iface = n.iface.as_str();
    if !links.iter().any(|l| l == iface) {
        r.run(&["ip", "link", "add", iface, "type", "wireguard"], None)?;
    }
    let (key, public) = keys::ensure(r, keys_dir, iface)?;
    let key = key.to_str().context("key path is not UTF-8")?;
    let address = format!("{}/{}", n.hub, n.cidr.prefix_len());
    r.run(&["ip", "addr", "replace", &address, "dev", iface], None)?;
    let port = n.port.to_string();
    r.run(
        &["wg", "set", iface, "listen-port", &port, "private-key", key],
        None,
    )?;
    r.run(&["ip", "link", "set", iface, "up"], None)?;

    let peers: Vec<_> = c.peers.iter().filter(|p| p.network == n.id).collect();
    let desired: Vec<WgPeer> = peers
        .iter()
        .map(|p| WgPeer {
            public_key: p.public_key.clone(),
            allowed: p.addrs.clone(),
        })
        .collect();
    let current = wg::parse_dump(&r.run(&["wg", "show", iface, "dump"], None)?)?;
    let diff = wg::diff(&current, &desired);
    for key in &diff.remove {
        r.run(&["wg", "set", iface, "peer", key, "remove"], None)?;
    }
    for p in &diff.set {
        let allowed: Vec<String> = p.allowed.iter().map(Ipv4Net::to_string).collect();
        r.run(
            &[
                "wg",
                "set",
                iface,
                "peer",
                &p.public_key,
                "allowed-ips",
                &allowed.join(","),
            ],
            None,
        )?;
    }

    // A router's LANs (its addrs beyond its own /32) are routed via the interface.
    let lans: Vec<Ipv4Net> = peers
        .iter()
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
        let lan = lan.to_string();
        r.run(
            &[
                "ip",
                "route",
                "del",
                &lan,
                "dev",
                iface,
                "proto",
                routes::PROTO,
            ],
            None,
        )?;
    }
    for lan in add {
        let lan = lan.to_string();
        r.run(
            &[
                "ip",
                "route",
                "replace",
                &lan,
                "dev",
                iface,
                "proto",
                routes::PROTO,
            ],
            None,
        )?;
    }

    nft(r, &render_network(c, n))?;
    Ok(public)
}

fn nft(r: &dyn Runner, script: &str) -> anyhow::Result<()> {
    r.run(&["nft", "-f", "-"], Some(script)).map(drop)
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
