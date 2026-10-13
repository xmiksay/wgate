//! The commands one reconcile is made of, each against the runner.

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{Compiled, CompiledNetwork};

use crate::routes;
use crate::runner::Runner;
use crate::wg::{self, PeerDiff, WgPeer};

pub(super) fn desired_peers(c: &Compiled, n: &CompiledNetwork) -> Vec<WgPeer> {
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

pub(super) fn peer_diff(
    r: &dyn Runner,
    c: &Compiled,
    n: &CompiledNetwork,
) -> anyhow::Result<PeerDiff> {
    let current = wg::parse_allowed_ips(&r.run(&["wg", "show", &n.iface, "allowed-ips"], None)?)?;
    Ok(wg::diff(&current, &desired_peers(c, n)))
}

pub(super) fn removals(r: &dyn Runner, iface: &str, d: &PeerDiff) -> anyhow::Result<()> {
    let remove = d
        .remove
        .iter()
        .map(|key| argv(&["wg", "set", iface, "peer", key, "remove"]));
    let narrow = d.narrow.iter().map(|p| allowed_ips(iface, p));
    all(r, &remove.chain(narrow).collect::<Vec<_>>())
}

pub(super) fn additions(r: &dyn Runner, n: &CompiledNetwork, d: &PeerDiff) -> anyhow::Result<()> {
    let commands: Vec<_> = d.set.iter().map(|p| allowed_ips(&n.iface, p)).collect();
    all(r, &commands)
}

pub(super) fn allowed_ips(iface: &str, p: &WgPeer) -> Vec<String> {
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
pub(super) fn lans(c: &Compiled, n: &CompiledNetwork) -> Vec<Ipv4Net> {
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
pub(super) fn route_commands(
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
pub(super) fn all(r: &dyn Runner, commands: &[Vec<String>]) -> anyhow::Result<()> {
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

pub(super) fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}

pub(super) fn nft(r: &dyn Runner, script: &str) -> anyhow::Result<()> {
    r.run(&["nft", "-f", "-"], Some(script)).map(drop)
}

pub(super) fn run(r: &dyn Runner, argv: &[&str]) -> anyhow::Result<()> {
    r.run(argv, None).map(drop)
}

/// The kernel's WireGuard interfaces.
pub(super) fn links(r: &dyn Runner) -> anyhow::Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Link {
        ifname: String,
    }
    let json = r.run(&["ip", "-j", "link", "show", "type", "wireguard"], None)?;
    let links: Vec<Link> = serde_json::from_str(&json).context("ip -j link")?;
    Ok(links.into_iter().map(|l| l.ifname).collect())
}

/// The interfaces registered in the `from_net` map, with their network.
pub(super) fn registered(r: &dyn Runner) -> anyhow::Result<Vec<(String, wgate_core::Id)>> {
    let json = r.run(
        &["nft", "-j", "list", "map", "inet", "wgate", "from_net"],
        None,
    )?;
    crate::nftmap::parse(&json)
}

/// Whether any link (WireGuard or not) has this name.
pub(super) fn link_exists(r: &dyn Runner, iface: &str) -> bool {
    r.run(&["ip", "-j", "link", "show", "dev", iface], None)
        .is_ok_and(|json| json.trim() != "[]")
}

/// Takes everything a gone network's interface carries away (peers, addresses, LAN
/// routes) when the interface itself would not go.
pub(super) fn disarm(r: &dyn Runner, iface: &str) -> anyhow::Result<()> {
    let current = wg::parse_allowed_ips(&r.run(&["wg", "show", iface, "allowed-ips"], None)?)?;
    let peers = removals(r, iface, &wg::diff(&current, &[]));
    let rest = all(
        r,
        &[
            argv(&["ip", "addr", "flush", "dev", iface]),
            argv(&["ip", "route", "flush", "dev", iface, "proto", routes::PROTO]),
        ],
    );
    peers.and(rest)
}
