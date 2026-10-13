//! The commands one reconcile is made of, each against the runner.

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{Compiled, CompiledNetwork, DISPATCH, Id, overlaps_any};

use crate::routes;
use crate::runner::Runner;
use crate::wg::{self, PeerDiff, WgPeer};

pub(super) fn desired_peers(c: &Compiled, n: &CompiledNetwork) -> Vec<WgPeer> {
    c.peers_of(n.id)
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
    Ok(wg::diff(&current_peers(r, &n.iface)?, &desired_peers(c, n)))
}

/// Peer removals and narrowings; returns, besides the outcome, what a failed one
/// still holds.
pub(super) fn removals(
    r: &dyn Runner,
    iface: &str,
    d: &PeerDiff,
) -> (anyhow::Result<()>, Vec<Ipv4Net>) {
    let lost: std::collections::HashMap<&str, &Vec<Ipv4Net>> =
        d.losing.iter().map(|(k, l)| (k.as_str(), l)).collect();
    let losing = |key: &str| lost.get(key).map(|l| (*l).clone()).unwrap_or_default();
    let remove = d.remove.iter().map(|key| {
        (
            argv(&["wg", "set", iface, "peer", key, "remove"]),
            losing(key),
        )
    });
    let narrow = d
        .narrow
        .iter()
        .map(|p| (allowed_ips(iface, p), losing(&p.public_key)));
    release(r, remove.chain(narrow).collect())
}

/// Peer additions, but none that takes an address another peer still holds (its
/// release failed).
pub(super) fn additions(
    r: &dyn Runner,
    n: &CompiledNetwork,
    d: &PeerDiff,
    held: &[Ipv4Net],
) -> anyhow::Result<()> {
    unless_held(
        r,
        &d.set,
        held,
        |p| &p.allowed,
        |p| p.public_key.clone(),
        |p| allowed_ips(&n.iface, p),
        "addresses",
    )
}

/// LAN routes, but none for a LAN still routed elsewhere.
pub(super) fn route_additions(
    r: &dyn Runner,
    n: &CompiledNetwork,
    lans: &[Ipv4Net],
    held: &[Ipv4Net],
) -> anyhow::Result<()> {
    unless_held(
        r,
        lans,
        held,
        std::slice::from_ref,
        ToString::to_string,
        |lan| route("add", lan, &n.iface),
        "routes",
    )
}

/// Runs the command of each item that touches nothing `held`; the others wait, named.
fn unless_held<T>(
    r: &dyn Runner,
    items: &[T],
    held: &[Ipv4Net],
    nets: impl Fn(&T) -> &[Ipv4Net],
    name: impl Fn(&T) -> String,
    command: impl Fn(&T) -> Vec<String>,
    what: &str,
) -> anyhow::Result<()> {
    let (free, waiting): (Vec<&T>, Vec<&T>) =
        items.iter().partition(|i| !overlaps_any(nets(i), held));
    let done = all(r, free.into_iter().map(command).collect());
    if waiting.is_empty() {
        return done;
    }
    let names: Vec<String> = waiting.into_iter().map(name).collect();
    let waits = format!("{} wait for {what} still held elsewhere", names.join(", "));
    Err(match done {
        Ok(()) => anyhow::anyhow!(waits),
        Err(e) => e.context(waits),
    })
}

/// Runs each command, also after one fails; what a failed one was to release stays
/// held.
fn release(
    r: &dyn Runner,
    commands: Vec<(Vec<String>, Vec<Ipv4Net>)>,
) -> (anyhow::Result<()>, Vec<Ipv4Net>) {
    let mut failures = vec![];
    let mut held = vec![];
    for (cmd, releases) in commands {
        let argv: Vec<&str> = cmd.iter().map(String::as_str).collect();
        if let Err(e) = run(r, &argv) {
            failures.push(format!("{e:#}"));
            held.extend(releases);
        }
    }
    let result = if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(failures.join("; ")))
    };
    (result, held)
}

/// Stale LAN route deletions; returns, besides the outcome, the LANs still routed.
pub(super) fn route_deletions(
    r: &dyn Runner,
    iface: &str,
    del: &[Ipv4Net],
) -> (anyhow::Result<()>, Vec<Ipv4Net>) {
    let commands = del
        .iter()
        .map(|lan| (route("del", lan, iface), vec![*lan]))
        .collect();
    release(r, commands)
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
    c.peers_of(n.id)
        .flat_map(|p| {
            p.addrs
                .iter()
                .filter(move |a| **a != Ipv4Net::from(p.ip))
                .copied()
        })
        .collect()
}

/// `ip route <verb> <lan> dev <iface> proto 150`.
fn route(verb: &str, lan: &Ipv4Net, iface: &str) -> Vec<String> {
    let lan = lan.to_string();
    argv(&[
        "ip",
        "route",
        verb,
        &lan,
        "dev",
        iface,
        "proto",
        routes::PROTO,
    ])
}

/// Runs every command, also after one fails (one stuck peer must not keep the other
/// revocations from applying); reports all failures.
pub(super) fn all(r: &dyn Runner, commands: Vec<Vec<String>>) -> anyhow::Result<()> {
    release(r, commands.into_iter().map(|c| (c, vec![])).collect()).0
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

/// The mark of an interface wgate made, in its alias: `wgate:n<network id>`. Kept on
/// the interface itself, it survives a flushed table and a lost key file.
const MARK: &str = "wgate:n";

pub(super) fn owner_mark(id: Id) -> String {
    format!("{MARK}{id}")
}

fn owner_of_mark(alias: Option<&str>) -> Option<Id> {
    alias?.strip_prefix(MARK)?.parse().ok()
}

/// A new interface is made under this name, marked, then renamed: a crash in between
/// leaves a link that is plainly wgate's.
pub(super) const SCRATCH: &str = "wgtmp-";

/// A WireGuard interface and the network that made it, if wgate did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Link {
    pub name: String,
    pub owner: Option<Id>,
}

#[derive(serde::Deserialize)]
struct Shown {
    ifname: String,
    ifalias: Option<String>,
    linkinfo: Option<LinkInfo>,
}

#[derive(serde::Deserialize)]
struct LinkInfo {
    info_kind: Option<String>,
}

impl From<Shown> for Link {
    fn from(l: Shown) -> Self {
        Link {
            owner: owner_of_mark(l.ifalias.as_deref()),
            name: l.ifname,
        }
    }
}

/// The kernel's WireGuard interfaces; when the type filter fails, from every link
/// with its details (its kind).
pub(super) fn links(r: &dyn Runner) -> anyhow::Result<Vec<Link>> {
    let filtered = r
        .run(&["ip", "-j", "link", "show", "type", "wireguard"], None)
        .and_then(|json| Ok(serde_json::from_str::<Vec<Shown>>(&json)?));
    let shown = match filtered {
        Ok(shown) => shown,
        Err(first) => {
            let json = r
                .run(&["ip", "-j", "-d", "link", "show"], None)
                .with_context(|| format!("{first:#}"))?;
            let all: Vec<Shown> = serde_json::from_str(&json).context("ip -j -d link")?;
            all.into_iter()
                .filter(|l| {
                    l.linkinfo.as_ref().and_then(|i| i.info_kind.as_deref()) == Some("wireguard")
                })
                .collect()
        }
    };
    Ok(shown.into_iter().map(Link::from).collect())
}

/// What the dispatch maps hold.
#[derive(Default)]
pub(super) struct Dispatch {
    /// The networks registered on each name, in any of the maps (one left in a single
    /// map is still a registration to take off).
    pub networks: Vec<(String, Id)>,
    /// Map by map, the interfaces of elements that are not wgate's.
    pub stray: Vec<(&'static str, String)>,
}

pub(super) fn registered(r: &dyn Runner) -> anyhow::Result<Dispatch> {
    let mut networks = vec![];
    let mut stray = vec![];
    for (map, chain) in DISPATCH {
        let json = r.run(&["nft", "-j", "list", "map", "inet", "wgate", map], None)?;
        let read = crate::nftmap::parse(&json, chain)?;
        for pair in read.networks {
            if !networks.contains(&pair) {
                networks.push(pair);
            }
        }
        stray.extend(read.stray.into_iter().map(|iface| (map, iface)));
    }
    Ok(Dispatch { networks, stray })
}

/// Takes an element that is not wgate's out of its map: the network's own entry could
/// not go in otherwise. Until it does, the base drops the interface's traffic.
pub(super) fn clear_stray(r: &dyn Runner, map: &str, iface: &str) -> anyhow::Result<()> {
    nft(
        r,
        &format!("delete element inet wgate {map} {{ \"{iface}\" }}\n"),
    )
}

/// Whether any link (WireGuard or not) has this name.
pub(super) fn link_exists(r: &dyn Runner, iface: &str) -> bool {
    r.run(&["ip", "-j", "link", "show", "dev", iface], None)
        .is_ok_and(|json| json.trim() != "[]")
}

/// Takes everything a gone network's interface carries away (peers, addresses, LAN
/// routes) when the interface itself would not go.
/// Returns, besides the outcome, what it still holds, and whether that could not even
/// be read.
pub(super) fn disarm(r: &dyn Runner, iface: &str) -> (anyhow::Result<()>, Vec<Ipv4Net>, bool) {
    let mut held = vec![];
    let mut blind = false;
    let peers = current_peers(r, iface)
        .inspect_err(|_| blind = true)
        .and_then(|current| {
            let (result, still) = removals(r, iface, &wg::diff(&current, &[]));
            held.extend(still);
            result
        });
    let routes = current_routes(r, iface)
        .inspect_err(|_| blind = true)
        .and_then(|current| {
            let (result, still) = route_deletions(r, iface, &current);
            held.extend(still);
            result
        });
    let addresses = run(r, &["ip", "addr", "flush", "dev", iface]);
    (peers.and(routes).and(addresses), held, blind)
}

/// The addresses in an interval set of `table inet wgate`.
pub(super) fn set_ranges(r: &dyn Runner, set: &str) -> anyhow::Result<Vec<Ipv4Net>> {
    let json = r.run(&["nft", "-j", "list", "set", "inet", "wgate", set], None)?;
    crate::nftmap::parse_ranges(&json)
}

/// The LAN routes (wgate's protocol) via an interface.
pub(super) fn current_routes(r: &dyn Runner, iface: &str) -> anyhow::Result<Vec<Ipv4Net>> {
    let json = r.run(
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
    )?;
    routes::parse(&json)
}

/// The peers an interface has, read with `allowed-ips`, never `dump` (that carries
/// the hub's private key and the peers' preshared keys).
pub(super) fn current_peers(r: &dyn Runner, iface: &str) -> anyhow::Result<Vec<WgPeer>> {
    wg::parse_allowed_ips(&r.run(&["wg", "show", iface, "allowed-ips"], None)?)
}
