//! The commands one reconcile is made of, each against the runner.

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{Compiled, CompiledNetwork, Id, overlaps};

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
    let losing = |key: &str| {
        d.losing
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, lost)| lost.clone())
            .unwrap_or_default()
    };
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
    let (free, waiting): (Vec<_>, Vec<_>) = d.set.iter().partition(|p| !touches(&p.allowed, held));
    let commands: Vec<_> = free.iter().map(|p| allowed_ips(&n.iface, p)).collect();
    let added = all(r, &commands);
    if waiting.is_empty() {
        return added;
    }
    let keys: Vec<&str> = waiting.iter().map(|p| p.public_key.as_str()).collect();
    let waits = format!(
        "{} wait for addresses still held elsewhere",
        keys.join(", ")
    );
    Err(match added {
        Ok(()) => anyhow::anyhow!(waits),
        Err(e) => e.context(waits),
    })
}

/// Whether any of `nets` overlaps any of `held`.
pub(super) fn touches(nets: &[Ipv4Net], held: &[Ipv4Net]) -> bool {
    nets.iter().any(|a| held.iter().any(|h| overlaps(*a, *h)))
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
    n: &CompiledNetwork,
    del: &[Ipv4Net],
) -> (anyhow::Result<()>, Vec<Ipv4Net>) {
    let commands = del
        .iter()
        .map(|lan| (route("del", lan, &n.iface), vec![*lan]))
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

/// `add`, not `replace`: a route someone else owns is reported, never taken over.
pub(super) fn route_commands(
    r: &dyn Runner,
    n: &CompiledNetwork,
    verb: &str,
    lans: &[Ipv4Net],
) -> anyhow::Result<()> {
    let commands: Vec<_> = lans.iter().map(|lan| route(verb, lan, &n.iface)).collect();
    all(r, &commands)
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
pub(super) fn all(r: &dyn Runner, commands: &[Vec<String>]) -> anyhow::Result<()> {
    release(r, commands.iter().map(|c| (c.clone(), vec![])).collect()).0
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

/// The kernel's WireGuard interfaces.
pub(super) fn links(r: &dyn Runner) -> anyhow::Result<Vec<Link>> {
    let json = r.run(&["ip", "-j", "link", "show", "type", "wireguard"], None)?;
    let shown: Vec<Shown> = serde_json::from_str(&json).context("ip -j link")?;
    Ok(shown.into_iter().map(Link::from).collect())
}

/// The compiled networks' own interfaces, each read on its own: those that exist and
/// are WireGuard. `None` when not one could be read.
pub(super) fn links_of(
    r: &dyn Runner,
    c: &Compiled,
    errors: &mut Vec<String>,
) -> Option<Vec<Link>> {
    let mut read_any = false;
    let mut found = vec![];
    for n in &c.networks {
        let Ok(json) = r.run(&["ip", "-j", "-d", "link", "show", "dev", &n.iface], None) else {
            continue;
        };
        let shown: Vec<Shown> = match serde_json::from_str(&json) {
            Ok(shown) => shown,
            Err(e) => {
                errors.push(format!("{}: ip -j link: {e}", n.iface));
                continue;
            }
        };
        read_any = true;
        found.extend(
            shown
                .into_iter()
                .filter(|l| {
                    l.linkinfo.as_ref().and_then(|i| i.info_kind.as_deref()) == Some("wireguard")
                })
                .map(Link::from),
        );
    }
    read_any.then_some(found)
}

/// The interfaces registered in the `from_net` map, with their network.
pub(super) fn registered(r: &dyn Runner) -> anyhow::Result<Vec<(String, Id)>> {
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
    let peers =
        current_peers(r, iface).and_then(|current| removals(r, iface, &wg::diff(&current, &[])).0);
    let rest = all(
        r,
        &[
            argv(&["ip", "addr", "flush", "dev", iface]),
            argv(&["ip", "route", "flush", "dev", iface, "proto", routes::PROTO]),
        ],
    );
    peers.and(rest)
}

/// The peers an interface has, read with `allowed-ips`, never `dump` (that carries
/// the hub's private key and the peers' preshared keys).
pub(super) fn current_peers(r: &dyn Runner, iface: &str) -> anyhow::Result<Vec<WgPeer>> {
    wg::parse_allowed_ips(&r.run(&["wg", "show", iface, "allowed-ips"], None)?)
}
