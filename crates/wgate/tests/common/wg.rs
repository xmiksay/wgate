//! A WireGuard client namespace brought up from a downloaded `wg-quick` config.

use std::collections::BTreeSet;

use super::netns::Netns;

/// Every range a test may probe. Routed into the tunnel on top of the config's
/// AllowedIPs, so a denial is the hub's verdict, not a client's missing route (the
/// config is rendered once, before later rights changes).
const UNIVERSE: &[&str] = &[
    "10.50.0.0/16",
    "10.244.0.0/24",
    "172.16.16.0/24",
    "172.19.9.0/24",
    "192.168.50.0/24",
];

/// The tunnel interface inside a client namespace.
pub const IFACE: &str = "wgc";

/// A key of the config, e.g. `Endpoint`.
pub fn value<'a>(conf: &'a str, key: &str) -> Option<&'a str> {
    conf.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == key).then_some(v.trim())
    })
}

/// The config's AllowedIPs, as a set.
pub fn allowed_ips(conf: &str) -> BTreeSet<String> {
    value(conf, "AllowedIPs")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// What `wg-quick up` would do, minus DNS: the interface with the config's keys and
/// peer, its address, and routes for AllowedIPs (plus `UNIVERSE`).
pub fn up(ns: &Netns, conf: &str) {
    let mut allowed = allowed_ips(conf);
    allowed.extend(UNIVERSE.iter().map(|s| (*s).to_owned()));
    let mut setconf = String::new();
    for line in conf.lines() {
        let key = line.split_once('=').map(|(k, _)| k.trim());
        if !matches!(key, Some("Address" | "DNS" | "AllowedIPs")) {
            setconf.push_str(line);
            setconf.push('\n');
        }
    }
    // [Peer] is the last section.
    let joined: Vec<&str> = allowed.iter().map(String::as_str).collect();
    setconf.push_str(&format!("AllowedIPs = {}\n", joined.join(", ")));
    let address = value(conf, "Address").expect("an Address");
    ns.exec(&["ip", "link", "add", IFACE, "type", "wireguard"], None);
    ns.exec(&["wg", "setconf", IFACE, "/dev/stdin"], Some(&setconf));
    ns.exec(&["ip", "addr", "add", address, "dev", IFACE], None);
    ns.exec(&["ip", "link", "set", IFACE, "up"], None);
    for net in &allowed {
        // Above the metric of connected routes: a router keeps its own LAN on the LAN.
        ns.exec(
            &["ip", "route", "add", net, "dev", IFACE, "metric", "100"],
            None,
        );
    }
}
