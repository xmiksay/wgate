use std::cell::RefCell;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use super::*;
use wgate_core::{Claim, DesiredState, NetRule, Network, Peer, RuleSet, Tenant, compile};

/// Answers commands from canned output (by their first words) and records them.
#[derive(Default)]
struct Fake {
    answers: HashMap<String, anyhow::Result<String>>,
    log: RefCell<Vec<String>>,
}

impl Fake {
    fn answer(mut self, prefix: &str, out: &str) -> Self {
        self.answers.insert(prefix.into(), Ok(out.into()));
        self
    }

    fn fail(mut self, prefix: &str) -> Self {
        self.answers
            .insert(prefix.into(), Err(anyhow::anyhow!("boom")));
        self
    }

    fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
}

impl Runner for Fake {
    fn run(&self, argv: &[&str], _stdin: Option<&str>) -> anyhow::Result<String> {
        let cmd = argv.join(" ");
        self.log.borrow_mut().push(cmd.clone());
        let mut best: Option<(&String, &anyhow::Result<String>)> = None;
        for (prefix, out) in &self.answers {
            if cmd.starts_with(prefix.as_str()) && best.is_none_or(|(b, _)| prefix.len() > b.len())
            {
                best = Some((prefix, out));
            }
        }
        match best {
            Some((_, Ok(out))) => Ok(out.clone()),
            Some((_, Err(e))) => Err(anyhow::anyhow!("{e}")),
            None if cmd.starts_with("wg genkey") => Ok("private\n".into()),
            None if cmd.starts_with("wg pubkey") => Ok("hubpub\n".into()),
            None if cmd.starts_with("wg show") => Ok("iface\tpub\t1\toff\n".into()),
            None if cmd.starts_with("ip -j") => Ok("[]".into()),
            None if cmd.starts_with("nft -j list map") => Ok(r#"{"nftables": []}"#.into()),
            None => Ok(String::new()),
        }
    }
}

const K1: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";
const K2: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

/// Two networks of one tenant: n1 with a router (LAN 192.168.1.0/24), n2 empty.
fn compiled() -> Compiled {
    let net = |s: &str| s.parse().unwrap();
    let network = |id: i64, cidr: &str| Network {
        id,
        tenant: 1,
        slug: format!("n{id}").parse().unwrap(),
        port: 51800 + id as u16,
        cidr: net(cidr),
        mesh: false,
        rules: Vec::<NetRule>::new(),
        inbound: RuleSet::new(),
    };
    compile(&DesiredState {
        pool: vec![net("10.50.0.0/16")],
        snat_source: Ipv4Addr::new(172, 19, 9, 10),
        node_cidrs: vec![],
        routed_space: vec![net("192.168.0.0/16")],
        reserved: vec![],
        tenants: vec![Tenant {
            id: 1,
            blocks: vec![Claim {
                id: 1,
                cidr: net("10.50.0.0/23"),
            }],
            ceiling: RuleSet::new(),
        }],
        networks: vec![network(1, "10.50.0.0/24"), network(2, "10.50.1.0/24")],
        peers: vec![Peer {
            id: 1,
            network: 1,
            ip: Ipv4Addr::new(10, 50, 0, 2),
            public_key: K1.into(),
            owner_tenant: Some(1),
            routed: vec![Claim {
                id: 1,
                cidr: net("192.168.1.0/24"),
            }],
        }],
        federations: vec![],
    })
}

fn keys() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn position(log: &[String], needle: &str) -> usize {
    log.iter()
        .position(|c| c.starts_with(needle))
        .unwrap_or_else(|| panic!("no `{needle}` in {log:#?}"))
}

/// Where the `n`th (from 0) nft transaction ran: the base, then fragments in order.
fn nft_run(log: &[String], n: usize) -> usize {
    log.iter()
        .enumerate()
        .filter(|(_, c)| c.as_str() == "nft -f -")
        .nth(n)
        .unwrap_or_else(|| panic!("no nft run {n} in {log:#?}"))
        .0
}

#[test]
fn a_new_network_is_built_and_its_fragment_applied_last() {
    let dir = keys();
    let fake = Fake::default();
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(out.hub_keys, [(1, "hubpub".into()), (2, "hubpub".into())]);
    let log = fake.log();
    let base = position(&log, "nft -f -");
    let link = position(&log, "ip link add wg-n1 type wireguard");
    let addr = position(&log, "ip addr replace 10.50.0.1/24 dev wg-n1");
    let port = position(&log, "wg set wg-n1 listen-port 51801 private-key ");
    let peer = position(
        &log,
        &format!("wg set wg-n1 peer {K1} allowed-ips 10.50.0.2/32,192.168.1.0/24"),
    );
    let route = position(&log, "ip route add 192.168.1.0/24 dev wg-n1 proto 150");
    // A new peer joins only after its network's rules are in.
    let fragment = nft_run(&log, 1);
    assert!(base < link && link < addr && addr < port && port < fragment);
    assert!(fragment < peer && peer < route);
    // Nothing asks about an interface before it exists.
    assert!(link < position(&log, "ip -j route show dev wg-n1"));
    // The key is the network's (by id) and stays private (0600).
    let key = dir.path().join("n1.key");
    assert_eq!(std::fs::read_to_string(&key).unwrap(), "private\n");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn revocations_come_before_additions_and_stale_routes_go() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            r#"[{"ifname":"wg-n1"},{"ifname":"wg-n2"}]"#,
        )
        .answer(
            "wg show wg-n1 dump",
            &format!("priv\tpub\t51801\toff\n{K2}\t(none)\t(none)\t10.50.0.3/32\t0\t0\t0\toff\n"),
        )
        .answer(
            "ip -j route show dev wg-n1",
            r#"[{"dst":"192.168.9.0/24","scope":"link","flags":[]}]"#,
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    assert!(
        !log.iter().any(|c| c.starts_with("ip link add")),
        "links exist"
    );
    let removal = position(&log, &format!("wg set wg-n1 peer {K2} remove"));
    let addition = position(&log, &format!("wg set wg-n1 peer {K1} allowed-ips"));
    assert!(removal < nft_run(&log, 1) && nft_run(&log, 1) < addition);
    position(&log, "ip route del 192.168.9.0/24 dev wg-n1 proto 150");
}

#[test]
fn a_network_that_is_gone_is_removed_and_unknown_links_are_left_alone() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            r#"[{"ifname":"wg-n1"},{"ifname":"wg-old"},{"ifname":"wg-stray"},{"ifname":"wg0"}]"#,
        )
        .answer(
            "nft -j list map",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-n1", {"jump": {"target": "n1_from"}}], ["wg-old", {"jump": {"target": "n9_from"}}]]}}]}"#,
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    // The interface goes first; the map entry stays until the fragment removal.
    assert!(position(&log, "ip link del wg-old") < nft_run(&log, 1));
    assert!(
        !log.iter()
            .any(|c| c == "ip link del wg-stray" || c == "ip link del wg0")
    );
}

#[test]
fn a_failing_step_neither_stops_its_networks_rules_nor_the_others() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            r#"[{"ifname":"wg-n1"},{"ifname":"wg-n2"}]"#,
        )
        .fail("wg show wg-n1 dump")
        .fail("ip -j route show dev wg-n1");
    let out = reconcile(&fake, &compiled(), dir.path());
    // Each phase (removals, additions; route deletions, additions) reports its own.
    assert_eq!(out.errors.len(), 4, "{:?}", out.errors);
    assert!(
        out.errors.iter().all(|e| e.starts_with("wg-n1: ")),
        "{:?}",
        out.errors
    );
    // Its fragment (every revocation of a right) still went in, and n2 was applied.
    let fragments = fake
        .log()
        .iter()
        .filter(|c| c.as_str() == "nft -f -")
        .count();
    assert_eq!(fragments, 3, "base + both networks");
    assert_eq!(out.hub_keys.len(), 2);
}

#[test]
fn a_reused_slug_gets_a_fresh_network() {
    let dir = keys();
    let old_key = format!("{:0>42}A=", 9);
    std::fs::write(dir.path().join("n9.key"), &old_key).unwrap();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer(
            "nft -j list map",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-n1", {"jump": {"target": "n9_from"}}]]}}]}"#,
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    // Network 9 used wg-n1 before: its interface goes before network 1 is built, on
    // a key of its own; network 9 keeps its key should it come back.
    let del = position(&log, "ip link del wg-n1");
    let add = position(&log, "ip link add wg-n1 type wireguard");
    assert!(del < add);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("n1.key")).unwrap(),
        "private\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("n9.key")).unwrap(),
        old_key
    );
}

#[test]
fn swapped_ports_are_freed_first() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            r#"[{"ifname":"wg-n1"},{"ifname":"wg-n2"}]"#,
        )
        .answer("wg show all listen-port", "wg-n1\t51802\nwg-n2\t51801\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    let free1 = position(&log, "wg set wg-n1 listen-port 0");
    let free2 = position(&log, "wg set wg-n2 listen-port 0");
    let take1 = position(&log, "wg set wg-n1 listen-port 51801 ");
    assert!(free1 < take1 && free2 < take1);
}

#[test]
fn a_port_nobody_else_wants_is_not_freed() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer("wg show all listen-port", "wg-n1\t51900\nwg-n2\t51802\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert!(!fake.log().iter().any(|c| c.ends_with("listen-port 0")));
}

#[test]
fn one_failing_revocation_does_not_keep_the_others() {
    let dir = keys();
    let stale = |k: &str, ip: &str| format!("{k}\t(none)\t(none)\t{ip}\t0\t0\t0\toff\n");
    let k3 = format!("{:0>42}A=", 3);
    let fake = Fake::default()
        .answer(
            "wg show wg-n1 dump",
            &format!(
                "priv\tpub\t51801\toff\n{}{}",
                stale(K2, "10.50.0.3/32"),
                stale(&k3, "10.50.0.4/32")
            ),
        )
        .fail(&format!("wg set wg-n1 peer {K2} remove"));
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    position(&fake.log(), &format!("wg set wg-n1 peer {k3} remove"));
}

#[test]
fn a_lan_moves_between_networks_in_one_reconcile() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            r#"[{"ifname":"wg-n1"},{"ifname":"wg-n2"}]"#,
        )
        .answer(
            "ip -j route show dev wg-n2",
            r#"[{"dst":"192.168.1.0/24","scope":"link","flags":[]}]"#,
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    let del = position(&log, "ip route del 192.168.1.0/24 dev wg-n2");
    let add = position(&log, "ip route add 192.168.1.0/24 dev wg-n1");
    assert!(del < add);
}

#[test]
fn without_an_inventory_nothing_is_removed() {
    let dir = keys();
    let fake = Fake::default().fail("ip -j link show").answer(
        "nft -j list map",
        r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-old", {"jump": {"target": "n9_from"}}]]}}]}"#,
    );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("inventory: ")),
        "{:?}",
        out.errors
    );
    assert!(!fake.log().iter().any(|c| c.contains("wg-old")));
}

#[test]
fn without_the_base_nothing_else_is_touched() {
    let dir = keys();
    let fake = Fake::default().fail("nft -f -");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors[0].starts_with("base: "));
    assert_eq!(fake.log().len(), 1);
}
