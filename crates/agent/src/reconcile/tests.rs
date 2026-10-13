use std::cell::RefCell;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use super::*;
use wgate_core::{Claim, DesiredState, NetRule, Network, Peer, RuleSet, Tenant, compile};

/// Answers commands from canned output (by their first words) and records them.
#[derive(Default)]
struct Fake {
    answers: HashMap<String, anyhow::Result<String>>,
    /// Fails any command whose input contains this.
    fail_input: Option<String>,
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

    fn fail_input(mut self, needle: &str) -> Self {
        self.fail_input = Some(needle.into());
        self
    }

    fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
}

impl Runner for Fake {
    fn run(&self, argv: &[&str], stdin: Option<&str>) -> anyhow::Result<String> {
        let cmd = argv.join(" ");
        self.log.borrow_mut().push(cmd.clone());
        if let (Some(needle), Some(input)) = (&self.fail_input, stdin)
            && input.contains(needle.as_str())
        {
            anyhow::bail!("boom");
        }
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
            None if cmd.starts_with("wg genkey") => Ok(format!("{GENERATED}\n")),
            None if cmd.starts_with("wg pubkey") => {
                Ok(format!("pub-{}\n", stdin.unwrap_or_default().trim()))
            }
            // wg-n1 and wg-n2 carry their network's key, other interfaces none.
            None if cmd == "wg show wg-n1 public-key" => Ok(format!("{}\n", hub_pub(1))),
            None if cmd == "wg show wg-n2 public-key" => Ok(format!("{}\n", hub_pub(2))),
            // wg-old is gone network 9's.
            None if cmd == "wg show wg-old public-key" => Ok(format!("{}\n", hub_pub(9))),
            None if cmd.ends_with(" public-key") => Ok("(none)\n".into()),
            None if cmd.starts_with("wg show") => Ok(String::new()),
            None if cmd.starts_with("ip -j") => Ok("[]".into()),
            None if cmd.starts_with("nft -j list map") => Ok(r#"{"nftables": []}"#.into()),
            None => Ok(String::new()),
        }
    }
}

/// What the fake `wg genkey` prints.
const GENERATED: &str = "000000000000000000000000000000000000000007A=";
const K1: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";
const K3: &str = "000000000000000000000000000000000000000003A=";
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

/// The `from_net` map (`nft -j list map …`) with these registrations.
fn registry(elems: &[(&str, Id)]) -> String {
    let elems: Vec<String> = elems
        .iter()
        .map(|(iface, id)| format!(r#"["{iface}", {{"jump": {{"target": "n{id}_from"}}}}]"#))
        .collect();
    format!(
        r#"{{"nftables": [{{"map": {{"name": "from_net", "elem": [{}]}}}}]}}"#,
        elems.join(", ")
    )
}

/// The `ip -j link show type wireguard` of these links and their marks.
fn wg_links(links: &[(&str, Option<Id>)]) -> String {
    let shown: Vec<String> = links
        .iter()
        .map(|(name, owner)| match owner {
            Some(id) => format!(r#"{{"ifname":"{name}","ifalias":"wgate:n{id}"}}"#),
            None => format!(r#"{{"ifname":"{name}"}}"#),
        })
        .collect();
    format!("[{}]", shown.join(","))
}

/// A keys directory holding the keys of networks 1, 2 and (gone) 9.
fn keys() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for id in [1, 2, 9] {
        std::fs::write(dir.path().join(format!("n{id}.key")), hub_private(id)).unwrap();
    }
    dir
}

fn hub_private(id: i64) -> String {
    format!("{:0>42}A=", 100 + id)
}

/// The fake `wg pubkey` of network `id`'s key.
fn hub_pub(id: i64) -> String {
    format!("pub-{}", hub_private(id))
}

fn position(log: &[String], needle: &str) -> usize {
    log.iter()
        .position(|c| c.starts_with(needle))
        .unwrap_or_else(|| panic!("no `{needle}` in {log:#?}"))
}

/// nft transactions other than SNAT (always the second, right after the base).
fn nft_runs(log: &[String]) -> usize {
    log.iter().filter(|c| c.as_str() == "nft -f -").count() - 1
}

/// Where the `n`th (from 0) nft transaction ran: the base, then fragments (and
/// removals) in order.
fn nft_run(log: &[String], n: usize) -> usize {
    log.iter()
        .enumerate()
        .filter(|(_, c)| c.as_str() == "nft -f -")
        // Past SNAT, the second.
        .nth(if n == 0 { 0 } else { n + 1 })
        .unwrap_or_else(|| panic!("no nft run {n} in {log:#?}"))
        .0
}

#[test]
fn a_new_network_is_keyed_made_marked_and_built() {
    // No keys yet: both are issued.
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::default();
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let issued = format!("pub-{GENERATED}");
    assert_eq!(out.hub_keys, [(1, issued.clone()), (2, issued)]);
    let log = fake.log();
    // The key before the interface; made under a scratch name, marked, renamed.
    let genkey = position(&log, "wg genkey");
    let made = position(&log, "ip link add wgtmp-1 type wireguard");
    let marked = position(&log, "ip link set dev wgtmp-1 alias wgate:n1");
    let named = position(&log, "ip link set dev wgtmp-1 name wg-n1");
    assert!(genkey < made && made < marked && marked < named);
    let addr = position(&log, "ip addr replace 10.50.0.1/24 dev wg-n1");
    let keyed = position(&log, "wg set wg-n1 private-key ");
    let port = position(&log, "wg set wg-n1 listen-port 51801");
    assert!(named < addr && addr < keyed && keyed < port);
    // A new peer joins only after its network's rules are in.
    let fragment = nft_run(&log, 1);
    let peer = position(
        &log,
        &format!("wg set wg-n1 peer {K1} allowed-ips 10.50.0.2/32,192.168.1.0/24"),
    );
    let route = position(&log, "ip route add 192.168.1.0/24 dev wg-n1 proto 150");
    assert!(port < fragment && fragment < peer && peer < route);
    // Nothing asks about an interface before it exists.
    assert!(
        !log.iter()
            .any(|c| c.contains("route show dev wg-n1") || c.starts_with("wg show wg-n1"))
    );
    // The key is the network's (by id) and stays private (0600).
    let key = dir.path().join("n1.key");
    assert_eq!(
        std::fs::read_to_string(&key).unwrap(),
        format!("{GENERATED}\n")
    );
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
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K2}\t10.50.0.3/32\n"),
        )
        .answer(
            "wg show wg-n2 allowed-ips",
            &format!("{K3}\t10.50.1.9/32\n"),
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
    // n2's losses also go before n1's rules or peers grow.
    assert!(position(&log, &format!("wg set wg-n2 peer {K3} remove")) < nft_run(&log, 1));
    position(&log, "ip route del 192.168.9.0/24 dev wg-n1 proto 150");
}

#[test]
fn a_failing_step_neither_stops_its_networks_rules_nor_the_others() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .fail("wg show wg-n1 allowed-ips")
        .fail("ip -j route show dev wg-n1");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors.len(), 2, "{:?}", out.errors);
    assert!(
        out.errors.iter().all(|e| e.starts_with("wg-n1: ")),
        "{:?}",
        out.errors
    );
    // Its fragment (every revocation of a right) still went in, and n2 was applied.
    assert_eq!(nft_runs(&fake.log()), 3, "base + both networks");
    assert_eq!(out.hub_keys.len(), 2);
}

#[test]
fn swapped_ports_are_freed_first() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .answer("wg show all listen-port", "wg-n1\t51802\nwg-n2\t51801\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    let free1 = position(&log, "wg set wg-n1 listen-port 51900");
    let free2 = position(&log, "wg set wg-n2 listen-port 51900");
    let take1 = position(&log, "wg set wg-n1 listen-port 51801");
    assert!(free1 < take1 && free2 < take1);
}

#[test]
fn a_port_nobody_else_wants_is_not_freed() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer("wg show all listen-port", "wg-n1\t51900\nwg-n2\t51802\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert!(!fake.log().iter().any(|c| c.ends_with("listen-port 51900")));
}

#[test]
fn one_failing_revocation_does_not_keep_the_others() {
    let dir = keys();
    let stale = |k: &str, ip: &str| format!("{k}\t{ip}\n");
    let k3 = format!("{:0>42}A=", 3);
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!(
                "{}{}",
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
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
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
fn what_a_peer_loses_goes_before_the_rules_change() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K1}\t10.50.0.2/32 192.168.1.0/24 192.168.7.0/24\n"),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    let narrow = position(
        &log,
        &format!("wg set wg-n1 peer {K1} allowed-ips 10.50.0.2/32,192.168.1.0/24"),
    );
    assert!(narrow < nft_run(&log, 1));
}

mod failures;
mod ownership;
mod removal;
