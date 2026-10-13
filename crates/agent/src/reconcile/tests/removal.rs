//! Networks that are gone, and what holds when the base or the inventory fails.

use super::*;

fn gone_n9_on(iface: &str) -> Fake {
    Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[(iface, Some(9))]),
        )
        .answer(
            "nft -j list map inet wgate from_net",
            &registry(&[(iface, 9)]),
        )
}

#[test]
fn a_network_that_is_gone_is_removed_and_unknown_links_are_left_alone() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[
                ("wg-n1", Some(1)),
                ("wg-old", Some(9)),
                ("wg-stray", None),
                ("wg0", None),
            ]),
        )
        .answer(
            "nft -j list map inet wgate from_net",
            &registry(&[("wg-n1", 1), ("wg-old", 9)]),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    // The interface goes first (that cuts its traffic at once), then its registration.
    assert!(position(&log, "ip link del wg-old") < nft_run(&log, 1));
    assert!(
        !log.iter()
            .any(|c| c == "ip link del wg-stray" || c == "ip link del wg0")
    );
}

#[test]
fn a_reused_slug_gets_a_fresh_network() {
    let dir = keys();
    let fake = gone_n9_on("wg-n1");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    // Network 9 used wg-n1 before: its interface goes before network 1's is made, on
    // a key of its own; network 9 keeps its key should it come back.
    assert!(position(&log, "ip link del wg-n1") < position(&log, "ip link add wgtmp-1"));
    assert!(out.hub_keys.contains(&(1, hub_pub(1))));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("n9.key")).unwrap(),
        hub_private(9)
    );
}

#[test]
fn a_gone_interface_that_would_not_go_is_disarmed_and_holds_its_name() {
    let dir = keys();
    let fake = gone_n9_on("wg-n1")
        .fail("ip link del wg-n1")
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K2}\t10.50.9.2/32\n"),
        )
        .answer("wg show all listen-port", "wg-n1\t51802\n")
        .answer(
            "ip -j route show dev wg-n1",
            r#"[{"dst":"192.168.9.0/24","scope":"link","flags":[]}]"#,
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("wg-n1: waits")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    // Its peers, addresses and LAN routes go; its registration too; and the port n2
    // wants comes free.
    position(&log, &format!("wg set wg-n1 peer {K2} remove"));
    position(&log, "ip addr flush dev wg-n1");
    position(&log, "ip route del 192.168.9.0/24 dev wg-n1 proto 150");
    assert!(nft_runs(&log) >= 2);
    assert!(
        position(&log, "wg set wg-n1 listen-port 51900")
            < position(&log, "wg set wg-n2 listen-port")
    );
    // Network 1 is not built on it.
    assert!(
        !log.iter()
            .any(|c| c.starts_with("ip addr replace") && c.ends_with("dev wg-n1"))
    );
    position(&log, "ip link add wgtmp-2");
}

#[test]
fn a_registration_that_will_not_go_is_cut_off() {
    let dir = keys();
    let fake = gone_n9_on("wg-old").fail_input("delete element inet wgate wg_ifaces");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-old (unregistering network 9)")),
        "{:?}",
        out.errors
    );
    assert!(
        !out.errors.iter().any(|e| e.contains("cutoff")),
        "{:?}",
        out.errors
    );
    // base, snat, removal, cutoff, then both networks.
    assert_eq!(nft_runs(&fake.log()), 5);
}

#[test]
fn without_the_links_only_registrations_go() {
    let dir = keys();
    let fake = Fake::default()
        .fail("ip -j link show type wireguard")
        .fail("ip -j -d link show")
        .answer(
            "nft -j list map inet wgate from_net",
            &registry(&[("wg-old", 9), ("wg-n1", 1)]),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("inventory: ")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    // The gone network's registration goes (that cuts it off); nothing is deleted,
    // made or built, and network 1's registration stays (failing closed).
    assert!(
        !log.iter()
            .any(|c| c.starts_with("ip link") || c.starts_with("wg set"))
    );
    let removal = "delete element inet wgate from_net { \"wg-old\" }";
    assert!(fake.inputs.borrow().iter().any(|i| i.contains(removal)));
    assert!(
        !fake
            .inputs
            .borrow()
            .iter()
            .any(|i| i.contains("delete element inet wgate from_net { \"wg-n1\" }"))
    );
}

#[test]
fn without_the_base_only_revocations_apply() {
    let dir = keys();
    let fake = Fake::default()
        .fail("nft -f -")
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K2}\t10.50.0.3/32\n"),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors[0].starts_with("base: "), "{:?}", out.errors);
    let log = fake.log();
    position(&log, &format!("wg set wg-n1 peer {K2} remove"));
    assert!(
        !log.iter()
            .any(|c| c.contains(" allowed-ips ") || c.starts_with("ip link add"))
    );
    assert!(out.hub_keys.is_empty());
}

#[test]
fn an_invalid_network_keeps_its_interface() {
    let dir = keys();
    let mut c = compiled();
    // Network 1 failed validation this pass (say, a bad block): not gone.
    c.networks.retain(|n| n.id != 1);
    c.peers.retain(|p| p.network != 1);
    c.invalid_networks.push(1);
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer(
            "nft -j list map inet wgate from_net",
            &registry(&[("wg-n1", 1)]),
        );
    reconcile(&fake, &c, dir.path());
    let log = fake.log();
    assert!(!log.iter().any(|l| l == "ip link del wg-n1"));
    // Unregistered: its traffic is dropped until it is valid again.
    let removal = "delete element inet wgate from_net { \"wg-n1\" }";
    assert!(fake.inputs.borrow().iter().any(|i| i.contains(removal)));
}

#[test]
fn an_element_not_wgates_on_a_networks_name_is_cleared() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer(
            "nft -j list map inet wgate from_net",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-n1", "accept"]]}}]}"#,
        );
    reconcile(&fake, &compiled(), dir.path());
    let cleared = "delete element inet wgate from_net { \"wg-n1\" }";
    let inputs = fake.inputs.borrow();
    let at = inputs
        .iter()
        .position(|i| i.trim() == cleared)
        .expect("cleared");
    // Before network 1's own entries go in.
    let fragment = inputs
        .iter()
        .rposition(|i| i.contains("add chain inet wgate n1_from"))
        .unwrap();
    assert!(at < fragment);
}

#[test]
fn what_an_invalid_network_holds_is_taken_by_nobody() {
    let dir = keys();
    let mut c = compiled();
    // n1 is invalid this pass; its LAN is now compiled for n2's router.
    let lan: ipnet::Ipv4Net = "192.168.1.0/24".parse().unwrap();
    let mut taker = c.peers[0].clone();
    taker.id = 2;
    taker.network = 2;
    taker.public_key = K3.into();
    taker.ip = "10.50.1.2".parse().unwrap();
    taker.addrs = vec!["10.50.1.2/32".parse().unwrap(), lan];
    c.networks.retain(|n| n.id != 1);
    c.peers = vec![taker];
    c.invalid_networks.push(1);
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .answer(
            "ip -j route show dev wg-n1",
            r#"[{"dst":"192.168.1.0/24","scope":"link","flags":[]}]"#,
        );
    reconcile(&fake, &c, dir.path());
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|l| l.starts_with(&format!("wg set wg-n2 peer {K3}")))
    );
    assert!(
        !log.iter()
            .any(|l| l.starts_with("ip route add 192.168.1.0/24"))
    );
}

#[test]
fn a_stray_in_one_map_is_cleared_from_that_map_only() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", &wg_links(&[("wg-n1", Some(1))]))
        .answer("nft -j list map inet wgate from_net", &registry(&[("wg-n1", 1)]))
        .answer(
            "nft -j list map inet wgate ingress",
            r#"{"nftables": [{"map": {"name": "ingress", "elem": [["wg-n1", {"jump": {"target": "n1_from"}}]]}}]}"#,
        );
    reconcile(&fake, &compiled(), dir.path());
    let inputs = fake.inputs.borrow();
    assert!(
        inputs
            .iter()
            .any(|i| i.trim() == "delete element inet wgate ingress { \"wg-n1\" }")
    );
    assert!(
        !inputs
            .iter()
            .any(|i| i.trim() == "delete element inet wgate from_net { \"wg-n1\" }")
    );
}
