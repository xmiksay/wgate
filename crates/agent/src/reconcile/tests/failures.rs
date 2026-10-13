//! Failed reads and writes that must never turn into an irreversible step.

use super::*;

fn owned_n1() -> Fake {
    Fake::default().answer(
        "ip -j link show type wireguard",
        &wg_links(&[("wg-n1", Some(1))]),
    )
}

#[test]
fn a_failed_fragment_holds_back_what_would_grow_on_stale_rules() {
    let dir = keys();
    let fake = owned_n1().fail_input("chain inet wgate n1_from");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e == "wg-n1: nft: boom"),
        "{:?}",
        out.errors
    );
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-n1: peers and routes: held back"))
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c.starts_with("wg set wg-n1 peer") || c.starts_with("ip route add"))
    );
}

#[test]
fn an_unreadable_interface_key_is_never_taken_for_none() {
    let dir = keys();
    std::fs::remove_file(dir.path().join("n1.key")).unwrap();
    let fake = owned_n1().fail("wg show wg-n1 public-key");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("wg-n1: hub key: ")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c == "wg genkey" || c.starts_with("wg set wg-n1 private-key"))
    );
    assert!(!dir.path().join("n1.key").exists());
}

#[test]
fn a_damaged_key_still_lets_the_rules_apply() {
    let dir = keys();
    std::fs::write(dir.path().join("n1.key"), "garbage").unwrap();
    let fake = owned_n1();
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.contains("not a WireGuard key")),
        "{:?}",
        out.errors
    );
    assert_eq!(nft_runs(&fake.log()), 3, "n1's rules still applied");
}

#[test]
fn a_freed_port_is_parked_on_the_first_spare_one_free() {
    let dir = keys();
    let both = wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]);
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", &both)
        .answer("wg show all listen-port", "wg-n1\t51802\n")
        .fail("wg set wg-n1 listen-port 51900");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    assert!(
        position(&log, "wg set wg-n1 listen-port 51901")
            < position(&log, "wg set wg-n2 listen-port 51802")
    );

    // No spare port free: reported.
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", &both)
        .answer("wg show all listen-port", "wg-n1\t51802\n")
        .fail("wg set wg-n1 listen-port 519");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors
            .iter()
            .any(|e| e.ends_with("no spare port is free")),
        "{:?}",
        out.errors
    );
}

#[test]
fn without_a_guarding_base_stale_routes_still_go() {
    let dir = keys();
    let fake = owned_n1().fail("nft -f -").answer(
        "ip -j route show dev wg-n1",
        r#"[{"dst":"192.168.9.0/24","scope":"link","flags":[]}]"#,
    );
    reconcile(&fake, &compiled(), dir.path());
    let log = fake.log();
    position(&log, "ip route del 192.168.9.0/24 dev wg-n1 proto 150");
    assert!(!log.iter().any(|c| c.starts_with("ip route add")));
}

/// n1's router moves its LAN to a new router in n2.
fn lan_moving_to_n2() -> Compiled {
    let mut c = compiled();
    let router = c.peers.iter_mut().find(|p| p.network == 1).unwrap();
    let lan: Ipv4Net = "192.168.1.0/24".parse().unwrap();
    router.addrs.retain(|a| *a != lan);
    let mut taker = router.clone();
    taker.id = 2;
    taker.network = 2;
    taker.public_key = K3.into();
    taker.ip = "10.50.1.2".parse().unwrap();
    taker.addrs = vec!["10.50.1.2/32".parse().unwrap(), lan];
    c.peers.push(taker);
    c
}

#[test]
fn what_could_not_be_released_is_not_taken_elsewhere() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K1}\t10.50.0.2/32 192.168.1.0/24\n"),
        )
        .answer(
            "ip -j route show dev wg-n1",
            r#"[{"dst":"192.168.1.0/24","scope":"link","flags":[]}]"#,
        )
        .fail(&format!("wg set wg-n1 peer {K1} allowed-ips"))
        .fail("ip route del 192.168.1.0/24 dev wg-n1");
    let out = reconcile(&fake, &lan_moving_to_n2(), dir.path());
    let log = fake.log();
    // n2's new router waits for the LAN, and so does its route.
    assert!(
        !log.iter()
            .any(|c| c.starts_with(&format!("wg set wg-n2 peer {K3}")))
    );
    assert!(
        !log.iter()
            .any(|c| c.starts_with("ip route add 192.168.1.0/24 dev wg-n2"))
    );
    assert!(
        out.errors
            .iter()
            .any(|e| e.contains("wait for addresses still held")),
        "{:?}",
        out.errors
    );
    assert!(
        out.errors
            .iter()
            .any(|e| e.contains("wait for routes still held"))
    );
}

#[test]
fn an_address_still_held_gets_no_rights_either() {
    let dir = keys();
    // A revoked peer still holds 10.50.0.2, which network 1's router now owns.
    let fake = owned_n1()
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K2}\t10.50.0.2/32\n"),
        )
        .fail(&format!("wg set wg-n1 peer {K2} remove"));
    reconcile(&fake, &compiled(), dir.path());
    let fragments = fake.fragments_of(1);
    assert_eq!(fragments.len(), 1);
    assert!(!fragments[0].contains("10.50.0.2"), "{}", fragments[0]);
    assert!(
        !fake
            .log()
            .iter()
            .any(|c| c.starts_with(&format!("wg set wg-n1 peer {K1}")))
    );
}

#[test]
fn unreadable_peers_leave_their_network_as_it_is() {
    let dir = keys();
    let fake = owned_n1().fail("wg show wg-n1 allowed-ips");
    reconcile(&fake, &compiled(), dir.path());
    assert!(fake.fragments_of(1).is_empty());
    assert!(
        !fake
            .log()
            .iter()
            .any(|c| c.starts_with("wg set wg-n1 peer"))
    );
}

#[test]
fn on_a_stale_base_removals_still_come_before_the_rules() {
    let dir = keys();
    let fake = owned_n1()
        .fail_input("add set inet wgate tenant_space")
        .answer(
            "nft -j list set inet wgate tenant_space",
            r#"{"nftables": [{"set": {"name": "tenant_space", "elem": [{"prefix": {"addr": "10.50.0.0", "len": 24}}]}}]}"#,
        )
        .answer("wg show wg-n1 allowed-ips", &format!("{K2}\t10.50.0.3/32\n"));
    reconcile(&fake, &compiled(), dir.path());
    let log = fake.log();
    assert!(position(&log, &format!("wg set wg-n1 peer {K2} remove")) < nft_run(&log, 1));
}

#[test]
fn without_the_registry_nothing_grows() {
    let dir = keys();
    let fake = owned_n1().fail("nft -j list map");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("inventory: ")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c.starts_with("ip link add") || c.contains(" allowed-ips "))
    );
    assert_eq!(fake.fragments_of(1).len(), 1, "n1's rules still refreshed");
}

#[test]
fn what_an_unreadable_network_may_hold_is_taken_by_nobody() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .fail("wg show wg-n1 allowed-ips");
    let mut c = lan_moving_to_n2();
    // Still compiled for n1's router too, so n1's addresses cover it.
    c.peers[0].addrs.push("192.168.1.0/24".parse().unwrap());
    reconcile(&fake, &c, dir.path());
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|l| l.starts_with(&format!("wg set wg-n2 peer {K3}")))
    );
    assert!(!fake.fragments_of(2)[0].contains("192.168.1.0/24"));
}
