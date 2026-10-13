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
fn without_the_list_of_links_wgates_own_interfaces_still_revoke() {
    let dir = keys();
    let fake = Fake::default()
        .fail("ip -j link show type wireguard")
        .answer(
            "ip -j -d link show dev wg-n1",
            r#"[{"ifname":"wg-n1","ifalias":"wgate:n1","linkinfo":{"info_kind":"wireguard"}}]"#,
        )
        .fail("ip -j -d link show dev wg-n2")
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K2}\t10.50.0.3/32\n"),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("inventory: ")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    position(&log, &format!("wg set wg-n1 peer {K2} remove"));
    // Its rules are refreshed; nothing grows, nothing is made.
    assert_eq!(nft_runs(&log), 2, "base + n1's fragment");
    assert!(
        !log.iter()
            .any(|c| c.contains(" allowed-ips ") || c.starts_with("ip link add"))
    );
}
