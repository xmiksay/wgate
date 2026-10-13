//! Networks that are gone, and what holds when the base or the inventory fails.

use super::*;

fn gone_n9_on(iface: &str) -> Fake {
    Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[(iface, Some(9))]),
        )
        .answer("nft -j list map", &registry(&[(iface, 9)]))
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
        .answer("nft -j list map", &registry(&[("wg-n1", 1), ("wg-old", 9)]));
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
        .answer("wg show all listen-port", "wg-n1\t51802\n");
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
    position(&log, "ip route flush dev wg-n1 proto 150");
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
        .answer("nft -j list map", &registry(&[("wg-old", 9), ("wg-n1", 1)]));
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("inventory: ")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    // The gone network's registration goes (that cuts it off); nothing is deleted,
    // made or built, and network 1's registration stays.
    assert!(
        !log.iter()
            .any(|c| c.starts_with("ip link") || c.starts_with("wg set"))
    );
    assert_eq!(nft_runs(&log), 2, "base + the removal: {log:#?}");
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
