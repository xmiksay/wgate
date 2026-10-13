//! What the agent refuses to take over, and when a hub key counts as in place.

use super::*;

#[test]
fn an_unregistered_interface_with_another_key_is_left_alone() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer("wg show wg-n1 public-key", "someone-elses\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(
        out.errors,
        ["wg-n1: an interface wgate did not make; left alone"]
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c.starts_with("wg set wg-n1") || c.contains("dev wg-n1 proto"))
    );
    assert_eq!(nft_runs(&log), 2, "base + n2 only");
}

#[test]
fn a_link_that_is_not_wireguard_is_never_registered() {
    let dir = keys();
    let fake = Fake::default().answer("ip -j link show dev wg-n1", r#"[{"ifname":"wg-n1"}]"#);
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert!(out.errors[0].starts_with("wg-n1: the name is taken"));
    assert_eq!(nft_runs(&fake.log()), 2, "base + n2 only");
}

#[test]
fn a_failed_create_stops_its_network() {
    let dir = keys();
    let fake = Fake::default().fail("ip link add wg-n1");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors, ["wg-n1: create: boom"]);
    let touched = |c: &String| {
        c.starts_with("wg set wg-n1") || (c.starts_with("ip addr") && c.ends_with("dev wg-n1"))
    };
    assert!(!fake.log().iter().any(touched));
    assert_eq!(out.hub_keys, [(2, hub_pub(2))]);
}

#[test]
fn a_hub_key_counts_only_once_the_interface_has_it() {
    let dir = keys();
    let fake = Fake::default()
        .fail("wg set wg-n1 private-key")
        .fail("wg set wg-n2 listen-port");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors.len(), 2, "{:?}", out.errors);
    // n2 has its key even though its port is taken.
    assert_eq!(out.hub_keys, [(2, hub_pub(2))]);
}

#[test]
fn without_the_base_a_gone_network_still_goes() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            r#"[{"ifname":"wg-n1"},{"ifname":"wg-old"}]"#,
        )
        .answer(
            "nft -j list map",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-n1", {"jump": {"target": "n1_from"}}], ["wg-old", {"jump": {"target": "n9_from"}}]]}}]}"#,
        )
        .fail_input("add table inet wgate\nadd set inet wgate tenant_space");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors[0].starts_with("base: "), "{:?}", out.errors);
    let log = fake.log();
    position(&log, "ip link del wg-old");
    assert!(
        !log.iter()
            .any(|c| c.contains(" allowed-ips ") || c.starts_with("ip link add"))
    );
}

#[test]
fn a_foreign_interface_keeps_its_peers_and_port_on_every_path() {
    for base_fails in [false, true] {
        let dir = keys();
        let mut fake = Fake::default()
            .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
            .answer("wg show wg-n1 public-key", "someone-elses\n")
            .answer(
                "wg show wg-n1 allowed-ips",
                &format!("{K2}\t10.50.0.3/32\n"),
            )
            .answer("wg show all listen-port", "wg-n1\t51802\n");
        if base_fails {
            fake = fake.fail_input("add set inet wgate tenant_space");
        }
        reconcile(&fake, &compiled(), dir.path());
        assert!(
            !fake.log().iter().any(|c| c.starts_with("wg set wg-n1")),
            "base fails: {base_fails}: {:#?}",
            fake.log()
        );
    }
}

#[test]
fn a_damaged_key_is_named_as_the_cause() {
    let dir = keys();
    std::fs::write(dir.path().join("n1.key"), "garbage").unwrap();
    let fake = Fake::default().answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#);
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("wg-n1: hub key: ")),
        "{:?}",
        out.errors
    );
}

#[test]
fn a_gone_network_whose_interface_stays_loses_its_peers() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-old"}]"#)
        .answer(
            "nft -j list map",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-old", {"jump": {"target": "n9_from"}}]]}}]}"#,
        )
        .answer("wg show wg-old allowed-ips", &format!("{K2}\t10.50.9.2/32\n"))
        .fail("ip link del wg-old");
    reconcile(&fake, &compiled(), dir.path());
    position(&fake.log(), &format!("wg set wg-old peer {K2} remove"));
}

fn registered_n1() -> Fake {
    Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer(
            "nft -j list map",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-n1", {"jump": {"target": "n1_from"}}]]}}]}"#,
        )
}

#[test]
fn a_lost_key_file_never_rotates_a_live_key() {
    let dir = keys();
    std::fs::remove_file(dir.path().join("n1.key")).unwrap();
    let fake = registered_n1();
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-n1: hub key: the interface has a key")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c == "wg genkey" || c.starts_with("wg set wg-n1 private-key"))
    );
    assert!(!dir.path().join("n1.key").exists());
    assert!(!out.hub_keys.iter().any(|(id, _)| *id == 1));
}

#[test]
fn an_interface_without_a_key_gets_one() {
    let dir = keys();
    std::fs::remove_file(dir.path().join("n1.key")).unwrap();
    let fake = registered_n1().answer("wg show wg-n1 public-key", "(none)\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    position(&fake.log(), "wg set wg-n1 private-key ");
    assert!(out.hub_keys.contains(&(1, format!("pub-{GENERATED}"))));
}

#[test]
fn a_stale_base_that_still_guards_lets_everything_else_apply() {
    let dir = keys();
    let fake = registered_n1()
        .fail_input("add set inet wgate tenant_space")
        .answer(
            "nft -j list set inet wgate tenant_space",
            r#"{"nftables": [{"set": {"name": "tenant_space", "elem": [{"prefix": {"addr": "10.50.0.0", "len": 16}}, {"prefix": {"addr": "192.168.0.0", "len": 16}}]}}]}"#,
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert!(out.errors[0].starts_with("base: "));
    let log = fake.log();
    position(&log, &format!("wg set wg-n1 peer {K1} allowed-ips"));
    assert_eq!(nft_runs(&log), 3, "base + both fragments");

    // One that does not cover today's tenant space: revocations only.
    let narrow = registered_n1()
        .fail_input("add set inet wgate tenant_space")
        .answer(
            "nft -j list set inet wgate tenant_space",
            r#"{"nftables": [{"set": {"name": "tenant_space", "elem": [{"prefix": {"addr": "10.50.0.0", "len": 24}}]}}]}"#,
        );
    reconcile(&narrow, &compiled(), dir.path());
    let log = narrow.log();
    // Nothing grows (n1's router has a LAN outside the guard, and n2 is not built),
    // but n1's fragment applies, cut down to what the stale guard covers.
    assert!(
        !log.iter()
            .any(|c| c.contains(" allowed-ips ") || c.starts_with("ip link add"))
    );
    assert_eq!(nft_runs(&log), 2, "base + n1's fragment");
}

#[test]
fn an_unregistered_leftover_of_a_gone_network_is_removed() {
    let dir = keys();
    std::fs::write(dir.path().join("n9.key"), hub_private(9)).unwrap();
    // A flushed table: nothing registered; wg-old and wg-n1 carry network 9's key.
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            r#"[{"ifname":"wg-old"},{"ifname":"wg-n1"},{"ifname":"wg-stray"}]"#,
        )
        .answer("wg show wg-old public-key", &hub_pub(9))
        .answer("wg show wg-n1 public-key", &hub_pub(9))
        .answer("wg show wg-stray public-key", "someone-elses\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    position(&log, "ip link del wg-old");
    // The slug is free again for network 1.
    assert!(position(&log, "ip link del wg-n1") < position(&log, "ip link add wg-n1"));
    assert!(!log.iter().any(|c| c == "ip link del wg-stray"));
}

#[test]
fn a_name_taken_again_after_removal_is_not_deleted() {
    let dir = keys();
    std::fs::write(dir.path().join("n9.key"), hub_private(9)).unwrap();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-old"}]"#)
        .answer(
            "nft -j list map",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-old", {"jump": {"target": "n9_from"}}]]}}]}"#,
        )
        .answer("wg show wg-old public-key", "someone-elses\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-old: carries a key")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c.starts_with("ip link del") || c.starts_with("wg set wg-old"))
    );
    // Its registration still goes.
    assert_eq!(nft_runs(&log), 4, "base, removal, both fragments");
}
