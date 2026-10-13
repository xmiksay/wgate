//! Networks that are gone, and what holds when the base or the inventory fails.

use super::*;

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
fn a_reused_slug_gets_a_fresh_network() {
    let dir = keys();
    let old_key = format!("{:0>42}A=", 9);
    std::fs::write(dir.path().join("n9.key"), &old_key).unwrap();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer("wg show wg-n1 public-key", &format!("pub-{old_key}\n"))
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
    assert!(out.hub_keys.contains(&(1, hub_pub(1))));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("n9.key")).unwrap(),
        old_key
    );
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
fn without_the_base_only_revocations_apply() {
    let dir = keys();
    let fake = Fake::default()
        .fail("nft -f -")
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K2}\t10.50.0.3/32\n"),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors[0].starts_with("base: "), "{:?}", out.errors);
    let log = fake.log();
    position(&log, &format!("wg set wg-n1 peer {K2} remove"));
    assert_eq!(log.iter().filter(|c| c.as_str() == "nft -f -").count(), 1);
    assert!(
        !log.iter()
            .any(|c| c.contains(" allowed-ips ") || c.starts_with("ip link add"))
    );
    assert!(out.hub_keys.is_empty());
}

#[test]
fn a_failed_removal_holds_back_the_network_reusing_its_interface() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer(
            "nft -j list map",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-n1", {"jump": {"target": "n9_from"}}]]}}]}"#,
        )
        .answer("wg show wg-n1 public-key", "(none)\n")
        .fail("ip link del wg-n1");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("wg-n1: waits")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c.contains("dev wg-n1") || c.starts_with("wg set wg-n1"))
    );
    position(&log, "ip link add wg-n2");
}

#[test]
fn an_unregistered_network_gets_no_interface() {
    let dir = keys();
    // n1's fragment fails; n2's applies.
    let fake = Fake {
        fail_input: Some("chain inet wgate n1_from".into()),
        ..Fake::default()
    };
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors, ["wg-n1: nft: boom"]);
    let log = fake.log();
    assert!(!log.iter().any(|c| c.starts_with("ip link add wg-n1")));
    assert!(log.iter().any(|c| c.starts_with("ip link add wg-n2")));
}
