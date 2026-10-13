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
    assert_eq!(out.hub_keys, [(2, "hubpub".into())]);
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
    assert_eq!(out.hub_keys, [(2, "hubpub".into())]);
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
            .any(|c| c.contains("allowed-ips") || c.starts_with("ip link add"))
    );
}
