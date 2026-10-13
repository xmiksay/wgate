//! Failed reads and writes that must never turn into an irreversible step.

use super::*;

fn registered(elems: &str) -> String {
    format!(r#"{{"nftables": [{{"map": {{"name": "from_net", "elem": [{elems}]}}}}]}}"#)
}

#[test]
fn a_failed_fragment_holds_back_what_would_grow_on_stale_rules() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .fail_input("chain inet wgate n1_from");
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
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer(
            "nft -j list map",
            &registered(r#"["wg-n1", {"jump": {"target": "n1_from"}}]"#),
        )
        .fail("wg show wg-n1 public-key");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("wg-n1: ")),
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
fn a_gone_network_whose_key_cannot_be_read_is_not_deleted() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-old"}]"#)
        .answer(
            "nft -j list map",
            &registered(r#"["wg-old", {"jump": {"target": "n9_from"}}]"#),
        )
        .fail("wg show wg-old public-key");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-old (removing network 9)"))
    );
    assert!(!fake.log().iter().any(|c| c.starts_with("ip link del")));
}

#[test]
fn a_registered_name_with_someone_elses_key_gets_only_its_rules() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer(
            "nft -j list map",
            &registered(r#"["wg-n1", {"jump": {"target": "n1_from"}}]"#),
        )
        .answer("wg show wg-n1 public-key", "someone-elses\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-n1: carries a key")
                && e.ends_with("only its rules are applied")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c.starts_with("wg set wg-n1") || c.ends_with("dev wg-n1"))
    );
    assert_eq!(nft_runs(&log), 3, "base + n1's rules + n2");
}

#[test]
fn a_damaged_key_still_lets_revocations_in_the_rules_apply() {
    let dir = keys();
    std::fs::write(dir.path().join("n1.key"), "garbage").unwrap();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-n1"}]"#)
        .answer(
            "nft -j list map",
            &registered(r#"["wg-n1", {"jump": {"target": "n1_from"}}]"#),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.contains("not a WireGuard key")),
        "{:?}",
        out.errors
    );
    assert_eq!(nft_runs(&fake.log()), 3, "n1's rules still applied");
}

#[test]
fn a_gone_network_is_unregistered_even_when_its_interface_stays() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-old"}]"#)
        .answer(
            "nft -j list map",
            &registered(r#"["wg-old", {"jump": {"target": "n9_from"}}]"#),
        )
        .fail("ip link del wg-old");
    let out = reconcile(&fake, &compiled(), dir.path());
    let log = fake.log();
    // Disarmed, and its registration still went.
    position(&log, "ip addr flush dev wg-old");
    assert!(nft_run(&log, 1) > position(&log, "ip link del wg-old"));
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-old (removing network 9)"))
    );
}

#[test]
fn a_gone_interface_whose_key_cannot_be_checked_is_left_alone() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-old"}]"#)
        .answer(
            "nft -j list map",
            &registered(r#"["wg-old", {"jump": {"target": "n9_from"}}]"#),
        )
        .answer("wg show wg-old public-key", "some-key\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.contains("key file is missing")),
        "{:?}",
        out.errors
    );
    assert!(!fake.log().iter().any(|c| c.starts_with("ip link del")));
}

#[test]
fn a_stuck_gone_interface_lets_go_of_a_wanted_port() {
    let dir = keys();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-old"}]"#)
        .answer(
            "nft -j list map",
            &registered(r#"["wg-old", {"jump": {"target": "n9_from"}}]"#),
        )
        .answer("wg show all listen-port", "wg-old\t51801\n")
        .fail("ip link del wg-old");
    reconcile(&fake, &compiled(), dir.path());
    let log = fake.log();
    assert!(
        position(&log, "wg set wg-old listen-port 0") < position(&log, "wg set wg-n1 listen-port")
    );
}

#[test]
fn a_blocked_interface_wgate_does_not_own_keeps_its_port() {
    let dir = keys();
    std::fs::write(dir.path().join("n9.key"), hub_private(9)).unwrap();
    let fake = Fake::default()
        .answer("ip -j link show type wireguard", r#"[{"ifname":"wg-x"}]"#)
        .answer(
            "nft -j list map",
            &registered(r#"["wg-x", {"jump": {"target": "n9_from"}}]"#),
        )
        .answer("wg show wg-x public-key", "someone-elses\n")
        .answer("wg show all listen-port", "wg-x\t51801\n")
        .fail_input("delete chain inet wgate n9_");
    reconcile(&fake, &compiled(), dir.path());
    assert!(!fake.log().iter().any(|c| c.starts_with("wg set wg-x")));
}

#[test]
fn a_freed_port_landing_on_a_wanted_one_is_picked_again() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            r#"[{"ifname":"wg-n1"},{"ifname":"wg-n2"}]"#,
        )
        .answer("wg show all listen-port", "wg-n1\t51802\n")
        // The kernel keeps handing out a port network 2 wants.
        .answer("wg show wg-n1 listen-port", "51802\n");
    reconcile(&fake, &compiled(), dir.path());
    let picks = fake
        .log()
        .iter()
        .filter(|c| *c == "wg set wg-n1 listen-port 0")
        .count();
    assert_eq!(picks, 5, "bounded retries");
}
