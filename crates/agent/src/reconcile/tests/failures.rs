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
fn a_registered_name_with_someone_elses_key_is_refused() {
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
        out.errors.contains(&format!("wg-n1: {NOT_MADE}")),
        "{:?}",
        out.errors
    );
    assert!(!fake.log().iter().any(|c| c.starts_with("wg set wg-n1")));
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
