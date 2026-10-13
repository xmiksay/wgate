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
fn a_freed_port_landing_on_a_wanted_one_is_picked_again() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .answer("wg show all listen-port", "wg-n1\t51802\n")
        // The kernel keeps handing out a port network 2 wants.
        .answer("wg show wg-n1 listen-port", "51802\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    let picks = fake
        .log()
        .iter()
        .filter(|c| *c == "wg set wg-n1 listen-port 0")
        .count();
    assert_eq!(picks, 5, "bounded retries");
    assert!(
        out.errors
            .iter()
            .any(|e| e.ends_with("every pick was a wanted port"))
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
