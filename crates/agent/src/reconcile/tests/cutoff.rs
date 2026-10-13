//! When a network's rules cannot be brought up to date, it is cut off rather than
//! left on its old rights.

use super::*;

fn owned_n1() -> Fake {
    Fake::default().answer(
        "ip -j link show type wireguard",
        &wg_links(&[("wg-n1", Some(1))]),
    )
}

fn cutoffs(fake: &Fake, id: Id) -> usize {
    // Only a cutoff drops everything on ingress (a fragment drops unknown sources).
    let drop = format!("add rule inet wgate n{id}_ingress counter drop");
    fake.inputs
        .borrow()
        .iter()
        .filter(|i| i.contains(&drop))
        .count()
}

#[test]
fn a_fragment_that_fails_cuts_its_network_off() {
    let dir = keys();
    let fake = owned_n1().fail_input("flush set inet wgate n1_peers");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e == "wg-n1: nft: boom"),
        "{:?}",
        out.errors
    );
    assert_eq!(cutoffs(&fake, 1), 1);
    assert_eq!(cutoffs(&fake, 2), 0);
}

#[test]
fn with_the_guard_unknown_every_network_is_cut_off() {
    let dir = keys();
    // The base fails and its tenant space cannot be read.
    let fake = owned_n1().fail_input("add set inet wgate tenant_space");
    reconcile(&fake, &compiled(), dir.path());
    assert_eq!(cutoffs(&fake, 1), 1);
    assert!(fake.fragments_of(1).is_empty());
}

#[test]
fn what_a_stuck_interface_still_routes_is_held() {
    let dir = keys();
    let fake = owned_n1()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-old", Some(9))]),
        )
        .fail("ip link del wg-old")
        .answer(
            "ip -j route show dev wg-old",
            r#"[{"dst":"192.168.1.0/24","scope":"link","flags":[]}]"#,
        )
        .fail("ip route del 192.168.1.0/24 dev wg-old");
    let out = reconcile(&fake, &compiled(), dir.path());
    // n1's router may not take the LAN the stuck wg-old still routes.
    assert!(
        !fake
            .log()
            .iter()
            .any(|c| c.starts_with("ip route add 192.168.1.0/24"))
    );
    assert!(
        out.errors
            .iter()
            .any(|e| e.contains("wait for routes still held")),
        "{:?}",
        out.errors
    );
    assert!(!fake.fragments_of(1)[0].contains("192.168.1.0/24"));
}

#[test]
fn an_unreadable_link_in_the_fallback_is_named() {
    let dir = keys();
    let fake = Fake::default()
        .fail("ip -j link show type wireguard")
        .fail("ip -j -d link show dev wg-n1");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-n1: no revocations without its link")),
        "{:?}",
        out.errors
    );
}
