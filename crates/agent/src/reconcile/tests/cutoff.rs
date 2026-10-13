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

#[test]
fn a_network_not_made_gets_no_registration_while_nothing_grows() {
    let dir = keys();
    let fake = owned_n1().fail("wg show wg-n1 allowed-ips");
    reconcile(&fake, &compiled(), dir.path());
    assert_eq!(fake.fragments_of(1).len(), 1);
    assert!(fake.fragments_of(2).is_empty(), "wg-n2 does not exist");
}

#[test]
fn an_unreadable_route_list_stops_growth_too() {
    let dir = keys();
    let fake = owned_n1().fail("ip -j route show dev wg-n1");
    reconcile(&fake, &compiled(), dir.path());
    assert!(!fake.log().iter().any(|c| c.starts_with("ip link add")));
}

#[test]
fn a_stuck_interface_whose_leftovers_are_unknown_stops_growth() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-old", Some(9))]),
        )
        .fail("ip link del wg-old")
        .fail("wg show wg-old allowed-ips");
    reconcile(&fake, &compiled(), dir.path());
    let log = fake.log();
    assert!(!log.iter().any(|c| c.starts_with("ip link add")));
    // Not registered: it is not unregistered over and over either.
    assert_eq!(nft_runs(&log), 1, "the base only: {log:#?}");
}

#[test]
fn a_registration_shown_not_to_be_wgates_goes_without_the_full_list() {
    let dir = keys();
    let fake = Fake::default()
        .fail("ip -j link show type wireguard")
        .answer(
            "ip -j -d link show dev wg-n1",
            r#"[{"ifname":"wg-n1","linkinfo":{"info_kind":"wireguard"}}]"#,
        )
        .answer(
            "nft -j list map",
            r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-n1", {"jump": {"target": "n1_from"}}]]}}]}"#,
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.contains(&format!("wg-n1: {NOT_MADE}")),
        "{:?}",
        out.errors
    );
    let removal = "delete element inet wgate from_net { \"wg-n1\" }";
    assert!(fake.inputs.borrow().iter().any(|i| i.contains(removal)));
}
