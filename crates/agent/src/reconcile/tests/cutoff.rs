//! A network whose rules fail to apply is cut off rather than left on its old
//! rights; when the agent cannot see (no links, no guard), the kernel is left as it is.

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
fn with_the_guard_unknown_the_kernel_is_left_as_it_is() {
    let dir = keys();
    // The base fails and its tenant space cannot be read.
    let fake = owned_n1()
        .fail_input("add set inet wgate tenant_space")
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K2}\t10.50.0.3/32\n"),
        );
    reconcile(&fake, &compiled(), dir.path());
    assert_eq!(cutoffs(&fake, 1), 0);
    assert!(fake.fragments_of(1).is_empty());
    // Peer revocations need no guard.
    position(&fake.log(), &format!("wg set wg-n1 peer {K2} remove"));
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
    assert!(!fake.fragments_of(1)[0].contains("192.168.1.0-192.168.1.255"));
}

#[test]
fn the_list_of_links_falls_back_to_every_links_details() {
    let dir = keys();
    let fake = Fake::default()
        .fail("ip -j link show type wireguard")
        .answer(
            "ip -j -d link show",
            r#"[{"ifname":"eth0","linkinfo":null},{"ifname":"wg-n1","ifalias":"wgate:n1","linkinfo":{"info_kind":"wireguard"}},{"ifname":"wg-n2","linkinfo":{"info_kind":"veth"}}]"#,
        )
        .answer("ip -j link show dev wg-n2", r#"[{"ifname":"wg-n2"}]"#);
    let out = reconcile(&fake, &compiled(), dir.path());
    // wg-n1 is wgate's and built; wg-n2 is not WireGuard, so it is not taken.
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-n2: the name is taken")),
        "{:?}",
        out.errors
    );
    position(&fake.log(), &format!("wg set wg-n1 peer {K1} allowed-ips"));
}

#[test]
fn without_any_list_of_links_the_kernel_is_left_as_it_is() {
    let dir = keys();
    let fake = Fake::default()
        .fail("ip -j link show type wireguard")
        .fail("ip -j -d link show")
        .answer(
            "nft -j list map inet wgate from_net",
            &registry(&[("wg-n1", 1), ("wg-old", 9)]),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("inventory: ")),
        "{:?}",
        out.errors
    );
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c.starts_with("wg set") || c.starts_with("ip link"))
    );
    assert!(fake.fragments_of(1).is_empty() && fake.fragments_of(2).is_empty());
    // A network no longer compiled is still unregistered: that needs no links.
    let removal = "delete element inet wgate from_net { \"wg-old\" }";
    assert!(fake.inputs.borrow().iter().any(|i| i.contains(removal)));
}

#[test]
fn a_network_not_made_gets_no_registration_while_nothing_grows() {
    let dir = keys();
    let fake = owned_n1().fail("nft -j list map inet wgate from_net");
    reconcile(&fake, &compiled(), dir.path());
    assert_eq!(fake.fragments_of(1).len(), 1);
    assert!(fake.fragments_of(2).is_empty(), "wg-n2 does not exist");
}

#[test]
fn an_unreadable_route_list_still_lets_peers_be_revoked() {
    let dir = keys();
    let fake = owned_n1().fail("ip -j route show dev wg-n1").answer(
        "wg show wg-n1 allowed-ips",
        &format!("{K2}\t10.50.0.3/32\n"),
    );
    reconcile(&fake, &compiled(), dir.path());
    let log = fake.log();
    position(&log, &format!("wg set wg-n1 peer {K2} remove"));
    // Its rules apply; no route of its is added.
    assert_eq!(fake.fragments_of(1).len(), 1);
    assert!(!log.iter().any(|c| c.starts_with("ip route add")));
    // n2 is made as usual.
    position(&log, "ip link add wgtmp-2");
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
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("wg-old (gone): disarm")),
        "{:?}",
        out.errors
    );
    // What it still holds is unknown, so nothing is known to be free.
    assert!(!fake.log().iter().any(|c| c.starts_with("ip link add")));
}

#[test]
fn an_unreadable_network_whose_last_rules_are_unknown_stops_growth() {
    let dir = keys();
    let fake = owned_n1()
        .fail("wg show wg-n1 allowed-ips")
        .fail("nft -j list set inet wgate n1_peers");
    reconcile(&fake, &compiled(), dir.path());
    assert!(!fake.log().iter().any(|c| c.starts_with("ip link add")));
}

#[test]
fn a_registration_shown_not_to_be_wgates_goes() {
    let dir = keys();
    let fake = Fake::default()
        .fail("ip -j link show type wireguard")
        .answer(
            "ip -j -d link show",
            r#"[{"ifname":"wg-n1","linkinfo":{"info_kind":"wireguard"}}]"#,
        )
        .answer(
            "nft -j list map inet wgate from_net",
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

#[test]
fn a_full_tenant_space_without_its_guard_rules_guards_nothing() {
    let dir = keys();
    // The base fails; the set is still full, but the prerouting rules are gone.
    let fake = owned_n1()
        .fail_input("add set inet wgate tenant_space")
        .answer(
            "nft -j list set inet wgate tenant_space",
            r#"{"nftables": [{"set": {"name": "tenant_space", "elem": [{"prefix": {"addr": "0.0.0.0", "len": 0}}]}}]}"#,
        )
        .answer("nft -j list chain inet wgate prerouting", r#"{"nftables": []}"#);
    reconcile(&fake, &compiled(), dir.path());
    // Treated as unknown: the kernel is left as it is, nothing grows.
    assert!(fake.fragments_of(1).is_empty());
    assert!(!fake.log().iter().any(|c| c.starts_with("ip link add")));
}

#[test]
fn an_unreadable_route_list_does_not_block_its_own_peers() {
    let dir = keys();
    let fake = owned_n1().fail("ip -j route show dev wg-n1");
    reconcile(&fake, &compiled(), dir.path());
    // Its new router joins; only its LAN route waits.
    position(&fake.log(), &format!("wg set wg-n1 peer {K1} allowed-ips"));
    assert!(!fake.log().iter().any(|c| c.starts_with("ip route add")));
}
