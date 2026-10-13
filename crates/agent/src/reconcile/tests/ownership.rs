//! What is wgate's (its mark), what it refuses, and how a new interface is made.

use super::*;

#[test]
fn an_unmarked_interface_is_left_alone_on_every_path() {
    for base_fails in [false, true] {
        let dir = keys();
        let mut fake = Fake::default()
            .answer(
                "ip -j link show type wireguard",
                &wg_links(&[("wg-n1", None)]),
            )
            .answer("nft -j list map", &registry(&[("wg-n1", 1)]))
            .answer(
                "wg show wg-n1 allowed-ips",
                &format!("{K2}\t10.50.0.3/32\n"),
            )
            .answer("wg show all listen-port", "wg-n1\t51802\n");
        if base_fails {
            fake = fake.fail_input("add set inet wgate tenant_space");
        }
        let out = reconcile(&fake, &compiled(), dir.path());
        assert!(
            out.errors.contains(&format!("wg-n1: {NOT_MADE}")),
            "{:?}",
            out.errors
        );
        let log = fake.log();
        let touched = |c: &String| {
            c.starts_with("wg set wg-n1") || c.ends_with("dev wg-n1") || c == "ip link del wg-n1"
        };
        assert!(
            !log.iter().any(touched),
            "base fails: {base_fails}: {log:#?}"
        );
        // Its registration goes: nothing on that name keeps network 1's rights.
        assert!(nft_runs(&log) >= 2, "{log:#?}");
    }
}

#[test]
fn a_link_that_is_not_wireguard_is_never_taken() {
    let dir = keys();
    let fake = Fake::default().answer("ip -j link show dev wg-n1", r#"[{"ifname":"wg-n1"}]"#);
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert!(out.errors[0].starts_with("wg-n1: the name is taken"));
    assert!(!fake.log().iter().any(|c| c.contains("wgtmp-1")));
}

#[test]
fn a_failed_creation_cleans_up_and_stops_its_network() {
    let dir = keys();
    let fake = Fake::default().fail("ip link set dev wgtmp-1 name");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors, ["wg-n1: create: boom"]);
    let log = fake.log();
    position(&log, "ip link del wgtmp-1");
    let built = |c: &String| c.starts_with("ip addr replace") || c.starts_with("wg set wg-n1");
    assert!(!log.iter().any(|c| built(c) && c.contains("wg-n1")));
    assert_eq!(out.hub_keys, [(2, hub_pub(2))]);
}

#[test]
fn a_key_that_cannot_be_issued_stops_a_new_network_before_its_interface() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::default().fail("wg genkey");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().all(|e| e.contains("hub key: ")),
        "{:?}",
        out.errors
    );
    assert!(!fake.log().iter().any(|c| c.starts_with("ip link add")));
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

fn owned_n1() -> Fake {
    Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer("nft -j list map", &registry(&[("wg-n1", 1)]))
}

#[test]
fn a_damaged_key_is_named_as_the_cause() {
    let dir = keys();
    std::fs::write(dir.path().join("n1.key"), "garbage").unwrap();
    let out = reconcile(&owned_n1(), &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("wg-n1: hub key: ")),
        "{:?}",
        out.errors
    );
}

#[test]
fn a_lost_key_file_never_rotates_a_live_key() {
    let dir = keys();
    std::fs::remove_file(dir.path().join("n1.key")).unwrap();
    let fake = owned_n1();
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
    let fake = owned_n1().answer("wg show wg-n1 public-key", "(none)\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    position(&fake.log(), "wg set wg-n1 private-key ");
    assert!(out.hub_keys.contains(&(1, public_of(GENERATED))));
}

#[test]
fn a_stale_base_that_still_guards_lets_everything_else_apply() {
    let dir = keys();
    let fake = owned_n1()
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

    // One that does not cover today's tenant space: nothing grows (n1's router has a
    // LAN outside the guard, n2 is not made), but n1's fragment applies, cut down.
    let narrow = owned_n1()
        .fail_input("add set inet wgate tenant_space")
        .answer(
            "nft -j list set inet wgate tenant_space",
            r#"{"nftables": [{"set": {"name": "tenant_space", "elem": [{"prefix": {"addr": "10.50.0.0", "len": 24}}]}}]}"#,
        );
    reconcile(&narrow, &compiled(), dir.path());
    let log = narrow.log();
    assert!(
        !log.iter()
            .any(|c| c.contains(" allowed-ips ") || c.starts_with("ip link add"))
    );
    assert_eq!(nft_runs(&log), 2, "base + n1's fragment");
}

#[test]
fn leftovers_of_gone_networks_are_removed_and_unregistered() {
    let dir = keys();
    // A flushed table: nothing registered. wg-old and wg-n1 carry network 9's mark;
    // a scratch link of a crashed creation is left too.
    let fake = Fake::default().answer(
        "ip -j link show type wireguard",
        &wg_links(&[
            ("wg-old", Some(9)),
            ("wg-n1", Some(9)),
            ("wgtmp-5", None),
            ("wg-stray", None),
        ]),
    );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    position(&log, "ip link del wg-old");
    position(&log, "ip link del wgtmp-5");
    // The slug is free again for network 1.
    assert!(position(&log, "ip link del wg-n1") < position(&log, "ip link add wgtmp-1"));
    assert!(!log.iter().any(|c| c == "ip link del wg-stray"));
    // base, snat, both leftovers' unregistration, both networks.
    assert_eq!(nft_runs(&log), 5);
}

#[test]
fn a_name_taken_again_after_removal_is_not_deleted() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-old", None)]),
        )
        .answer("nft -j list map", &registry(&[("wg-old", 9)]));
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    assert!(
        !log.iter()
            .any(|c| c.starts_with("ip link del") || c.starts_with("wg set wg-old"))
    );
    // Its registration still goes.
    assert_eq!(nft_runs(&log), 4, "base, removal, both fragments");
}

#[test]
fn a_network_that_cannot_be_made_loses_a_stale_registration() {
    let dir = keys();
    // wg-n1 was deleted by hand; its registration is still there.
    let fake = Fake::default()
        .answer("nft -j list map", &registry(&[("wg-n1", 1)]))
        .fail("ip link add wgtmp-1");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(
        out.errors.iter().any(|e| e.starts_with("wg-n1: create")),
        "{:?}",
        out.errors
    );
    let removal = "delete element inet wgate from_net { \"wg-n1\" }";
    assert!(fake.inputs.borrow().iter().any(|i| i.contains(removal)));
}
