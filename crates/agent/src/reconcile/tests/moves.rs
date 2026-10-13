//! Addresses and LANs that move between peers and networks, and revocations.

use super::*;

#[test]
fn one_failing_revocation_does_not_keep_the_others() {
    let dir = keys();
    let stale = |k: &str, ip: &str| format!("{k}\t{ip}\n");
    let k3 = format!("{:0>42}A=", 3);
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!(
                "{}{}",
                stale(K2, "10.50.0.3/32"),
                stale(&k3, "10.50.0.4/32")
            ),
        )
        .fail(&format!("wg set wg-n1 peer {K2} remove"));
    let out = reconcile(&fake, &compiled(), dir.path());
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    position(&fake.log(), &format!("wg set wg-n1 peer {k3} remove"));
}

#[test]
fn a_lan_moves_between_networks_in_one_reconcile() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .answer(
            "ip -j route show dev wg-n2",
            r#"[{"dst":"192.168.1.0/24","scope":"link","flags":[]}]"#,
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    let del = position(&log, "ip route del 192.168.1.0/24 dev wg-n2");
    let add = position(&log, "ip route add 192.168.1.0/24 dev wg-n1");
    assert!(del < add);
}

#[test]
fn what_a_peer_loses_goes_before_the_rules_change() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer(
            "wg show wg-n1 allowed-ips",
            &format!("{K1}\t10.50.0.2/32 192.168.1.0/24 192.168.7.0/24\n"),
        );
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    let narrow = position(
        &log,
        &format!("wg set wg-n1 peer {K1} allowed-ips 10.50.0.2/32,192.168.1.0/24"),
    );
    assert!(narrow < nft_run(&log, 1));
}
