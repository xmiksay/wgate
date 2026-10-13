//! Ports that move between networks.

use super::*;

#[test]
fn swapped_ports_are_freed_first() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1)), ("wg-n2", Some(2))]),
        )
        .answer("wg show all listen-port", "wg-n1\t51802\nwg-n2\t51801\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let log = fake.log();
    let free1 = position(&log, "wg set wg-n1 listen-port 51900");
    let free2 = position(&log, "wg set wg-n2 listen-port 51901");
    let take1 = position(&log, "wg set wg-n1 listen-port 51801");
    assert!(free1 < take1 && free2 < take1);
}

#[test]
fn a_port_nobody_else_wants_is_not_freed() {
    let dir = keys();
    let fake = Fake::default()
        .answer(
            "ip -j link show type wireguard",
            &wg_links(&[("wg-n1", Some(1))]),
        )
        .answer("wg show all listen-port", "wg-n1\t51900\nwg-n2\t51802\n");
    let out = reconcile(&fake, &compiled(), dir.path());
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert!(!fake.log().iter().any(|c| c.contains("listen-port 519")));
}
