//! Root-only tests in throwaway network namespaces: the kernel accepts what core
//! renders. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::net::Ipv4Addr;

use common::Netns;
use wgate_core::{
    DesiredState, compile, render_base, render_network_cutoff, render_network_removal, render_snat,
};

/// The kernel features the design depends on: a `wg-*` interface and an nft set
/// with concatenated interval keys (design.md → Risks).
#[test]
#[ignore = "needs root: make test-netns"]
fn kernel_supports_wg_and_concat_interval_sets() {
    let ns = Netns::new("smoke");
    ns.exec(
        &["ip", "link", "add", "wg-smoke", "type", "wireguard"],
        None,
    );
    ns.exec(
        &["nft", "-f", "-"],
        Some(
            "table inet wgate {
               set allow {
                 type ipv4_addr . ipv4_addr . inet_proto . inet_service; flags interval;
                 elements = { 10.50.1.2 . 172.16.16.1 . tcp . 6443,
                              10.50.1.0/24 . 172.19.9.10-172.19.9.12 . udp . 1000-2000 }
               }
             }",
        ),
    );
}

/// The rendered ruleset golden (core: the base plus every network's fragment) must be
/// accepted by the kernel (overlapping interval elements are rejected), re-applying it
/// must work, and removing the networks and re-applying an empty base must leave
/// nothing of theirs behind.
#[test]
#[ignore = "needs root: make test-netns"]
fn rendered_ruleset_loads_reapplies_and_removes() {
    let golden = include_str!("../../core/tests/golden/ruleset.nft");
    let ns = Netns::new("ruleset");
    ns.exec(&["nft", "-f", "-"], Some(golden));
    ns.exec(&["nft", "-f", "-"], Some(golden));
    let listed = ns.output(&["nft", "list", "table", "inet", "wgate"]);
    assert!(listed.contains("10.50.1.2 . "), "{listed}");

    for (id, iface) in [(1, "wg-nexial"), (2, "wg-nexial-dev"), (3, "wg-krcmar")] {
        // Twice: a removal applies whatever is already gone.
        for _ in 0..2 {
            ns.exec(
                &["nft", "-f", "-"],
                Some(&render_network_removal(id, iface)),
            );
        }
    }
    // A cutoff, then a removal, of a network that never existed.
    ns.exec(&["nft", "-f", "-"], Some(&render_network_cutoff(9)));
    ns.exec(
        &["nft", "-f", "-"],
        Some(&render_network_removal(9, "wg-gone")),
    );
    let empty = compile(&DesiredState {
        pool: vec![],
        snat_source: Ipv4Addr::new(172, 19, 9, 10),
        node_cidrs: vec![],
        routed_space: vec![],
        reserved: vec![],
        tenants: vec![],
        networks: vec![],
        peers: vec![],
        federations: vec![],
    });
    ns.exec(&["nft", "-f", "-"], Some(&render_base(&empty)));
    ns.exec(&["nft", "-f", "-"], Some(&render_snat(&empty)));
    let listed = ns.output(&["nft", "list", "table", "inet", "wgate"]);
    for stale in ["10.50.", "n1_", "n2_", "n9_", "wg-nexial", "snat"] {
        assert!(!listed.contains(stale), "{stale} survived:\n{listed}");
    }
}
