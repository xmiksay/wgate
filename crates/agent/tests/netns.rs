//! Root-only tests in throwaway network namespaces: the kernel accepts what core
//! renders. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::net::Ipv4Addr;

use common::Netns;
use wgate_core::{Compiled, NftState, render_nft};

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

/// The rendered ruleset golden (core) must be accepted by the kernel — overlapping
/// interval elements are rejected — and applying another render must replace it.
#[test]
#[ignore = "needs root: make test-netns"]
fn rendered_ruleset_loads_and_replaces() {
    let ns = Netns::new("ruleset");
    ns.exec(
        &["nft", "-f", "-"],
        Some(include_str!("../../core/tests/golden/ruleset.nft")),
    );
    assert!(
        ns.output(&["nft", "list", "table", "inet", "wgate"])
            .contains("10.50.1.2 . ")
    );

    let empty = render_nft(&NftState {
        snat_source: Ipv4Addr::new(172, 19, 9, 10),
        node_cidrs: vec![],
        compiled: Compiled::default(),
    });
    ns.exec(&["nft", "-f", "-"], Some(&empty));
    let listed = ns.output(&["nft", "list", "table", "inet", "wgate"]);
    assert!(
        !listed.contains("10.50.1."),
        "stale elements survived:\n{listed}"
    );
    assert!(!listed.contains("snat"), "stale snat survived:\n{listed}");
}
