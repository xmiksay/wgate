//! Revocation and disabling against live TCP streams: what is cut stops within a
//! second of the API call; everything else keeps flowing. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use common::{NODE, World, lines_until, longest_gap, stream, tcp_ok};
use serde_json::json;

const CUT: Duration = Duration::from_secs(1);
/// The stream echoes every 100 ms; a longer silence means it stalled.
const STALL: Duration = Duration::from_millis(500);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and Docker: make test-netns"]
async fn revocation_cuts_live_streams_only_where_it_should() {
    let w = World::new().await;
    let node_8080 = json!({ "dst": "172.19.9.11/32", "proto": "tcp", "port_from": 8080 });
    let a = w.tenant("a", "10.50.0.0/24").await;
    let b = w.tenant("b", "10.50.1.0/24").await;
    for t in [a.0, b.0] {
        w.admin
            .create(&format!("/tenants/{t}/ceilings"), node_8080.clone())
            .await;
    }
    let a1 = w.network(a, "a1", "10.50.0.0/25", 51801).await;
    let a2 = w.network(a, "a2", "10.50.0.128/25", 51802).await;
    let b1 = w.network(b, "b1", "10.50.1.0/25", 51803).await;
    for n in [a1, a2, b1] {
        w.admin_create(&format!("/networks/{n}/rules"), node_8080.clone())
            .await;
    }
    // One device in two networks, one tunnel each; another A1 member; a B1 member.
    let laptop = w.device(a.0, "laptop").await;
    let (in_a1, d1) = w.peer_host("d1", laptop, a1, "10.50.0.2").await;
    let (_, d2) = w.peer_host("d2", laptop, a2, "10.50.0.130").await;
    let (_, e1) = w
        .peer_host("e1", w.device(a.0, "desk").await, a1, "10.50.0.3")
        .await;
    let (_, f1) = w
        .peer_host("f1", w.device(b.0, "phone").await, b1, "10.50.1.2")
        .await;
    let (s_d1, s_d2, s_e1, s_f1) = (
        stream(&d1.ns, NODE, 8080),
        stream(&d2.ns, NODE, 8080),
        stream(&e1.ns, NODE, 8080),
        stream(&f1.ns, NODE, 8080),
    );

    // Revoking the laptop's A1 peer kills its stream within a second.
    let (status, v) = w
        .admin
        .post(&format!("/peers/{in_a1}/revoke"), json!({}))
        .await;
    assert!(status.is_success(), "{v}");
    let revoked = Instant::now();
    let until = revoked + CUT * 2;
    let cut = lines_until(&s_d1, until);
    let since = |at: &[Instant]| at.last().map(|t| t.duration_since(revoked));
    assert!(
        cut.iter().all(|t| *t < revoked + CUT),
        "the revoked stream ran on: {:?}",
        since(&cut)
    );
    // The same device's A2 tunnel and the other A1 member are untouched.
    for (what, s) in [("A2 tunnel", &s_d2), ("A1 member", &s_e1)] {
        let at = lines_until(s, until);
        assert!(
            longest_gap(revoked, until, &at) < STALL,
            "{what} stalled: {at:?}"
        );
        assert!(since(&at) > Some(CUT), "{what} stopped");
    }
    w.settle().await;
    assert!(!tcp_ok(&d1.ns, NODE, 8080), "revoked");
    assert!(tcp_ok(&d2.ns, NODE, 8080), "the A2 peer keeps working");
    let peers = w.hub.output(&["wg", "show", "wg-a1", "peers"]);
    assert_eq!(peers.lines().count(), 1, "only e1 is left: {peers}");

    // Disabling B1 deletes its interface while A1's stream keeps running.
    w.admin
        .patch(&format!("/networks/{b1}"), json!({ "disabled": true }))
        .await;
    let disabled = Instant::now();
    w.settle().await;
    assert!(
        !w.hub.output(&["ip", "link"]).contains("wg-b1"),
        "wg-b1 is gone"
    );
    let until = Instant::now() + CUT;
    let gone = lines_until(&s_f1, until);
    assert!(
        gone.iter().all(|t| *t < disabled + CUT),
        "B1's stream ran on"
    );
    let at = lines_until(&s_e1, until);
    assert!(
        longest_gap(disabled, until, &at) < STALL,
        "A1's stream stalled: {at:?}"
    );
    assert!(tcp_ok(&e1.ns, NODE, 8080), "A1 still works");
    assert!(!tcp_ok(&f1.ns, NODE, 8080), "B1 is off");
}
