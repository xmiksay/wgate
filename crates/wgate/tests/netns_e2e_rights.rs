//! Rights between peers end to end: the mesh flag, a rule between two networks of a
//! tenant (one way), and federation across tenants, which a tenant admin cannot make.
//! Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::api::sign_in;
use common::{World, tcp_ok};
use serde_json::json;

const A1X: &str = "10.50.0.2";
const A1Y: &str = "10.50.0.3";
const A2: &str = "10.50.0.130";
const B1: &str = "10.50.1.2";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and Docker: make test-netns"]
async fn mesh_rules_and_federation() {
    let w = World::new().await;
    let a = w.tenant("a", "10.50.0.0/24").await;
    let b = w.tenant("b", "10.50.1.0/24").await;
    let a1 = w.network(a, "a1", "10.50.0.0/25", 51801).await;
    let a2 = w.network(a, "a2", "10.50.0.128/25", 51802).await;
    let b1 = w.network(b, "b1", "10.50.1.0/25", 51803).await;
    let (dx, dy, d2, db) = (
        w.device(a.0, "x").await,
        w.device(a.0, "y").await,
        w.device(a.0, "z").await,
        w.device(b.0, "w").await,
    );
    let (_, x) = w.peer_host("a1x", dx, a1, A1X).await;
    let (_, y) = w.peer_host("a1y", dy, a1, A1Y).await;
    let (_, z) = w.peer_host("a2", d2, a2, A2).await;
    let (_, v) = w.peer_host("b1", db, b1, B1).await;
    let tcp = json!({ "proto": "tcp", "port_from": 7000 });

    // Default deny inside a network, until it is a mesh.
    assert!(!tcp_ok(&x.ns, A1Y, 7000), "mesh off");
    assert!(!tcp_ok(&y.ns, A1X, 7000), "mesh off");
    w.admin
        .patch(&format!("/networks/{a1}"), json!({ "mesh": true }))
        .await;
    w.settle().await;
    assert!(tcp_ok(&x.ns, A1Y, 7000), "mesh on");
    assert!(tcp_ok(&y.ns, A1X, 7000), "mesh on");

    // A1 → A2 only with a rule A1 → A2, and only that way.
    assert!(!tcp_ok(&x.ns, A2, 7000), "no rule yet");
    let mut rule = tcp.clone();
    rule["target_network_id"] = json!(a2);
    w.admin_create(&format!("/networks/{a1}/rules"), rule).await;
    assert!(tcp_ok(&x.ns, A2, 7000), "rule A1 → A2");
    assert!(tcp_ok(&y.ns, A2, 7000), "rule A1 → A2");
    assert!(!tcp_ok(&z.ns, A1X, 7000), "A2 → A1 stays denied");
    assert!(!tcp_ok(&x.ns, A2, 7001), "only the rule's port");

    // A1 → B1: denied, and a tenant admin of A cannot open it.
    assert!(!tcp_ok(&x.ns, B1, 7000), "another tenant");
    let ta = sign_in(&w.db, &w.app, "admin@a.test", "tenant_admin", Some(a.0)).await;
    let mut cross = tcp.clone();
    cross["target_network_id"] = json!(b1);
    let rules = format!("/networks/{a1}/rules");
    ta.expect(
        StatusCode::UNPROCESSABLE_ENTITY,
        Method::POST,
        &rules,
        Some(cross),
    )
    .await;
    let mut external = tcp.clone();
    external["dst"] = json!("10.50.1.0/25");
    ta.expect(
        StatusCode::UNPROCESSABLE_ENTITY,
        Method::POST,
        &rules,
        Some(external),
    )
    .await;
    let mut fed = tcp.clone();
    fed["from_network_id"] = json!(a1);
    fed["to_network_id"] = json!(b1);
    ta.expect(
        StatusCode::FORBIDDEN,
        Method::POST,
        "/federations",
        Some(fed.clone()),
    )
    .await;
    w.settle().await;
    assert!(!tcp_ok(&x.ns, B1, 7000), "still denied");

    // A federation by the global admin opens it, one way.
    w.admin_create("/federations", fed).await;
    assert!(tcp_ok(&x.ns, B1, 7000), "federation A1 → B1");
    assert!(!tcp_ok(&v.ns, A1X, 7000), "B1 → A1 stays denied");
    assert!(!tcp_ok(&z.ns, B1, 7000), "A2 is not federated");
}
