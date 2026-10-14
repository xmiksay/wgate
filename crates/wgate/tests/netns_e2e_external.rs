//! External rights end to end: a tenant's ceiling and rules, SNAT towards the nodes,
//! and the hub's own services. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::collections::BTreeSet;

use axum::http::{Method, StatusCode};
use common::{HUB_SERVICES, NODE, World, id, ping_ok, tcp_ok, wg};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and Docker: make test-netns"]
async fn external_rights_snat_and_hub_services() {
    let w = World::new().await;
    let a = w.tenant("a", "10.50.0.0/24").await;
    for c in [
        json!({ "dst": "172.19.9.11/32", "proto": "icmp" }),
        json!({ "dst": "172.16.16.1/32", "proto": "tcp", "port_from": 6443 }),
    ] {
        w.admin
            .create(&format!("/tenants/{}/ceilings", a.0), c)
            .await;
    }
    let a1 = w.network(a, "a1", "10.50.0.0/25", 51801).await;
    let rules = format!("/networks/{a1}/rules");
    w.admin
        .create(&rules, json!({ "dst": "172.19.9.11/32", "proto": "icmp" }))
        .await;
    let api = id(&w
        .admin
        .create(
            &rules,
            json!({ "dst": "172.16.16.1/32", "proto": "tcp", "port_from": 6443 }),
        )
        .await);
    // The ceiling bounds the rules: 22 on the hub is not the tenant's to open.
    let v = w
        .admin
        .expect(
            StatusCode::UNPROCESSABLE_ENTITY,
            Method::POST,
            &rules,
            Some(json!({ "dst": "172.16.16.1/32", "proto": "tcp", "port_from": 22 })),
        )
        .await;
    assert_eq!(
        v["detail"]["uncovered"],
        json!(["tcp 172.16.16.1 22"]),
        "{v}"
    );

    let laptop = w.device(a.0, "laptop").await;
    let (_, config) = w.peer(laptop, a1, "10.50.0.2", &[]).await;
    // The rendered config: the hub's underlay endpoint and AllowedIPs = the rights
    // (plus the hub address, the source of its ICMP errors).
    assert_eq!(
        wg::value(&config, "Endpoint"),
        Some("198.51.100.1:51801"),
        "{config}"
    );
    assert_eq!(
        wg::value(&config, "Address"),
        Some("10.50.0.2/32"),
        "{config}"
    );
    let want: BTreeSet<String> = ["10.50.0.1/32", "172.16.16.1/32", "172.19.9.11/32"]
        .map(String::from)
        .into();
    assert_eq!(wg::allowed_ips(&config), want, "{config}");
    let h = w.host("laptop", &config);

    // The node has no route back to the pool: the reply comes only through SNAT.
    assert!(!w.node.succeeds(&["ip", "route", "get", "10.50.0.2"]));
    assert!(ping_ok(&h.ns, NODE), "A1 pings the node");
    let snat = w
        .hub
        .output(&["nft", "list", "chain", "inet", "wgate", "postrouting"]);
    assert!(snat.contains("snat ip to 172.19.9.10"), "{snat}");

    assert!(tcp_ok(&h.ns, HUB_SERVICES, 6443), "the k8s API on the hub");
    assert!(tcp_ok(&w.hub, HUB_SERVICES, 22), "ssh on the hub is up");
    assert!(!tcp_ok(&h.ns, HUB_SERVICES, 22), "but not the tenant's");
    assert!(!tcp_ok(&h.ns, NODE, 8080), "no rule for the node's 8080");

    // Removing the rule takes the right away at once.
    w.admin.delete(&format!("/rules/{api}")).await;
    w.settle().await;
    assert!(!tcp_ok(&h.ns, HUB_SERVICES, 6443), "the rule is gone");
    assert!(ping_ok(&h.ns, NODE), "the other rule stays");
}
