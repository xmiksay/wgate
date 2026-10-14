//! A routed LAN behind a router peer, both ways, and a source outside the pool that
//! gets in only with an inbound grant. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use common::netns::Netns;
use common::{HUB_SERVICES, POD, World, echo, id, lines_until, stream, tcp_ok};
use serde_json::json;

const LAN_HOST: &str = "192.168.50.10";
const A1Y: &str = "10.50.0.3";
const A2: &str = "10.50.0.130";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and Docker: make test-netns"]
async fn routed_lan_and_inbound_grants() {
    let w = World::new().await;
    let a = w.tenant("a", "10.50.0.0/24").await;
    w.admin
        .create(
            &format!("/tenants/{}/ceilings", a.0),
            json!({ "dst": "172.16.16.1/32", "proto": "tcp", "port_from": 6443 }),
        )
        .await;
    let a1 = w.network(a, "a1", "10.50.0.0/25", 51801).await;
    let a2 = w.network(a, "a2", "10.50.0.128/25", 51802).await;
    w.admin_create(
        &format!("/networks/{a1}/rules"),
        json!({ "dst": "172.16.16.1/32", "proto": "tcp", "port_from": 6443 }),
    )
    .await;

    // router (A1, routes 192.168.50.0/24) ─ lan0 192.168.50.1 ─ lan 192.168.50.10
    let device = w.device(a.0, "router").await;
    let (_, config) = w.peer(device, a1, "10.50.0.2", &["192.168.50.0/24"]).await;
    let router = w.host("router", &config);
    let lan = Netns::new("lan");
    router
        .ns
        .exec(&["sysctl", "-qw", "net.ipv4.ip_forward=1"], None);
    router.ns.exec(
        &[
            "ip", "link", "add", "lan0", "type", "veth", "peer", "name", "p0", "netns", &lan.0,
        ],
        None,
    );
    router.ns.exec(
        &["ip", "addr", "add", "192.168.50.1/24", "dev", "lan0"],
        None,
    );
    router.ns.exec(&["ip", "link", "set", "lan0", "up"], None);
    for argv in [
        &["ip", "link", "set", "lo", "up"][..],
        &["ip", "addr", "add", "192.168.50.10/24", "dev", "p0"],
        &["ip", "link", "set", "p0", "up"],
        &["ip", "route", "add", "default", "via", "192.168.50.1"],
    ] {
        lan.exec(argv, None);
    }
    let _lan_echo = echo(&lan, &["7000"]);
    let (_, y) = w.peer_host("a1y", w.device(a.0, "y").await, a1, A1Y).await;
    let (_, z) = w.peer_host("a2", w.device(a.0, "z").await, a2, A2).await;
    let routes = w.hub.output(&["ip", "route", "show", "192.168.50.0/24"]);
    assert!(routes.contains("dev wg-a1"), "{routes}");

    // The LAN host has its router's access, and nothing more.
    assert!(tcp_ok(&lan, HUB_SERVICES, 6443), "the router's rule");
    assert!(!tcp_ok(&lan, HUB_SERVICES, 22), "no rule");
    assert!(!tcp_ok(&lan, A2, 7000), "no rule A1 → A2 yet");
    // Others reach the LAN only per rules: not even its own network without mesh.
    assert!(!tcp_ok(&y.ns, LAN_HOST, 7000), "mesh off");
    assert!(!tcp_ok(&z.ns, LAN_HOST, 7000), "no rule A2 → A1 yet");

    let tcp =
        |target: i64| json!({ "proto": "tcp", "port_from": 7000, "target_network_id": target });
    w.admin_create(&format!("/networks/{a2}/rules"), tcp(a1))
        .await;
    assert!(tcp_ok(&z.ns, LAN_HOST, 7000), "rule A2 → A1 covers the LAN");
    assert!(!tcp_ok(&lan, A2, 7000), "but not the way back");
    w.admin_create(&format!("/networks/{a1}/rules"), tcp(a2))
        .await;
    assert!(
        tcp_ok(&lan, A2, 7000),
        "rule A1 → A2 covers the LAN as a source"
    );

    // The pod (outside the pool) gets in only with an inbound grant.
    assert!(!tcp_ok(&w.pod, A2, 7000), "no grant");
    let grant = w
        .admin_create(
            &format!("/networks/{a2}/inbound"),
            json!({ "source": "10.244.0.0/24", "proto": "tcp", "port_from": 7000 }),
        )
        .await;
    assert!(tcp_ok(&w.pod, A2, 7000), "granted");
    assert!(!tcp_ok(&w.pod, A1Y, 7000), "a grant for A2 only");
    assert!(!tcp_ok(&z.ns, POD, 7000), "inbound, not outbound");

    // Revoking the grant kills the pod's live stream.
    let live = stream(&w.pod, A2, 7000);
    w.admin
        .delete(&format!("/inbound/{}", id(&grant["inbound"])))
        .await;
    let revoked = Instant::now();
    let at = lines_until(&live, revoked + Duration::from_secs(2));
    let cut = revoked + Duration::from_secs(1);
    assert!(
        at.iter().all(|t| *t < cut),
        "the stream outlived the grant: {:?}",
        at.last().map(|t| t.duration_since(revoked))
    );
    w.settle().await;
    assert!(!tcp_ok(&w.pod, A2, 7000), "the grant is gone");
}
