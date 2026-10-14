//! A routed LAN behind a router peer, both ways, and a source outside the pool that
//! gets in only with an inbound grant. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::time::Instant;

use axum::http::StatusCode;
use common::netns::{Netns, tcp_ok};
use common::stream::{assert_alive, assert_cut, stream};
use common::{HUB_SERVICES, POD, World, echo, id, nets, wg};
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
    let (pr, config) = w.peer(device, a1, "10.50.0.2", &["192.168.50.0/24"]).await;
    assert_eq!(
        wg::allowed_ips(&config),
        nets(&["10.50.0.1/32", "172.16.16.1/32"]),
        "the router's config: the hub and its rule, not its own LAN"
    );
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
    let (pz, z) = w.peer_host("a2", w.device(a.0, "z").await, a2, A2).await;
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
    let router_now = nets(&["10.50.0.1/32", "10.50.0.130/32", "172.16.16.1/32"]);
    assert_eq!(
        w.refresh(&router.ns, pr).await,
        router_now,
        "A2 may reach the router"
    );
    let z_now = nets(&["10.50.0.129/32", "10.50.0.2/31", "192.168.50.0/24"]);
    assert_eq!(
        w.refresh(&z.ns, pz).await,
        z_now,
        "z may reach A1 and the LAN"
    );
    assert!(tcp_ok(&z.ns, LAN_HOST, 7000), "rule A2 → A1 covers the LAN");
    assert!(!tcp_ok(&lan, A2, 7000), "but not the way back");
    w.admin_create(&format!("/networks/{a1}/rules"), tcp(a2))
        .await;
    // The same addresses either way.
    assert_eq!(w.refresh(&router.ns, pr).await, router_now);
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
    let mut z_granted = z_now.clone();
    z_granted.insert("10.244.0.0/24".into());
    assert_eq!(
        w.refresh(&z.ns, pz).await,
        z_granted,
        "z's config routes the pod"
    );
    assert!(tcp_ok(&w.pod, A2, 7000), "granted");
    assert!(!tcp_ok(&w.pod, A1Y, 7000), "a grant for A2 only");
    assert!(!tcp_ok(&z.ns, POD, 7000), "inbound, not outbound");

    // Revoking the grant kills the pod's live stream.
    let live = stream(&w.pod, A2, 7000);
    assert_alive(&live, "the pod's stream");
    let (status, v) = w
        .admin
        .delete(&format!("/inbound/{}", id(&grant["inbound"])))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{v}");
    assert_cut(&live, Instant::now(), "the pod's stream");
    w.settle().await;
    assert!(!tcp_ok(&w.pod, A2, 7000), "the grant is gone");
}
