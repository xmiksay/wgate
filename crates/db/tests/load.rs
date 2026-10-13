//! The desired state loaded from rows compiles to the rights the rows describe.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{ok, pg};
use wgate_core::{Proto, compile};
use wgate_db::{Infra, desired_state};

fn infra() -> Infra {
    let nets = |n: &[&str]| n.iter().map(|s| s.parse().expect("cidr")).collect();
    Infra {
        pool: nets(&["10.50.0.0/16"]),
        routed_space: nets(&["192.168.0.0/16"]),
        reserved: vec![],
        snat_source: "172.19.9.10".parse().expect("addr"),
        node_cidrs: nets(&["172.19.9.0/24"]),
    }
}

const KEYS: [&str; 4] = [
    "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
    "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
];

/// nexial: networks `nexial` (a router with a LAN, k8s API, SSH into `dev`) and `dev`
/// (mesh off, pods may reach it on 8080); krcmar: `krcmar`, federated into `dev` on
/// 443. Plus rows that must not count: a revoked peer, a disabled user's peer, a
/// disabled network.
const SCENARIO: &str = "
    INSERT INTO tenant (id, slug, name) VALUES (1, 'nexial', 'Nexial'), (2, 'krcmar', 'Krcmar');
    INSERT INTO tenant_block (id, tenant_id, cidr)
        VALUES (1, 1, '10.50.0.0/23'), (2, 2, '10.50.2.0/24'), (3, 1, '10.50.3.0/24');
    INSERT INTO ceiling (tenant_id, proto, dst, port_from, port_to)
        VALUES (1, 'tcp', '172.16.16.1/32', 6443, 6443);
    INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port) VALUES
        (1, 1, 1, 'nexial', 'Nexial', '10.50.0.0/24', 51801),
        (2, 1, 1, 'dev', 'Dev', '10.50.1.0/24', 51802),
        (3, 2, 2, 'krcmar', 'Krcmar', '10.50.2.0/24', 51803);
    INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port, disabled_at)
        VALUES (4, 1, 3, 'old', 'Old', '10.50.3.0/24', 51804, now());
    INSERT INTO rule (tenant_id, network_id, proto, port_from, port_to, dst, target_network_id) VALUES
        (1, 1, 'tcp', 6443, 6443, '172.16.16.1/32', NULL),
        (1, 1, 'tcp', 22, 22, NULL, 2);
    INSERT INTO inbound (network_id, source, proto, port_from, port_to)
        VALUES (2, '10.244.0.0/16', 'tcp', 8080, 8080);
    INSERT INTO federation (from_network_id, to_network_id, proto, port_from, port_to)
        VALUES (3, 2, 'tcp', 443, 443);
    INSERT INTO app_user (id, tenant_id, email, role) VALUES
        (1, 1, 'a@nexial.cz', 'user'), (2, 2, 'b@krcmar.cz', 'user');
    INSERT INTO app_user (id, tenant_id, email, role, disabled_at)
        VALUES (3, 1, 'gone@nexial.cz', 'user', now());
    INSERT INTO device (id, user_id, name) VALUES (1, 1, 'router'), (2, 2, 'laptop'), (3, 3, 'old');
";

fn peers() -> String {
    format!(
        "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES
            (1, 1, 1, '{}', '10.50.0.2'),
            (2, 1, 2, '{}', '10.50.1.2'),
            (3, 2, 3, '{}', '10.50.2.2');
         INSERT INTO peer (id, device_id, network_id, public_key, ip, revoked_at)
            VALUES (4, 1, 1, '{}', '10.50.0.3', now());
         INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.10.0/24');",
        KEYS[0], KEYS[1], KEYS[2], KEYS[3]
    )
}

#[tokio::test]
async fn rows_compile_to_the_rights_they_describe() {
    let pg = pg("").await;
    ok(&pg.db, SCENARIO).await;
    ok(&pg.db, &peers()).await;
    let loaded = desired_state(&pg.db, &infra()).await.expect("load");
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    // Disabled network 4 and revoked peer 4 are not part of the state.
    assert_eq!(loaded.state.networks.len(), 3);
    assert_eq!(loaded.state.peers.len(), 3);

    let c = compile(&loaded.state);
    assert!(
        c.skipped.is_empty() && c.invalid_networks.is_empty(),
        "{c:?}"
    );
    let get = |id| c.peers.iter().find(|p| p.id == id).expect("peer");
    let ip = |s: &str| s.parse().expect("addr");
    let router = get(1);
    let iface = |p: &wgate_core::CompiledPeer| &c.network(p.network).expect("network").iface;
    assert_eq!(iface(router), "wg-nexial");
    assert!(router.outbound.allows(Proto::Tcp, ip("172.16.16.1"), 6443));
    assert!(router.outbound.allows(Proto::Tcp, ip("10.50.1.2"), 22));
    assert!(
        router
            .addrs
            .contains(&"192.168.10.0/24".parse().expect("cidr"))
    );
    let dev = get(2);
    assert!(
        dev.inbound.allows(Proto::Tcp, ip("192.168.10.7"), 22),
        "via the router"
    );
    assert!(
        dev.inbound.allows(Proto::Tcp, ip("10.244.1.1"), 8080),
        "inbound grant"
    );
    assert!(
        dev.inbound.allows(Proto::Tcp, ip("10.50.2.2"), 443),
        "federation"
    );
    assert!(get(3).outbound.allows(Proto::Tcp, ip("10.50.1.2"), 443));
    assert!(
        !get(3).outbound.allows(Proto::Tcp, ip("172.16.16.1"), 6443),
        "no ceiling"
    );
}

#[tokio::test]
async fn the_snapshot_carries_its_revision() {
    let pg = pg("").await;
    ok(&pg.db, SCENARIO).await;
    ok(&pg.db, "UPDATE network SET mesh = true WHERE id = 1").await;
    let current = wgate_db::revision::current(&pg.db).await.expect("revision");
    assert!(current > 0);
    assert_eq!(
        desired_state(&pg.db, &infra())
            .await
            .expect("load")
            .revision,
        current
    );
}

#[tokio::test]
async fn peers_of_inactive_networks_are_simply_absent() {
    let pg = pg("").await;
    ok(&pg.db, SCENARIO).await;
    ok(&pg.db, &peers()).await;
    ok(
        &pg.db,
        "UPDATE network SET disabled_at = now() WHERE id = 2",
    )
    .await;
    let loaded = desired_state(&pg.db, &infra()).await.expect("load");
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    assert_eq!(
        loaded.state.peers.iter().map(|p| p.id).collect::<Vec<_>>(),
        [1, 3]
    );
    assert!(compile(&loaded.state).skipped.is_empty());
}

#[tokio::test]
async fn a_global_admins_device_joins_any_network() {
    let pg = pg("").await;
    ok(&pg.db, SCENARIO).await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO app_user (id, email, role) VALUES (9, 'admin@mmik.cz', 'global_admin');
             INSERT INTO device (id, user_id, name) VALUES (9, 9, 'admin');
             INSERT INTO peer (id, device_id, network_id, public_key, ip)
                VALUES (6, 9, 3, '{}', '10.50.2.6')",
            KEYS[1]
        ),
    )
    .await;
    // (A tenant user's device in another tenant's network is refused on insert, see
    // the schema tests; compile refuses it too, see core.)
    let c = compile(&desired_state(&pg.db, &infra()).await.expect("load").state);
    assert!(c.skipped.is_empty(), "{:?}", c.skipped);
    let admin = c.peers.iter().find(|p| p.id == 6).expect("admin peer");
    assert_eq!(admin.public_key, KEYS[1]);
}

#[tokio::test]
async fn a_disabled_user_loses_every_peer() {
    let pg = pg("").await;
    ok(&pg.db, SCENARIO).await;
    ok(&pg.db, &peers()).await;
    ok(
        &pg.db,
        "UPDATE app_user SET disabled_at = now() WHERE id = 1",
    )
    .await;
    let state = desired_state(&pg.db, &infra()).await.expect("load").state;
    assert_eq!(state.peers.iter().map(|p| p.id).collect::<Vec<_>>(), [3]);
}

#[tokio::test]
async fn a_disabled_tenant_takes_its_networks_along() {
    let pg = pg("").await;
    ok(&pg.db, SCENARIO).await;
    ok(&pg.db, "UPDATE tenant SET disabled_at = now() WHERE id = 1").await;
    let state = desired_state(&pg.db, &infra()).await.expect("load").state;
    assert_eq!(state.networks.iter().map(|n| n.id).collect::<Vec<_>>(), [3]);
    assert_eq!(state.tenants.iter().map(|t| t.id).collect::<Vec<_>>(), [2]);
}

/// The grants and the loader must agree: the agent loads as `wgate_agent`.
#[tokio::test]
async fn the_agent_role_can_load_the_desired_state() {
    let pg = pg("CREATE ROLE wgate_agent LOGIN PASSWORD 'agent'").await;
    ok(&pg.db, SCENARIO).await;
    ok(&pg.db, &peers()).await;
    let agent = sea_orm::Database::connect(&common::as_agent(&pg.url))
        .await
        .expect("connect as agent");
    let loaded = desired_state(&agent, &infra())
        .await
        .expect("load as wgate_agent");
    assert_eq!(loaded.state.peers.len(), 3);
}
