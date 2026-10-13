//! The agent end to end: a real reconcile against Postgres (Docker) inside a network
//! namespace with real WireGuard interfaces. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::Netns;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use wgate_agent::{Config, System, reconcile_once};

const KEY: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

async fn postgres() -> (ContainerAsync<Postgres>, String, DatabaseConnection) {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("start postgres (is Docker running?)");
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let db = Database::connect(&url).await.expect("connect");
    wgate_db::migrate(&db).await.expect("migrate");
    (container, url, db)
}

async fn sql(db: &DatabaseConnection, sql: &str) {
    db.execute_unprepared(sql)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

#[tokio::test]
#[ignore = "needs root and Docker: make test-netns"]
async fn the_agent_builds_updates_and_tears_down_a_network() {
    let (_pg, url, db) = postgres().await;
    sql(
        &db,
        &format!(
            "INSERT INTO tenant (id, slug, name) VALUES (1, 'nexial', 'Nexial');
             INSERT INTO tenant_block (id, tenant_id, cidr) VALUES (1, 1, '10.50.0.0/24');
             INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port)
                 VALUES (1, 1, 1, 'n1', 'N1', '10.50.0.0/24', 51801);
             INSERT INTO app_user (id, tenant_id, email, role) VALUES (1, 1, 'a@nexial.cz', 'user');
             INSERT INTO device (id, user_id, name) VALUES (1, 1, 'router');
             INSERT INTO peer (id, device_id, network_id, public_key, ip)
                 VALUES (1, 1, 1, '{KEY}', '10.50.0.2');
             INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')"
        ),
    )
    .await;
    let hub = Netns::new("agent");
    hub.exec(&["ip", "link", "set", "lo", "up"], None);
    let keys = tempfile::tempdir().expect("keys dir");
    let net = |s: &str| s.parse().expect("cidr");
    let config = Config {
        database_url: url,
        pool: vec![net("10.50.0.0/16")],
        routed_space: vec![net("192.168.0.0/16")],
        reserved: vec![],
        snat_source: "172.19.9.10".parse().expect("addr"),
        node_cidrs: vec![],
        keys_dir: keys.path().to_owned(),
        reconcile_interval_secs: 60,
    };
    let runner = Arc::new(System::in_netns(&hub.0));
    let apply = || reconcile_once(&db, &config, runner.clone());

    apply().await.expect("first reconcile");
    let dump = hub.output(&["wg", "show", "wg-n1", "dump"]);
    assert!(
        dump.contains(&format!(
            "{KEY}\t(none)\t(none)\t10.50.0.2/32,192.168.1.0/24"
        )),
        "{dump}"
    );
    assert!(dump.contains("\t51801\t"), "{dump}");
    let routes = hub.output(&["ip", "route", "show", "dev", "wg-n1", "proto", "150"]);
    assert!(routes.contains("192.168.1.0/24"), "{routes}");
    let table = hub.output(&["nft", "list", "table", "inet", "wgate"]);
    assert!(
        table.contains("chain n1_from") && table.contains("10.50.0.2"),
        "{table}"
    );
    let status = db
        .query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT s.error, k.public_key FROM agent_status s, hub_key k",
        ))
        .await
        .expect("status")
        .expect("one row");
    assert_eq!(
        status
            .try_get::<Option<String>>("", "error")
            .expect("error"),
        None
    );
    let hub_key: String = status.try_get("", "public_key").expect("hub key");
    assert!(
        hub.output(&["wg", "show", "wg-n1", "public-key"])
            .contains(&hub_key)
    );

    // Revoking the router removes the peer, its route and its set elements.
    sql(&db, "UPDATE peer SET revoked_at = now()").await;
    apply().await.expect("reconcile after revoke");
    assert!(!hub.output(&["wg", "show", "wg-n1", "dump"]).contains(KEY));
    assert!(
        !hub.output(&["ip", "route", "show", "dev", "wg-n1", "proto", "150"])
            .contains("192.168")
    );
    assert!(
        !hub.output(&["nft", "list", "table", "inet", "wgate"])
            .contains("10.50.0.2")
    );

    // Disabling the network takes its interface and nft fragment away.
    sql(&db, "UPDATE network SET disabled_at = now()").await;
    apply().await.expect("reconcile after disable");
    assert!(!hub.output(&["ip", "link"]).contains("wg-n1"));
    assert!(
        !hub.output(&["nft", "list", "table", "inet", "wgate"])
            .contains("n1_")
    );
}
