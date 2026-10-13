//! Migrations, constraints, grants and NOTIFY against a real Postgres (Docker).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::{ok, pg, refused};
use sea_orm::{Database, TransactionTrait};
use sea_orm_migration::MigratorTrait;
use wgate_db::{Migrator, revision};

const BASE: &str = "
    INSERT INTO tenant (id, slug, name) VALUES (1, 'nexial', 'Nexial'), (2, 'krcmar', 'Krcmar');
    INSERT INTO tenant_block (tenant_id, cidr) VALUES (1, '10.50.0.0/24'), (2, '10.50.1.0/24');
    INSERT INTO network (id, tenant_id, slug, name, cidr, port)
        VALUES (1, 1, 'nexial', 'Nexial', '10.50.0.0/25', 51801);
    INSERT INTO app_user (id, tenant_id, email, role) VALUES (1, 1, 'a@nexial.cz', 'user');
    INSERT INTO device (id, user_id, name) VALUES (1, 1, 'laptop');
";
const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

#[tokio::test]
async fn migrations_apply_and_reapply() {
    let pg = pg("").await;
    Migrator::up(&pg.db, None)
        .await
        .expect("second run is a no-op");
    assert_eq!(revision::current(&pg.db).await.expect("revision"), 0);
}

#[tokio::test]
async fn ranges_are_exclusive() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    // Blocks, networks and routes never overlap, whoever claims them.
    refused(
        &pg.db,
        "INSERT INTO tenant_block (tenant_id, cidr) VALUES (2, '10.50.0.128/25')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO network (tenant_id, slug, name, cidr, port) VALUES (1, 'other', 'x', '10.50.0.64/26', 51802)",
    )
    .await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip)
                 VALUES (1, 1, 1, '{KEY}', '10.50.0.2');
             INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')"
        ),
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.0.0/23')",
    )
    .await;
}

#[tokio::test]
async fn columns_are_checked() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let network = |slug: &str, cidr: &str, port: u32| {
        format!(
            "INSERT INTO network (tenant_id, slug, name, cidr, port) VALUES (1, '{slug}', 'x', '{cidr}', {port})"
        )
    };
    refused(&pg.db, &network("-bad", "10.50.0.128/28", 51802)).await;
    refused(&pg.db, &network("waytoolongslug", "10.50.0.128/28", 51802)).await;
    refused(&pg.db, &network("p20", "10.50.0.128/28", 51820)).await;
    refused(&pg.db, &network("p99", "10.50.0.128/28", 51900)).await;
    refused(&pg.db, &network("p01", "10.50.0.128/28", 51801)).await;
    refused(&pg.db, &network("tiny", "10.50.0.128/31", 51802)).await;
    ok(&pg.db, &network("ok", "10.50.0.128/28", 51802)).await;

    let rule = |proto: &str, from: &str, to: &str, dst: &str, target: &str| {
        format!(
            "INSERT INTO rule (network_id, proto, port_from, port_to, dst, target_network_id)
             VALUES (1, '{proto}', {from}, {to}, {dst}, {target})"
        )
    };
    ok(
        &pg.db,
        &rule("tcp", "6443", "6443", "'172.16.16.1/32'", "NULL"),
    )
    .await;
    ok(&pg.db, &rule("icmp", "NULL", "NULL", "NULL", "1")).await;
    refused(&pg.db, &rule("icmp", "1", "2", "'172.16.16.1/32'", "NULL")).await;
    refused(
        &pg.db,
        &rule("tcp", "NULL", "NULL", "'172.16.16.1/32'", "NULL"),
    )
    .await;
    refused(&pg.db, &rule("tcp", "0", "80", "'172.16.16.1/32'", "NULL")).await;
    refused(&pg.db, &rule("tcp", "90", "80", "'172.16.16.1/32'", "NULL")).await;
    refused(&pg.db, &rule("sctp", "1", "2", "'172.16.16.1/32'", "NULL")).await;
    refused(&pg.db, &rule("tcp", "1", "2", "'172.16.16.1/32'", "1")).await;
    refused(&pg.db, &rule("tcp", "1", "2", "NULL", "NULL")).await;

    // Roles: global admins have no tenant, everyone else has one.
    refused(
        &pg.db,
        "INSERT INTO app_user (tenant_id, email, role) VALUES (1, 'x@y', 'global_admin')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO app_user (email, role) VALUES ('x@y', 'user')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO app_user (tenant_id, email, role) VALUES (1, 'A@NEXIAL.CZ', 'user')",
    )
    .await;
}

#[tokio::test]
async fn peer_addresses_are_free_again_after_revocation() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let insert = |id: u32, key: &str| {
        format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES ({id}, 1, 1, '{key}', '10.50.0.2')"
        )
    };
    let other_key = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";
    ok(&pg.db, &insert(1, KEY)).await;
    refused(&pg.db, &insert(2, other_key)).await;
    refused(
        &pg.db,
        "INSERT INTO peer (device_id, network_id, public_key, ip) VALUES (1, 1, 'not-a-key', '10.50.0.3')",
    )
    .await;
    ok(&pg.db, "UPDATE peer SET revoked_at = now() WHERE id = 1").await;
    ok(&pg.db, &insert(2, other_key)).await;
}

#[tokio::test]
async fn bump_notifies_on_commit_only() {
    let pg = pg("").await;
    let mut listener = revision::listener(&pg.url).await.expect("listen");

    let txn = pg.db.begin().await.expect("begin");
    assert_eq!(revision::bump(&txn).await.expect("bump"), 1);
    txn.rollback().await.expect("rollback");
    assert_eq!(revision::current(&pg.db).await.expect("revision"), 0);

    let txn = pg.db.begin().await.expect("begin");
    assert_eq!(revision::bump(&txn).await.expect("bump"), 1);
    txn.commit().await.expect("commit");
    let note = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("notified within 5 s")
        .expect("notification");
    // The rolled-back bump never notified: the first notification is the commit's.
    assert_eq!(note.channel(), revision::CHANNEL);
    assert_eq!(note.payload(), "1");
}

#[tokio::test]
async fn the_agent_role_reads_everything_and_writes_only_its_tables() {
    let pg = pg("CREATE ROLE wgate_agent LOGIN PASSWORD 'agent'").await;
    ok(&pg.db, BASE).await;
    let agent_url = pg.url.replace("postgres:postgres@", "wgate_agent:agent@");
    let agent = Database::connect(&agent_url)
        .await
        .expect("connect as agent");
    ok(
        &agent,
        "SELECT * FROM tenant, network, peer, peer_route, rule, inbound",
    )
    .await;
    ok(
        &agent,
        "INSERT INTO hub_key (network_id, public_key) VALUES (1, 'pk')",
    )
    .await;
    ok(&agent, "UPDATE hub_key SET public_key = 'pk2'").await;
    ok(
        &agent,
        "INSERT INTO agent_status (applied_revision, applied_at) VALUES (0, now())",
    )
    .await;
    refused(&agent, "INSERT INTO tenant (slug, name) VALUES ('x', 'x')").await;
    refused(&agent, "UPDATE network SET mesh = true").await;
    refused(&agent, "DELETE FROM hub_key").await;
    refused(&agent, "UPDATE state_revision SET revision = 9").await;
}
