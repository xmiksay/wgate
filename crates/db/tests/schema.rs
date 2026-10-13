//! Migrations, constraints, grants and NOTIFY against a real Postgres (Docker).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::{ok, pg, refused};
use sea_orm::{ConnectionTrait, Database, TransactionTrait};
use wgate_db::{migrate, revision};

const BASE: &str = "
    INSERT INTO tenant (id, slug, name) VALUES (1, 'nexial', 'Nexial'), (2, 'krcmar', 'Krcmar');
    INSERT INTO tenant_block (id, tenant_id, cidr) VALUES (1, 1, '10.50.0.0/24'), (2, 2, '10.50.1.0/24');
    INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port)
        VALUES (1, 1, 1, 'nexial', 'Nexial', '10.50.0.0/25', 51801);
    INSERT INTO app_user (id, tenant_id, email, role) VALUES (1, 1, 'a@nexial.cz', 'user');
    INSERT INTO device (id, user_id, name) VALUES (1, 1, 'laptop');
";
const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

#[tokio::test]
async fn migrations_apply_and_reapply() {
    let pg = pg("").await;
    assert!(
        migrate(&pg.db).await.expect("second run").is_empty(),
        "nothing pending"
    );
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
        "INSERT INTO network (tenant_id, block_id, slug, name, cidr, port) VALUES (1, 1, 'other', 'x', '10.50.0.64/26', 51802)",
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
            "INSERT INTO network (tenant_id, block_id, slug, name, cidr, port) VALUES (1, 1, '{slug}', 'x', '{cidr}', {port})"
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
            "INSERT INTO rule (tenant_id, network_id, proto, port_from, port_to, dst, target_network_id)
             VALUES (1, 1, '{proto}', {from}, {to}, {dst}, {target})"
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
    // Tables later migrations add (as the owner) are readable too.
    ok(&pg.db, "CREATE TABLE later (x int)").await;
    ok(&agent, "SELECT * FROM later").await;
}

#[tokio::test]
async fn the_migration_is_recorded_under_its_own_name() {
    let pg = pg("").await;
    let row = pg
        .db
        .query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT name FROM wgate_migration",
        ))
        .await
        .expect("query")
        .expect("one migration");
    assert_eq!(
        row.try_get::<String>("", "name").expect("name"),
        "m0001_init"
    );
}

#[tokio::test]
async fn revoking_a_peer_frees_its_key_and_lans() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let insert = |id: u32, ip: &str| {
        format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES ({id}, 1, 1, '{KEY}', '{ip}')"
        )
    };
    ok(&pg.db, &insert(1, "10.50.0.2")).await;
    ok(
        &pg.db,
        "INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')",
    )
    .await;
    refused(&pg.db, &insert(2, "10.50.0.3")).await;
    ok(&pg.db, "UPDATE peer SET revoked_at = now() WHERE id = 1").await;
    ok(&pg.db, &insert(2, "10.50.0.3")).await;
    ok(
        &pg.db,
        "INSERT INTO peer_route (peer_id, cidr) VALUES (2, '192.168.1.0/24')",
    )
    .await;
}

#[tokio::test]
async fn tenants_may_share_an_identity_provider() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        "INSERT INTO oidc_provider (tenant_id, issuer, client_id) VALUES
            (1, 'https://accounts.google.com', 'a'), (2, 'https://accounts.google.com', 'b'),
            (NULL, 'https://accounts.google.com', 'admin')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO oidc_provider (tenant_id, issuer, client_id) VALUES (NULL, 'https://x', 'y')",
    )
    .await;
}

#[tokio::test]
async fn a_revoked_peer_cannot_be_given_a_lan() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip, revoked_at)
                 VALUES (1, 1, 1, '{KEY}', '10.50.0.2', now())"
        ),
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')",
    )
    .await;
}

/// A route inserted while the peer is being revoked must not survive: the guard's
/// row lock makes the revocation wait for the insert, and then free the new route.
#[tokio::test]
async fn a_route_racing_a_revocation_is_freed() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES (1, 1, 1, '{KEY}', '10.50.0.2')"
        ),
    )
    .await;
    let insert = pg.db.begin().await.expect("begin");
    insert
        .execute_unprepared("INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')")
        .await
        .expect("insert route");
    let other = sea_orm::Database::connect(&pg.url)
        .await
        .expect("second connection");
    let revoke = tokio::spawn(async move {
        other
            .execute_unprepared("UPDATE peer SET revoked_at = now() WHERE id = 1")
            .await
            .expect("revoke");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !revoke.is_finished(),
        "the revocation waits for the route insert"
    );
    insert.commit().await.expect("commit route");
    revoke.await.expect("revoke task");
    let row = pg
        .db
        .query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT count(*) AS n FROM peer_route",
        ))
        .await
        .expect("count")
        .expect("row");
    assert_eq!(row.try_get::<i64>("", "n").expect("n"), 0);
}

#[tokio::test]
async fn tenant_blocks_are_ipv4() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    refused(
        &pg.db,
        "INSERT INTO tenant_block (tenant_id, cidr) VALUES (1, 'fd00::/64')",
    )
    .await;
}

#[tokio::test]
async fn networks_stay_inside_their_tenants_blocks() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let network = |tenant: u32, block: u32, cidr: &str| {
        format!(
            "INSERT INTO network (tenant_id, block_id, slug, name, cidr, port) VALUES ({tenant}, {block}, 'n2', 'x', '{cidr}', 51802)"
        )
    };
    // In tenant 2's block, and in no block at all.
    refused(&pg.db, &network(1, 1, "10.50.1.0/28")).await;
    refused(&pg.db, &network(1, 2, "10.50.1.0/28")).await;
    refused(&pg.db, &network(1, 1, "10.50.9.0/28")).await;
    ok(&pg.db, &network(2, 2, "10.50.1.0/28")).await;
    // A block cannot be removed under its networks, and blocks never change.
    refused(&pg.db, "DELETE FROM tenant_block WHERE tenant_id = 2").await;
    refused(
        &pg.db,
        "UPDATE tenant_block SET cidr = '10.50.1.128/25' WHERE tenant_id = 2",
    )
    .await;
    ok(&pg.db, "DELETE FROM network WHERE tenant_id = 2").await;
    ok(&pg.db, "DELETE FROM tenant_block WHERE tenant_id = 2").await;
}

#[tokio::test]
async fn a_device_joins_a_network_once_and_revokes_at_read_committed() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let insert = |id: u32, key: &str, ip: &str| {
        format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES ({id}, 1, 1, '{key}', '{ip}')"
        )
    };
    ok(&pg.db, &insert(1, KEY, "10.50.0.2")).await;
    refused(
        &pg.db,
        &insert(
            2,
            "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
            "10.50.0.3",
        ),
    )
    .await;
    let txn = pg
        .db
        .begin_with_config(Some(sea_orm::IsolationLevel::RepeatableRead), None)
        .await
        .expect("begin");
    assert!(
        txn.execute_unprepared("UPDATE peer SET revoked_at = now() WHERE id = 1")
            .await
            .is_err(),
        "a snapshot-isolated revoke could miss a racing route"
    );
    txn.rollback().await.expect("rollback");
    ok(&pg.db, "UPDATE peer SET revoked_at = now() WHERE id = 1").await;
}

#[tokio::test]
async fn deleting_a_tenant_cascades_through_everything() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES (1, 1, 1, '{KEY}', '10.50.0.2');
             INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')"
        ),
    )
    .await;
    ok(&pg.db, "DELETE FROM tenant WHERE id = 1").await;
}

#[tokio::test]
async fn a_peer_fits_its_network_and_tenant() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        "INSERT INTO app_user (id, tenant_id, email, role) VALUES (2, 2, 'b@krcmar.cz', 'user');
         INSERT INTO device (id, user_id, name) VALUES (2, 2, 'other tenant');
         INSERT INTO app_user (id, email, role) VALUES (3, 'admin@mmik.cz', 'global_admin');
         INSERT INTO device (id, user_id, name) VALUES (3, 3, 'admin');
         INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port)
             VALUES (2, 2, 2, 'krcmar', 'Krcmar', '10.50.1.0/24', 51802)",
    )
    .await;
    let peer = |device: u32, network: u32, ip: &str| {
        format!(
            "INSERT INTO peer (device_id, network_id, public_key, ip) VALUES ({device}, {network}, '{KEY}', '{ip}')"
        )
    };
    // Another network's address, the hub, network and broadcast addresses.
    for ip in ["10.50.1.5", "10.50.0.1", "10.50.0.0", "10.50.0.127"] {
        refused(&pg.db, &peer(1, 1, ip)).await;
    }
    // A device of tenant 2's user in tenant 1's network.
    refused(&pg.db, &peer(2, 1, "10.50.0.5")).await;
    // A global admin's device may join any network.
    ok(&pg.db, &peer(3, 1, "10.50.0.5")).await;
    // Ownership never changes once saved.
    refused(&pg.db, "UPDATE peer SET ip = '10.50.0.6'").await;
    refused(&pg.db, "UPDATE device SET user_id = 1 WHERE id = 2").await;
    refused(&pg.db, "UPDATE app_user SET tenant_id = 1 WHERE id = 2").await;
    refused(
        &pg.db,
        "UPDATE network SET cidr = '10.50.0.0/26' WHERE id = 1",
    )
    .await;
}

#[tokio::test]
async fn rules_stay_inside_their_tenant() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        "INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port)
             VALUES (2, 2, 2, 'krcmar', 'Krcmar', '10.50.1.0/24', 51802)",
    )
    .await;
    let rule = |tenant: u32, network: u32, target: u32| {
        format!(
            "INSERT INTO rule (tenant_id, network_id, proto, port_from, port_to, target_network_id)
             VALUES ({tenant}, {network}, 'tcp', 22, 22, {target})"
        )
    };
    refused(&pg.db, &rule(1, 1, 2)).await;
    refused(&pg.db, &rule(2, 1, 2)).await;
    ok(&pg.db, &rule(1, 1, 1)).await;
}

#[tokio::test]
async fn migrate_refuses_a_newer_schema_and_regrants() {
    let pg = pg("").await;
    ok(
        &pg.db,
        "INSERT INTO wgate_migration (name) VALUES ('m9999_future')",
    )
    .await;
    assert!(
        migrate(&pg.db).await.is_err(),
        "unknown migration must stop the rollout"
    );
    ok(
        &pg.db,
        "DELETE FROM wgate_migration WHERE name = 'm9999_future'",
    )
    .await;
    // A role created after the first migration gets its rights on the next run.
    ok(&pg.db, "CREATE ROLE wgate_agent LOGIN PASSWORD 'agent'").await;
    migrate(&pg.db).await.expect("migrate");
    let agent_url = pg.url.replace("postgres:postgres@", "wgate_agent:agent@");
    let agent = Database::connect(&agent_url)
        .await
        .expect("connect as agent");
    ok(&agent, "SELECT * FROM peer").await;
}
