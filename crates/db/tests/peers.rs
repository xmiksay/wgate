//! Peers, their addresses, keys and LANs, and revocation, against a real Postgres.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::{BASE, KEY, ok, pg, refused};
use sea_orm::{ConnectionTrait, TransactionTrait};

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
    // Wait until the revocation is actually blocked on the route insert's lock.
    let deadline = Instant::now() + Duration::from_secs(10);
    while count(
        &pg.db,
        "SELECT count(*) AS n FROM pg_stat_activity
                          WHERE wait_event_type = 'Lock' AND query LIKE 'UPDATE peer%'",
    )
    .await
        == 0
    {
        assert!(
            Instant::now() < deadline,
            "the revocation never waited for the lock"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    insert.commit().await.expect("commit route");
    revoke.await.expect("revoke task");
    assert_eq!(
        count(&pg.db, "SELECT count(*) AS n FROM peer_route").await,
        0
    );
}

async fn count(db: &sea_orm::DatabaseConnection, sql: &str) -> i64 {
    db.query_one_raw(sea_orm::Statement::from_string(
        sea_orm::DbBackend::Postgres,
        sql,
    ))
    .await
    .expect("query")
    .expect("row")
    .try_get("", "n")
    .expect("n")
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
async fn revocation_is_final_and_unchanged_values_may_be_rewritten() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES (1, 1, 1, '{KEY}', '10.50.0.2')"
        ),
    )
    .await;
    // A full-row save that rewrites the ownership columns unchanged is fine.
    ok(
        &pg.db,
        &format!(
            "UPDATE peer SET device_id = 1, network_id = 1, ip = '10.50.0.2', public_key = '{KEY}'"
        ),
    )
    .await;
    ok(
        &pg.db,
        "UPDATE network SET name = 'renamed', tenant_id = 1, block_id = 1, cidr = '10.50.0.0/25'",
    )
    .await;
    ok(&pg.db, "UPDATE peer SET revoked_at = now()").await;
    refused(&pg.db, "UPDATE peer SET revoked_at = NULL").await;
    refused(
        &pg.db,
        "UPDATE peer SET revoked_at = now() - interval '1 day'",
    )
    .await;
}
