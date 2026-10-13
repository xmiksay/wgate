//! Migrations, the agent role's grants and change notifications, against a real
//! Postgres.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::{BASE, as_agent, ok, pg, refused};
use sea_orm::{ConnectionTrait, Database, TransactionTrait};
use wgate_db::{migrate, revision};

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
async fn changes_notify_on_commit_only() {
    let pg = pg("").await;
    let mut listener = revision::listener(&pg.url).await.expect("listen");

    let txn = pg.db.begin().await.expect("begin");
    txn.execute_unprepared("INSERT INTO tenant (slug, name) VALUES ('gone', 'x')")
        .await
        .expect("insert");
    txn.rollback().await.expect("rollback");
    assert_eq!(revision::current(&pg.db).await.expect("revision"), 0);

    // No write path calls anything: the triggers bump and notify.
    ok(
        &pg.db,
        "INSERT INTO tenant (slug, name) VALUES ('kept', 'x')",
    )
    .await;
    let note = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("notified within 5 s")
        .expect("notification");
    // The rolled-back insert never notified: the first notification is the commit's.
    assert_eq!(note.channel(), revision::CHANNEL);
    assert_eq!(note.payload(), "1");
    // The agent's own writes do not wake it.
    ok(
        &pg.db,
        "INSERT INTO agent_status (applied_revision, applied_at) VALUES (1, now())",
    )
    .await;
    assert_eq!(revision::current(&pg.db).await.expect("revision"), 1);
}

#[tokio::test]
async fn the_agent_role_reads_the_desired_state_and_writes_only_its_tables() {
    let pg = pg("CREATE ROLE wgate_agent LOGIN PASSWORD 'agent'").await;
    ok(&pg.db, BASE).await;
    let agent = Database::connect(&as_agent(&pg.url))
        .await
        .expect("connect as agent");
    ok(
        &agent,
        "SELECT * FROM tenant, network, peer, peer_route, rule, inbound",
    )
    .await;
    ok(
        &agent,
        "SELECT id, tenant_id, role, disabled_at FROM app_user",
    )
    .await;
    // No emails, OIDC subjects or audit trail for the root process.
    refused(&agent, "SELECT email FROM app_user").await;
    refused(&agent, "SELECT * FROM oidc_provider").await;
    refused(&agent, "SELECT * FROM audit").await;
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
async fn migrate_refuses_a_newer_schema_and_regrants() {
    let pg = pg("").await;
    ok(
        &pg.db,
        "INSERT INTO wgate_migration (name, checksum) VALUES ('m9999_future', 'x')",
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
    let agent = Database::connect(&as_agent(&pg.url))
        .await
        .expect("connect as agent");
    ok(&agent, "SELECT * FROM peer").await;
}

#[tokio::test]
async fn one_notification_per_changing_transaction() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let base = revision::current(&pg.db).await.expect("revision");
    // Several statements, one transaction: one bump.
    ok(
        &pg.db,
        "BEGIN;
         UPDATE network SET mesh = true;
         UPDATE network SET mesh = false;
         INSERT INTO tenant (id, slug, name) VALUES (3, 't3', 'x');
         COMMIT",
    )
    .await;
    assert_eq!(revision::current(&pg.db).await.expect("revision"), base + 1);
    // Nothing changed, or only data the state does not depend on: no bump.
    ok(&pg.db, "UPDATE peer SET revoked_at = now() WHERE id = 999").await;
    ok(
        &pg.db,
        "UPDATE app_user SET email = 'new@nexial.cz', oidc_sub = 's'",
    )
    .await;
    ok(&pg.db, "UPDATE device SET name = 'renamed'").await;
    assert_eq!(revision::current(&pg.db).await.expect("revision"), base + 1);
    ok(&pg.db, "UPDATE app_user SET disabled_at = now()").await;
    assert_eq!(revision::current(&pg.db).await.expect("revision"), base + 2);
}

#[tokio::test]
async fn migrate_refuses_an_edited_migration() {
    let pg = pg("").await;
    ok(&pg.db, "UPDATE wgate_migration SET checksum = 'edited'").await;
    let err = migrate(&pg.db)
        .await
        .expect_err("a changed migration must stop the rollout");
    assert!(err.to_string().contains("differs"), "{err}");
}

#[tokio::test]
async fn regranting_narrows_an_over_granted_agent() {
    let pg = pg("CREATE ROLE wgate_agent LOGIN PASSWORD 'agent'").await;
    ok(&pg.db, "GRANT SELECT ON app_user, audit TO wgate_agent").await;
    migrate(&pg.db).await.expect("migrate");
    let agent = Database::connect(&as_agent(&pg.url))
        .await
        .expect("connect as agent");
    refused(&agent, "SELECT email FROM app_user").await;
    refused(&agent, "SELECT * FROM audit").await;
    ok(&agent, "SELECT id, tenant_id FROM app_user").await;
}

#[tokio::test]
async fn state_is_written_at_read_committed_and_truncate_counts() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let txn = pg
        .db
        .begin_with_config(Some(sea_orm::IsolationLevel::RepeatableRead), None)
        .await
        .expect("begin");
    txn.execute_unprepared("UPDATE network SET mesh = true")
        .await
        .expect("update");
    assert!(
        txn.commit().await.is_err(),
        "a snapshot-isolated state write is refused"
    );
    let base = revision::current(&pg.db).await.expect("revision");
    ok(&pg.db, "TRUNCATE inbound").await;
    assert_eq!(revision::current(&pg.db).await.expect("revision"), base + 1);
}
