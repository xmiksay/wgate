//! Upgrading a 0.1.0 database (m0001 only) with `wgate migrate`.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{empty, ok, refused};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};

/// The database as 0.1.0 left it: m0001 applied and recorded.
async fn release_0_1_0(db: &DatabaseConnection) {
    let m0001 = concat!(
        include_str!("../src/migration/m0001_init.sql"),
        include_str!("../src/migration/m0001_state.sql")
    );
    ok(
        db,
        "CREATE TABLE wgate_migration (
            name text PRIMARY KEY, checksum text NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now())",
    )
    .await;
    ok(db, m0001).await;
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO wgate_migration (name, checksum) VALUES ('m0001_init', md5($1))",
        [m0001.into()],
    ))
    .await
    .expect("record m0001");
}

const ACCOUNTS: &str = "
    INSERT INTO tenant (id, slug, name) VALUES (1, 'nexial', 'Nexial'), (2, 'krcmar', 'Krcmar');
    INSERT INTO app_user (id, tenant_id, email, role) VALUES
        (1, NULL, 'admin@mmik.cz', 'global_admin'), (2, 1, 'a@nexial.cz', 'user');
    INSERT INTO session (token_hash, user_id, csrf, expires_at)
        VALUES ('\\x01', 1, 'c', now() + interval '1 day');
";

#[tokio::test]
async fn m0002_applies_on_a_0_1_0_database() {
    let pg = empty().await;
    release_0_1_0(&pg.db).await;
    ok(&pg.db, ACCOUNTS).await;
    let applied = wgate_db::migrate(&pg.db).await.expect("migrate");
    assert_eq!(applied, ["m0002_accounts", "m0003_totp"]);
    // Existing rows: no password, nothing failed, their sessions full OIDC ones.
    ok(
        &pg.db,
        "DO $$ BEGIN
            IF (SELECT count(*) FROM app_user
                WHERE password_hash IS NULL AND brake_failures = 0 AND brake_since IS NULL) <> 2
               OR (SELECT stage || '/' || method FROM session) <> 'full/oidc' THEN
                RAISE EXCEPTION 'unexpected defaults';
            END IF;
        END $$",
    )
    .await;
    // An email is now one account across wgate, any case.
    refused(
        &pg.db,
        "INSERT INTO app_user (id, tenant_id, email, role) VALUES (3, 2, 'A@Nexial.cz', 'user')",
    )
    .await;
    refused(&pg.db, "UPDATE session SET stage = 'half'").await;
    refused(&pg.db, "UPDATE app_user SET brake_failures = -1").await;
    refused(&pg.db, "UPDATE app_user SET brake_last_at = 'infinity'").await;
    refused(
        &pg.db,
        "INSERT INTO login_failure (user_id, client, failed, locked_until)
         VALUES (1, '192.0.2.1', 5, 'infinity')",
    )
    .await;
    refused(&pg.db, "UPDATE session SET method = 'magic'").await;
    ok(&pg.db, "UPDATE session SET stage = 'totp'").await;
    // m0003: TOTP is off for everyone; on needs a secret; links have a purpose.
    ok(&pg.db, "UPDATE session SET method = 'password_totp'").await;
    refused(&pg.db, "UPDATE app_user SET totp_enabled_at = now()").await;
    ok(
        &pg.db,
        "UPDATE app_user SET totp_secret = '\\x01', totp_enabled_at = now() WHERE id = 1",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO account_token (user_id, token_hash, purpose, expires_at)
         VALUES (1, '\\x01', 'login', now())",
    )
    .await;
    // An account's codes and links go with it; a link outlives the admin who made it.
    ok(
        &pg.db,
        "INSERT INTO recovery_code (user_id, code_hash) VALUES (2, '\\x01');
         INSERT INTO account_token (user_id, token_hash, purpose, created_by, expires_at)
         VALUES (2, '\\x02', 'reset', 1, now());
         DELETE FROM app_user WHERE id = 1;
         DO $$ BEGIN
            IF (SELECT count(*) FROM account_token WHERE created_by IS NULL) <> 1 THEN
                RAISE EXCEPTION 'the link went with its maker';
            END IF;
         END $$;
         DELETE FROM app_user WHERE id = 2;
         DO $$ BEGIN
            IF EXISTS (SELECT FROM account_token) OR EXISTS (SELECT FROM recovery_code) THEN
                RAISE EXCEPTION 'left behind';
            END IF;
         END $$",
    )
    .await;
}

#[tokio::test]
async fn m0002_names_emails_shared_by_tenants() {
    let pg = empty().await;
    release_0_1_0(&pg.db).await;
    ok(&pg.db, ACCOUNTS).await;
    ok(
        &pg.db,
        "INSERT INTO app_user (id, tenant_id, email, role) VALUES (3, 2, 'A@nexial.cz', 'user')",
    )
    .await;
    let err = wgate_db::migrate(&pg.db)
        .await
        .expect_err("two accounts, one email");
    assert!(err.to_string().contains("a@nexial.cz"), "{err}");
    // Nothing applied: still 0.1.0, ready once the duplicate is gone.
    ok(&pg.db, "DELETE FROM app_user WHERE tenant_id = 2").await;
    assert_eq!(
        wgate_db::migrate(&pg.db).await.expect("migrate"),
        ["m0002_accounts", "m0003_totp"]
    );
}
