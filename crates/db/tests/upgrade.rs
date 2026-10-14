//! Upgrading older databases with `wgate migrate`: 0.1.0 (m0001 only), and one
//! from before the providers moved into the database (m0001–m0003).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{empty, ok, refused};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};

const M0001: &str = concat!(
    include_str!("../src/migration/m0001_init.sql"),
    include_str!("../src/migration/m0001_state.sql")
);
const OLD: &[(&str, &str)] = &[
    ("m0001_init", M0001),
    (
        "m0002_accounts",
        include_str!("../src/migration/m0002_accounts.sql"),
    ),
    (
        "m0003_totp",
        include_str!("../src/migration/m0003_totp.sql"),
    ),
];

/// The database as a release with the first `n` migrations left it.
async fn release(db: &DatabaseConnection, n: usize) {
    ok(
        db,
        "CREATE TABLE wgate_migration (
            name text PRIMARY KEY, checksum text NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now())",
    )
    .await;
    for (name, sql) in &OLD[..n] {
        ok(db, sql).await;
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO wgate_migration (name, checksum) VALUES ($1, md5($2))",
            [(*name).into(), (*sql).into()],
        ))
        .await
        .expect("record");
    }
}

/// 0.1.0: m0001 only.
async fn release_0_1_0(db: &DatabaseConnection) {
    release(db, 1).await;
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
    assert_eq!(applied, ["m0002_accounts", "m0003_totp", "m0004_providers"]);
    // Existing rows: no password, nothing failed; their OIDC sessions (from
    // `[admin_oidc]`, which names no provider) are over.
    ok(
        &pg.db,
        "DO $$ BEGIN
            IF (SELECT count(*) FROM app_user
                WHERE password_hash IS NULL AND brake_failures = 0 AND brake_since IS NULL) <> 2
               OR EXISTS (SELECT FROM session) THEN
                RAISE EXCEPTION 'unexpected defaults';
            END IF;
        END $$;
        INSERT INTO session (token_hash, user_id, csrf, expires_at, method)
            VALUES ('\\x02', 1, 'c', now() + interval '1 day', 'password')",
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
        ["m0002_accounts", "m0003_totp", "m0004_providers"]
    );
}

#[tokio::test]
async fn m0004_moves_providers_into_the_database() {
    let pg = empty().await;
    release(&pg.db, 3).await;
    ok(
        &pg.db,
        "INSERT INTO tenant (id, slug, name) VALUES (1, 'nexial', 'Nexial'), (2, 'krcmar', 'K');
         INSERT INTO app_user (id, tenant_id, email, role, oidc_sub) VALUES
             (1, NULL, 'admin@mmik.cz', 'global_admin', 'google-sub'),
             (2, 1, 'a@nexial.cz', 'user', NULL);
         INSERT INTO oidc_provider (tenant_id, issuer, client_id) VALUES (1, 'https://x', 'y');
         INSERT INTO session (token_hash, user_id, csrf, expires_at, method) VALUES
             ('\\x01', 1, 'c', now() + interval '1 day', 'oidc'),
             ('\\x02', 2, 'c', now() + interval '1 day', 'password_totp')",
    )
    .await;
    let applied = wgate_db::migrate(&pg.db).await.expect("migrate");
    assert_eq!(applied, ["m0004_providers"]);
    // The `[admin_oidc]` bindings and sessions are gone, as are the provider rows
    // nothing used; the password session stays.
    refused(&pg.db, "SELECT oidc_sub FROM app_user").await;
    ok(
        &pg.db,
        "DO $$ BEGIN
            IF EXISTS (SELECT FROM oidc_provider)
               OR (SELECT string_agg(method, ',') FROM session) <> 'password_totp' THEN
                RAISE EXCEPTION 'left behind';
            END IF;
         END $$",
    )
    .await;
    // Several providers per tenant and global ones; a name once per login page.
    ok(
        &pg.db,
        "INSERT INTO oidc_provider (id, tenant_id, name, issuer, client_id, client_secret,
                                    link_by_email) VALUES
             (1, NULL, 'Google', 'https://accounts.google.com', 'a', '\\x01', true),
             (2, NULL, 'Keycloak', 'https://kc', 'b', '\\x01', false),
             (3, 1, 'Google', 'https://accounts.google.com', 'c', '\\x01', false),
             (4, 1, 'Azure', 'https://login.microsoftonline.com', 'd', '\\x01', false),
             (5, 2, 'Google', 'https://accounts.google.com', 'e', '\\x01', false)",
    )
    .await;
    for bad in [
        "(NULL, 'google', 'https://x', 'f', '\\x01', false)",
        "(1, 'AZURE', 'https://x', 'f', '\\x01', false)",
        "(1, 'Other', 'https://x', 'f', '\\x01', true)",
        "(1, '', 'https://x', 'f', '\\x01', false)",
        "(1, 'Other', 'https://x', 'f', NULL, false)",
    ] {
        refused(
            &pg.db,
            &format!(
                "INSERT INTO oidc_provider (tenant_id, name, issuer, client_id, client_secret,
                                            link_by_email) VALUES {bad}"
            ),
        )
        .await;
    }
    refused(
        &pg.db,
        "UPDATE oidc_provider SET tenant_id = 2 WHERE id = 3",
    )
    .await;
    // One subject per provider, one identity per provider per account.
    ok(
        &pg.db,
        "INSERT INTO identity (user_id, provider_id, subject) VALUES
             (1, 1, 's1'), (2, 1, 's2'), (2, 3, 's1')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO identity (user_id, provider_id, subject) VALUES (1, 2, '')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO identity (user_id, provider_id, subject) VALUES (1, 1, 's9')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO identity (user_id, provider_id, subject) VALUES (1, 3, 's1')",
    )
    .await;
    // An OIDC session names its provider, no other does, and none has a default.
    refused(
        &pg.db,
        "INSERT INTO session (token_hash, user_id, csrf, expires_at)
         VALUES ('\\x03', 1, 'c', now())",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO session (token_hash, user_id, csrf, expires_at, method)
         VALUES ('\\x03', 1, 'c', now(), 'oidc')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO session (token_hash, user_id, csrf, expires_at, method, provider_id)
         VALUES ('\\x03', 1, 'c', now(), 'password', 1)",
    )
    .await;
    // A provider takes its identities and sessions along; an account its identities.
    ok(
        &pg.db,
        "INSERT INTO session (token_hash, user_id, csrf, expires_at, method, provider_id)
             VALUES ('\\x03', 1, 'c', now() + interval '1 day', 'oidc', 1);
         DELETE FROM oidc_provider WHERE id = 1;
         DELETE FROM app_user WHERE id = 2;
         DO $$ BEGIN
            IF EXISTS (SELECT FROM identity) OR EXISTS (SELECT FROM session WHERE user_id = 1)
            THEN
                RAISE EXCEPTION 'left behind';
            END IF;
         END $$",
    )
    .await;
}
