//! A password never reaches the log, nor the audit trail: logins (right, wrong,
//! locked), a change, the CLI. Its own test binary, as `log.rs` (a global subscriber).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::capture::Captured;
use common::login::{self, account, login};
use common::sql;
use serde_json::json;

const PW: &str = "correct horse battery";
const WRONG: &str = "wrong horse battery";
const NEW: &str = "a new and longer passphrase";

#[tokio::test]
async fn a_password_never_reaches_the_log_or_the_audit() {
    let captured = Captured::install();
    let e = common::env().await;
    sql(
        &e.db,
        "INSERT INTO tenant (id, slug, name) VALUES (1, 'acme', 'A')",
    )
    .await;
    account(&e.db, "u@acme.test", "user", Some(1), PW).await;
    login(&e.app, "nobody@acme.test", PW).await;
    for _ in 0..5 {
        login(&e.app, "u@acme.test", WRONG).await;
    }
    login(&e.app, "u@acme.test", PW).await;
    sql(&e.db, "DELETE FROM login_failure").await;
    let c = login::client(
        &e.app,
        &login(&e.app, "u@acme.test", PW).await.session().unwrap(),
    )
    .await;
    let (s, _) = c
        .post("/me/password", json!({ "current": WRONG, "new": NEW }))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = c
        .post("/me/password", json!({ "current": PW, "new": NEW }))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let log = captured.text();
    assert!(
        log.contains("UPDATE app_user"),
        "the subscriber missed the queries"
    );
    let rows = {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        e.db.query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT string_agg(action || ' ' || detail::text, '\n') AS t FROM audit",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<String>("", "t")
        .unwrap()
    };
    for action in [
        "login.password.failed",
        "locked_until",
        "login.password.ok",
        "user.password.change",
        "user.password.failed",
    ] {
        assert!(rows.contains(action), "{action} missing: {rows}");
    }
    for secret in [PW, WRONG, NEW] {
        assert!(!log.contains(secret), "{secret} was logged");
        assert!(!rows.contains(secret), "{secret} in the audit");
    }
}
