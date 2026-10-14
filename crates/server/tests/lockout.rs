//! The guessing brakes in Postgres: a lockout per account and client, claimed before
//! the verify (so parallel guesses do not all get one), the account-wide brake that
//! known clients skip, and attempts that finish when their client hangs up.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::login::{PEER, account, login_from, one, tenant};
use common::sql;
use serde_json::json;

const PW: &str = "correct horse battery";
const OTHER: &str = "198.51.100.1:5000";

/// (failures in a row, seconds of lockout left) of `id` from `client`.
fn row_of(id: i64, client: &str) -> String {
    format!(
        "SELECT coalesce(max(failed), 0) AS n,
                max(ceil(extract(epoch FROM locked_until - now())))::int AS secs
         FROM login_failure WHERE user_id = {id} AND client = '{client}'"
    )
}

/// `n` failures in a row and, when locked, `secs` (give or take a slow CI) left.
async fn assert_row(db: &sea_orm::DatabaseConnection, query: &str, n: i64, secs: Option<i64>) {
    let row = one(db, query).await;
    assert_eq!(row["n"], n, "{row}");
    match (secs, row["secs"].as_i64()) {
        (None, None) => {}
        (Some(want), Some(got)) => assert!((want - 10..=want).contains(&got), "{row}"),
        _ => panic!("lock: want {secs:?}, got {row}"),
    }
}

#[tokio::test]
async fn five_failures_lock_out_that_client_only() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let id = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    let here = row_of(id, "192.0.2.10");
    let try_here = |pw: &'static str| login_from(&e.app, "u@acme.test", pw, PEER, &[]);
    for n in 1..=4 {
        assert_eq!(try_here("wrong").await.status, StatusCode::UNAUTHORIZED);
        assert_row(&e.db, &here, n, None).await;
    }
    try_here("wrong").await;
    assert_row(&e.db, &here, 5, Some(60)).await;
    // The lock is in the same audit entry as the failure that set it.
    let a = one(
        &e.db,
        "SELECT detail->>'failed_logins' AS n, detail ? 'locked_until' AS locked
         FROM audit ORDER BY id DESC LIMIT 1",
    )
    .await;
    assert_eq!(a, json!({ "n": "5", "locked": true }));
    // Locked: even the right password is refused here (and not counted)...
    assert_eq!(try_here(PW).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(one(&e.db, &here).await["n"], 5);
    // ...but not from another client, whose success leaves this lockout alone.
    let r = login_from(&e.app, "u@acme.test", PW, OTHER, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(one(&e.db, &here).await["n"], 5);
    // Once it is over, each further failure locks for twice as long, up to 15 min.
    sql(
        &e.db,
        "UPDATE login_failure SET locked_until = now() - interval '1 second'",
    )
    .await;
    try_here("wrong").await;
    assert_row(&e.db, &here, 6, Some(120)).await;
    sql(
        &e.db,
        "UPDATE login_failure SET failed = 40, locked_until = NULL",
    )
    .await;
    try_here("wrong").await;
    assert_row(&e.db, &here, 41, Some(900)).await;
    // A success starts this client over.
    sql(
        &e.db,
        "UPDATE login_failure SET locked_until = now() - interval '1 second'",
    )
    .await;
    assert_eq!(try_here(PW).await.status, StatusCode::NO_CONTENT);
    assert_row(&e.db, &here, 0, None).await;
    // The CLI clears every client's lockout and the brake.
    sql(
        &e.db,
        &format!(
            "INSERT INTO login_failure (user_id, client, failed, locked_until)
             VALUES ({id}, '192.0.2.10', 7, now() + interval '1 hour'),
                    ({id}, '203.0.113.0', 9, now() + interval '1 hour');
             INSERT INTO login_known (user_id, client) VALUES ({id}, '203.0.113.9');
             UPDATE app_user SET brake_since = now(), brake_failures = 300, brake_last_at = now()"
        ),
    )
    .await;
    wgate_server::set_password(&e.db, "u@acme.test", wgate_server::Password::new(PW.into()))
        .await
        .unwrap();
    let left = one(
        &e.db,
        &format!(
            "SELECT (SELECT count(*) FROM login_failure) AS rows,
                    (SELECT count(*) FROM login_known) AS known, brake_failures AS brake
             FROM app_user WHERE id = {id}"
        ),
    )
    .await;
    assert_eq!(left, json!({ "rows": 0, "known": 0, "brake": 0 }));
    assert_eq!(try_here(PW).await.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn parallel_guesses_get_one_verify_per_attempt_left() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let id = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    sql(
        &e.db,
        &format!(
            "INSERT INTO login_failure (user_id, client, failed) VALUES ({id}, '192.0.2.10', 4)"
        ),
    )
    .await;
    let guesses = (0..10).map(|i| {
        let app = e.app.clone();
        tokio::spawn(async move {
            let guess = format!("wrong guess number {i}");
            login_from(&app, "u@acme.test", &guess, PEER, &[])
                .await
                .status
        })
    });
    for g in guesses.collect::<Vec<_>>() {
        assert_eq!(g.await.unwrap(), StatusCode::UNAUTHORIZED);
    }
    // One attempt was left before the lockout: one guess was verified, nine refused.
    assert_eq!(one(&e.db, &row_of(id, "192.0.2.10")).await["n"], 5);
    let reasons = one(
        &e.db,
        "SELECT count(*) FILTER (WHERE detail->>'reason' = 'wrong_password') AS verified,
                count(*) FILTER (WHERE detail->>'reason' = 'locked') AS refused
         FROM audit WHERE action = 'login.password.failed'",
    )
    .await;
    assert_eq!(reasons, json!({ "verified": 1, "refused": 9 }));
}

#[tokio::test]
async fn the_brake_holds_up_strangers_but_not_the_owners_clients() {
    let e = common::env().await;
    // A plain user: an admin's right password alone (no TOTP yet) resets nothing.
    let t = tenant(&e.db, "acme").await;
    let id = account(&e.db, "root@x.test", "user", Some(t), PW).await;
    let at =
        |client: &'static str, pw: &'static str| login_from(&e.app, "root@x.test", pw, client, &[]);
    let reason = async || {
        one(
            &e.db,
            "SELECT detail->>'reason' AS r FROM audit ORDER BY id DESC LIMIT 1",
        )
        .await["r"]
            .clone()
    };
    // The admin's usual client.
    assert_eq!(at(OTHER, PW).await.status, StatusCode::NO_CONTENT);
    // An attacker makes the 100th failure of the hour, from wherever.
    sql(
        &e.db,
        &format!(
            "UPDATE app_user SET brake_since = now() - interval '10 minutes',
                 brake_failures = 99, brake_last_at = now() - interval '2 minutes'
             WHERE id = {id}"
        ),
    )
    .await;
    at("203.0.113.1:1", "wrong").await;
    let b = format!("SELECT brake_failures AS n FROM app_user WHERE id = {id}");
    assert_eq!(one(&e.db, &b).await["n"], 100);
    // Braked: within the minute no new client gets an attempt, even with the password,
    // and polling counts against the poller's own client...
    for _ in 0..5 {
        assert_eq!(
            at("203.0.113.2:1", PW).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(reason().await, "braked");
    }
    assert_row(&e.db, &row_of(id, "203.0.113.2"), 5, Some(60)).await;
    // ...while the admin's known client logs in, without taking the minute's slot.
    assert_eq!(at(OTHER, PW).await.status, StatusCode::NO_CONTENT);
    assert_eq!(
        at("203.0.113.3:1", PW).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(reason().await, "braked");
    // A minute later: one stranger's attempt, then the brake again.
    sql(
        &e.db,
        &format!(
            "UPDATE app_user SET brake_last_at = now() - interval '61 seconds' WHERE id = {id}"
        ),
    )
    .await;
    at("203.0.113.4:1", "wrong").await;
    assert_eq!(reason().await, "wrong_password");
    at("203.0.113.5:1", PW).await;
    assert_eq!(reason().await, "braked");
    // Failures older than the hour no longer count; the poller is still locked out.
    sql(
        &e.db,
        &format!("UPDATE app_user SET brake_since = now() - interval '61 minutes' WHERE id = {id}"),
    )
    .await;
    assert_eq!(at("203.0.113.6:1", PW).await.status, StatusCode::NO_CONTENT);
    at("203.0.113.2:1", PW).await;
    assert_eq!(reason().await, "locked");
}

#[tokio::test]
async fn an_unknown_email_leaves_nothing_behind() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    account(&e.db, "root@x.test", "user", Some(t), PW).await;
    for _ in 0..3 {
        login_from(&e.app, "nobody@x.test", PW, PEER, &[]).await;
    }
    let left = one(
        &e.db,
        "SELECT (SELECT count(*) FROM login_failure) AS rows,
                (SELECT sum(brake_failures) FROM app_user) AS brake",
    )
    .await;
    assert_eq!(left, json!({ "rows": 0, "brake": 0 }));
}

#[tokio::test]
async fn an_attempt_whose_client_hangs_up_still_finishes() {
    let e = common::env().await;
    // A plain user: an admin's right password alone (no TOTP yet) resets nothing.
    let t = tenant(&e.db, "acme").await;
    let id = account(&e.db, "root@x.test", "user", Some(t), PW).await;
    // Dropped after 0 to 57 ms: some before the claim, some during the verify, some
    // after the reply.
    for i in 0..20u64 {
        let peer = format!("192.0.2.{}:1", 100 + i);
        let attempt = login_from(&e.app, "root@x.test", PW, &peer, &[]);
        let _ = tokio::time::timeout(std::time::Duration::from_millis(i * 3), attempt).await;
    }
    // Every claim that was made gets its success: no failure is left counted, and
    // every session has its audit entry.
    let state = format!(
        "SELECT (SELECT count(*) FROM login_failure) AS rows, brake_failures AS brake,
                (SELECT count(*) FROM session WHERE user_id = {id}) AS sessions,
                (SELECT count(*) FROM audit WHERE action = 'login.password.ok') AS ok
         FROM app_user WHERE id = {id}"
    );
    let mut last = json!(null);
    for _ in 0..100 {
        last = one(&e.db, &state).await;
        if last["rows"] == 0 && last["sessions"] == last["ok"] {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(last["rows"], 0, "{last}");
    assert_eq!(last["brake"], 0, "{last}");
    assert_eq!(last["sessions"], last["ok"], "{last}");
}
