//! The `totp` stage of a password login: nothing but the code until it comes, each
//! code once, ±1 step, recovery codes once, wrong codes locked out like wrong
//! passwords (a right password in between resets nothing), and the account-wide pace
//! of code attempts. The server's TOTP clock is the test's (`Env::clock`).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::login::{self, PEER, account, login_from, one, tenant};
use common::totp::{PW, code, enrol, next_step};
use common::{Client, Env, sql};
use serde_json::json;

const OTHER: &str = "198.51.100.1:5000";

/// A user of tenant `t` with a password and TOTP on: (id, secret, recovery codes).
async fn user_with_totp(e: &Env, email: &str, t: i64) -> (i64, Vec<u8>, Vec<String>) {
    let id = account(&e.db, email, "user", Some(t), PW).await;
    let c = password_login(e, email, PEER).await;
    let en = enrol(&c, &e.clock).await;
    (id, en.secret, en.recovery_codes)
}

/// A password login from `peer`, in whatever stage it lands.
async fn password_login(e: &Env, email: &str, peer: &str) -> Client {
    let r = login_from(&e.app, email, PW, peer, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    login::client(&e.app, &r.session().unwrap()).await
}

/// The reasons of the failed second steps so far, oldest first.
async fn reasons(e: &Env) -> serde_json::Value {
    one(
        &e.db,
        "SELECT coalesce(jsonb_agg(detail->'reason' ORDER BY id), '[]') AS r FROM audit
         WHERE action = 'login.totp.failed'",
    )
    .await["r"]
        .clone()
}

#[tokio::test]
async fn a_totp_login_takes_each_code_once() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let (id, secret, codes) = user_with_totp(&e, "u@acme.test", t).await;
    assert_eq!(codes.len(), 10);
    // Sealed: the stored blob is a key id, a nonce and the ciphertext, not the secret.
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let stored = one(
        &e.db,
        &format!(
            "SELECT get_byte(totp_secret, 0) AS key_id, length(totp_secret) AS len,
                    position(decode('{hex}', 'hex') IN totp_secret) AS at
             FROM app_user WHERE id = {id}"
        ),
    )
    .await;
    assert_eq!(stored, json!({ "key_id": 1, "len": 49, "at": 0 }));

    let c = password_login(&e, "u@acme.test", PEER).await;
    let (_, s) = c.get("/session").await;
    assert_eq!(s["stage"], "totp");
    let ttl = one(
        &e.db,
        &format!(
            "SELECT round(extract(epoch FROM expires_at - created_at)) AS s FROM session
             WHERE user_id = {id} AND stage = 'totp'"
        ),
    )
    .await;
    assert_eq!(ttl["s"], 300);
    // Not signed in until the code.
    assert_eq!(c.get("/devices").await.0, StatusCode::UNAUTHORIZED);
    let (s, _) = c.post("/me/password", json!({})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        c.post("/me/totp/setup", json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Two steps past the setup's code, so `now - 30` is unused too.
    next_step(&e.clock);
    let now = e.clock.now();
    // A wrong code, and codes two steps off either way.
    for wrong in [
        "000000".into(),
        code(&secret, now + 60),
        code(&secret, now - 60),
    ] {
        let r = c.second(json!({ "code": wrong })).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert_eq!(r.body["error"], "invalid_credentials");
    }
    let r = c.second(json!({})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // One step off is fine.
    let r = c.second(json!({ "code": code(&secret, now - 30) })).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let full = c.after(&r);
    assert_ne!(full.token, c.token, "the full session has a new token");
    assert_eq!(c.get("/session").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(full.get("/session").await.1["stage"], "full");
    let row = one(
        &e.db,
        &format!("SELECT stage, method FROM session WHERE user_id = {id} ORDER BY id DESC LIMIT 1"),
    )
    .await;
    assert_eq!(row, json!({ "stage": "full", "method": "password_totp" }));

    // The next step works once; then neither it nor an earlier one does.
    let c = password_login(&e, "u@acme.test", PEER).await;
    let r = c.second(json!({ "code": code(&secret, now + 30) })).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let c = password_login(&e, "u@acme.test", PEER).await;
    for used in [now + 30, now, now - 30] {
        let r = c.second(json!({ "code": code(&secret, used) })).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }

    // Recovery codes: each once, in any case.
    sql(&e.db, "DELETE FROM login_failure").await;
    let c = password_login(&e, "u@acme.test", PEER).await;
    let r = c.second(json!({ "recovery_code": codes[0] })).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let left = one(
        &e.db,
        "SELECT detail->'recovery_codes_left' AS n FROM audit
         WHERE action = 'login.totp.ok' ORDER BY id DESC LIMIT 1",
    )
    .await;
    assert_eq!(left["n"], 9);
    let c = password_login(&e, "u@acme.test", PEER).await;
    let r = c.second(json!({ "recovery_code": codes[0] })).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = c
        .second(json!({ "recovery_code": codes[1].to_lowercase() }))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(
        reasons(&e).await,
        json!([
            "wrong_code",
            "wrong_code",
            "wrong_code",
            "replayed_code",
            "replayed_code",
            "replayed_code",
            "wrong_recovery_code"
        ])
    );
}

#[tokio::test]
async fn wrong_codes_lock_the_client_out_like_passwords() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let (id, secret, _) = user_with_totp(&e, "u@acme.test", t).await;
    let here = format!(
        "SELECT coalesce(max(failed), 0) AS n,
                coalesce(bool_or(locked_until > now()), false) AS locked
         FROM login_failure WHERE user_id = {id} AND client = '192.0.2.10'"
    );
    let state = |n: i64, locked: bool| json!({ "n": n, "locked": locked });
    let wrong = json!({ "code": "000000" });
    // The password is counted until its code comes: logging in again resets nothing.
    let c = password_login(&e, "u@acme.test", PEER).await;
    assert_eq!(one(&e.db, &here).await, state(1, false));
    for _ in 0..2 {
        let r = c.second(wrong.clone()).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let c = password_login(&e, "u@acme.test", PEER).await;
    assert_eq!(one(&e.db, &here).await, state(4, false));
    let r = c.second(wrong.clone()).await;
    assert_eq!(r.body["error"], "invalid_credentials");
    assert_eq!(one(&e.db, &here).await, state(5, true));
    // Locked out: the session is over, and the password is refused from here.
    assert_eq!(c.get("/session").await.0, StatusCode::UNAUTHORIZED);
    let r = login_from(&e.app, "u@acme.test", PW, PEER, &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Another client gets in, and its success leaves this lockout alone.
    let other = password_login(&e, "u@acme.test", OTHER).await;
    let body = json!({ "code": code(&secret, e.clock.now()) });
    let r = other.second_from(body, OTHER).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    assert_eq!(one(&e.db, &here).await, state(5, true));
    // Each of this client's five claims counts toward the brake; the other client's
    // two (its password and its code) are taken back.
    let brake = format!("SELECT brake_failures AS n FROM app_user WHERE id = {id}");
    assert_eq!(one(&e.db, &brake).await["n"], 5);

    // A right password on the 5th attempt lifts the lock it set; the code then clears
    // the count.
    sql(
        &e.db,
        &format!(
            "UPDATE login_failure SET failed = 4, locked_until = NULL
             WHERE user_id = {id} AND client = '192.0.2.10'"
        ),
    )
    .await;
    let c = password_login(&e, "u@acme.test", PEER).await;
    assert_eq!(one(&e.db, &here).await, state(5, false));
    next_step(&e.clock);
    let r = c
        .second(json!({ "code": code(&secret, e.clock.now()) }))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(one(&e.db, &here).await, state(0, false));
}

/// The account's code attempts, from any clients, wait their turn: each takes the
/// next slot up front, the gap doubling, so parallel guesses are checked one after
/// another; a slot over 30 s away is a 429.
#[tokio::test]
async fn code_attempts_queue_per_account_whatever_the_client() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let (id, secret, _) = user_with_totp(&e, "u@acme.test", t).await;
    let c = password_login(&e, "u@acme.test", PEER).await;
    // Five wrong codes so far: the next slots are now and 16 s on, the one after 48 s
    // away (a margin no slow runner eats up).
    sql(
        &e.db,
        &format!("UPDATE app_user SET totp_wrong = 5, totp_next_at = now() WHERE id = {id}"),
    )
    .await;
    // Ten clients at once: two get those slots, the rest a 429.
    let started = std::time::Instant::now();
    let guesses: Vec<_> = (0..10)
        .map(|i| {
            let c = c.clone();
            tokio::spawn(async move {
                let peer = format!("203.0.113.{}:1", 10 + i);
                c.second_from(json!({ "code": "000000" }), &peer).await
            })
        })
        .collect();
    let mut replies = vec![];
    for g in guesses {
        replies.push(g.await.unwrap());
    }
    let mut statuses: Vec<u16> = replies.iter().map(|r| r.status.as_u16()).collect();
    statuses.sort_unstable();
    assert_eq!(statuses, [401, 401, 429, 429, 429, 429, 429, 429, 429, 429]);
    let refused = replies
        .iter()
        .find(|r| r.status == StatusCode::TOO_MANY_REQUESTS);
    assert!(refused.unwrap().headers.contains_key("retry-after"));
    assert!(
        started.elapsed().as_secs_f64() >= 15.5,
        "{:?}",
        started.elapsed()
    );
    // Checked one after another, not all at once.
    let spread = one(
        &e.db,
        "SELECT round(extract(epoch FROM max(at) - min(at))) AS s FROM audit
         WHERE action = 'login.totp.failed'",
    )
    .await;
    assert!(spread["s"].as_f64().unwrap() >= 15.0, "{spread}");

    // Far behind: refused at once, nothing reserved; a right code resets the pace.
    let pace = format!(
        "SELECT totp_wrong AS n, totp_next_at IS NULL AS free FROM app_user WHERE id = {id}"
    );
    assert_eq!(one(&e.db, &pace).await, json!({ "n": 7, "free": false }));
    sql(
        &e.db,
        &format!(
            "UPDATE app_user SET totp_next_at = now() + interval '100 seconds' WHERE id = {id}"
        ),
    )
    .await;
    let r = c
        .second(json!({ "code": code(&secret, e.clock.now()) }))
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let wait: u64 = r.headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((60..=70).contains(&wait), "{wait}");
    assert_eq!(one(&e.db, &pace).await["n"], 7);
    sql(
        &e.db,
        &format!("UPDATE app_user SET totp_next_at = now() WHERE id = {id}"),
    )
    .await;
    let r = c
        .second(json!({ "code": code(&secret, e.clock.now()) }))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    assert_eq!(one(&e.db, &pace).await, json!({ "n": 0, "free": true }));
}

#[tokio::test]
async fn a_user_without_totp_is_signed_in_by_the_password() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    let c = password_login(&e, "u@acme.test", PEER).await;
    let (_, s) = c.get("/session").await;
    assert_eq!(
        (&s["stage"], &s["has_password"], &s["totp_enabled"]),
        (&json!("full"), &json!(true), &json!(false))
    );
    // Not a login waiting for a code.
    let r = c.second(json!({ "code": "000000" })).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(c.get("/session").await.0, StatusCode::OK);
}
