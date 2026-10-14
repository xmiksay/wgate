//! Password login: sessions, the uniform refusal, JSON only, and the per-client
//! limit (the lockouts: `lockout.rs`).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::{StatusCode, header};
use common::login::{self, PEER, account, login, login_from, one, send, tenant};
use common::sql;
use sea_orm::DatabaseConnection;
use serde_json::json;

const PW: &str = "correct horse battery";

/// No password, in any form a request carried, ever reaches the audit trail.
async fn audit_has_no(db: &DatabaseConnection, secrets: &[&str]) {
    let all = one(db, "SELECT string_agg(detail::text, ' ') AS t FROM audit").await;
    let all = all["t"].as_str().unwrap_or_default();
    for s in secrets {
        assert!(!all.contains(s), "{s} in the audit: {all}");
    }
}

#[tokio::test]
async fn every_role_logs_in_with_a_password() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    wgate_server::grant_admin(&e.db, "root@example.org")
        .await
        .unwrap();
    wgate_server::set_password(
        &e.db,
        "root@example.org",
        wgate_server::Password::new(PW.into()),
    )
    .await
    .unwrap();
    account(&e.db, "admin@acme.test", "tenant_admin", Some(t), PW).await;
    let user = account(&e.db, "user@acme.test", "user", Some(t), PW).await;
    // Admins set up TOTP first (`totp.rs`); a user without it is signed in.
    for (email, role, stage, tenants) in [
        (
            "ROOT@example.org",
            "global_admin",
            "enrol",
            StatusCode::FORBIDDEN,
        ),
        (
            "admin@acme.test",
            "tenant_admin",
            "enrol",
            StatusCode::FORBIDDEN,
        ),
        (" user@acme.test", "user", "full", StatusCode::FORBIDDEN),
    ] {
        let r = login(&e.app, email, PW).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{email}: {}", r.body);
        let set = r.headers[header::SET_COOKIE].to_str().unwrap();
        for attr in ["HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=604800"] {
            assert!(set.contains(attr), "{set}");
        }
        let c = login::client(&e.app, &r.session().unwrap()).await;
        let (_, s) = c.get("/session").await;
        assert_eq!((&s["role"], &s["stage"]), (&json!(role), &json!(stage)));
        // What they may do is their role's: a plain user has no admin API.
        assert_eq!(c.get("/tenants").await.0, tenants, "{role}");
    }
    let s = one(
        &e.db,
        &format!("SELECT stage, method FROM session WHERE user_id = {user}"),
    )
    .await;
    assert_eq!(s, json!({ "stage": "full", "method": "password" }));
    let ok = one(
        &e.db,
        &format!(
            "SELECT actor_user_id, detail->>'ip' AS ip FROM audit
             WHERE action = 'login.password.ok' AND target = 'app_user/{user}'"
        ),
    )
    .await;
    assert_eq!(ok, json!({ "actor_user_id": user, "ip": "192.0.2.10" }));
    audit_has_no(&e.db, &[PW]).await;
}

#[tokio::test]
async fn every_failure_gets_the_same_answer() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let off = tenant(&e.db, "off").await;
    account(&e.db, "ok@acme.test", "user", Some(t), PW).await;
    account(&e.db, "disabled@acme.test", "user", Some(t), PW).await;
    account(&e.db, "tenant-off@off.test", "tenant_admin", Some(off), PW).await;
    account(&e.db, "locked@acme.test", "user", Some(t), PW).await;
    sql(
        &e.db,
        &format!(
            "INSERT INTO app_user (tenant_id, email, role) VALUES ({t}, 'nopw@acme.test', 'user')"
        ),
    )
    .await;
    sql(
        &e.db,
        "UPDATE app_user SET disabled_at = now() WHERE email = 'disabled@acme.test'",
    )
    .await;
    sql(
        &e.db,
        &format!("UPDATE tenant SET disabled_at = now() WHERE id = {off}"),
    )
    .await;
    account(&e.db, "braked@acme.test", "user", Some(t), PW).await;
    sql(
        &e.db,
        "INSERT INTO login_failure (user_id, client, failed, locked_until)
         SELECT id, '192.0.2.10', 5, now() + interval '1 hour' FROM app_user
         WHERE email = 'locked@acme.test';
         UPDATE app_user SET brake_since = now(), brake_failures = 100, brake_last_at = now()
         WHERE email = 'braked@acme.test'",
    )
    .await;
    let mut seen = vec![];
    for (email, password, reason) in [
        ("nobody@acme.test", PW, "unknown_email"),
        ("ok@acme.test", "wrong horse battery", "wrong_password"),
        ("ok@acme.test", "short", "wrong_password"),
        ("nopw@acme.test", PW, "no_password"),
        ("disabled@acme.test", PW, "disabled"),
        ("tenant-off@off.test", PW, "disabled"),
        ("locked@acme.test", PW, "locked"),
        ("braked@acme.test", PW, "braked"),
        // A password typed into the email box is not kept.
        ("correct horse battery", PW, "unknown_email"),
    ] {
        let r = login(&e.app, email, password).await;
        assert!(r.session().is_none(), "{email}");
        seen.push((r.status, r.body));
        let a = one(
            &e.db,
            "SELECT action, detail->>'reason' AS reason, detail->>'email' AS email
             FROM audit ORDER BY id DESC LIMIT 1",
        )
        .await;
        let kept = email.contains('@').then_some(email);
        assert_eq!(
            a,
            json!({ "action": "login.password.failed", "reason": reason, "email": kept }),
        );
    }
    assert_eq!(seen[0].0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        seen[0].1,
        json!({ "error": "invalid_credentials", "message": "invalid credentials" })
    );
    assert!(seen.iter().all(|s| *s == seen[0]), "{seen:?}");
    audit_has_no(&e.db, &[PW, "wrong horse battery", "short"]).await;
}

#[tokio::test]
async fn twenty_attempts_a_minute_per_client() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    for _ in 0..20 {
        let r = login_from(&e.app, "nobody@acme.test", PW, PEER, &[]).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    // Even the right password: the client is out of attempts.
    let r = login_from(&e.app, "u@acme.test", PW, PEER, &[]).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.body["error"], "too_many_attempts");
    let wait: u64 = r.headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    // Another client is not held up.
    let r = login_from(&e.app, "u@acme.test", PW, "198.51.100.1:5000", &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn forwarded_for_counts_only_from_a_trusted_proxy() {
    let e = common::env_with(|c| {
        c.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
    })
    .await;
    let proxy = "10.0.0.1:443";
    let from = |client: &'static str| [("x-forwarded-for", client)];
    for _ in 0..20 {
        login_from(
            &e.app,
            "x@y.test",
            "pw",
            proxy,
            &from("1.1.1.1, 198.51.100.7"),
        )
        .await;
    }
    let r = login_from(&e.app, "x@y.test", "pw", proxy, &from("198.51.100.7")).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // Another client behind the same proxy has its own attempts.
    let r = login_from(&e.app, "x@y.test", "pw", proxy, &from("198.51.100.8")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let ip = one(
        &e.db,
        "SELECT detail->>'ip' AS ip FROM audit ORDER BY id DESC LIMIT 1",
    )
    .await;
    assert_eq!(ip["ip"], "198.51.100.8");
    // Anyone else's header is their own claim: every attempt is the peer's.
    let direct = "203.0.113.5:5000";
    for i in 0..20 {
        let fake = format!("198.51.100.{}", 100 + i);
        let r = send(
            &e.app,
            "POST",
            "/auth/password",
            Some(json!({ "email": "x@y.test", "password": "pw" })),
            direct,
            &[("x-forwarded-for", &fake)],
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = login_from(&e.app, "x@y.test", "pw", direct, &from("198.51.100.9")).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn only_json_is_taken() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    let body = json!({ "email": "u@acme.test", "password": PW }).to_string();
    let form = format!("email=u%40acme.test&password={}", PW.replace(' ', "+"));
    // What a cross-site form can send: refused before anything is looked at.
    for (kind, body) in [
        ("text/plain", body),
        ("application/x-www-form-urlencoded", form),
    ] {
        let res = tower::ServiceExt::oneshot(
            e.app.clone(),
            axum::http::Request::post("/auth/password")
                .header(header::CONTENT_TYPE, kind)
                .extension(axum::extract::ConnectInfo(
                    PEER.parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE, "{kind}");
        assert!(!res.headers().contains_key(header::SET_COOKIE), "{kind}");
    }
    let n = one(
        &e.db,
        "SELECT count(*) AS n FROM audit WHERE action LIKE 'login%'",
    )
    .await;
    assert_eq!(n["n"], 0);
}
