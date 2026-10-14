//! Admin roles and what reaches them: only a global admin gives or takes one (so a
//! tenant admin cannot carry a link or a session across a role change), and an
//! admin's password sessions from before TOTP neither skip it nor outlive it.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::login::{self, PEER, account, login, one, send, tenant};
use common::totp::{PW, enrol};
use common::{Client, Env, sign_in, sql};
use serde_json::json;

async fn password_login(e: &Env, email: &str) -> Client {
    let r = login(&e.app, email, PW).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    login::client(&e.app, &r.session().unwrap()).await
}

/// A reset link for `id` from `admin`: its token.
async fn reset_link(admin: &Client, id: i64) -> String {
    let (s, v) = admin.post(&format!("/users/{id}/reset"), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned()
}

async fn link_status(e: &Env, token: &str) -> StatusCode {
    let uri = format!("/auth/account/{token}");
    send(&e.app, "GET", &uri, None, PEER, &[]).await.status
}

#[tokio::test]
async fn only_a_global_admin_gives_or_takes_an_admin_role() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let ta = sign_in(&e, "ta@acme.test", "tenant_admin", Some(t)).await;
    let u = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    let a = account(&e.db, "a@acme.test", "tenant_admin", Some(t), PW).await;
    // A tenant admin makes plain users only.
    let new =
        |role: &str| json!({ "tenant_id": t, "email": format!("{role}@acme.test"), "role": role });
    assert_eq!(
        ta.post("/users", new("tenant_admin")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ta.post("/users", new("user")).await.0, StatusCode::CREATED);
    // A link it made for a user cannot outlive the user becoming an admin...
    let token = reset_link(&ta, u).await;
    let promote = json!({ "role": "tenant_admin" });
    let (s, _) = ta.patch(&format!("/users/{u}"), promote.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a global admin's call");
    assert_eq!(link_status(&e, &token).await, StatusCode::OK);
    let session = password_login(&e, "u@acme.test").await;
    let (s, v) = g.patch(&format!("/users/{u}"), promote).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(link_status(&e, &token).await, StatusCode::NOT_FOUND);
    assert_eq!(session.get("/session").await.0, StatusCode::UNAUTHORIZED);
    // ...nor can a tenant admin turn an admin into a user it reaches, or touch one.
    for (s, what) in [
        (
            ta.patch(&format!("/users/{a}"), json!({ "role": "user" }))
                .await
                .0,
            "demote",
        ),
        (
            ta.patch(&format!("/users/{a}"), json!({ "disabled": true }))
                .await
                .0,
            "disable",
        ),
        (ta.delete(&format!("/users/{a}")).await.0, "delete"),
        (
            ta.post(&format!("/users/{a}/reset"), json!({})).await.0,
            "link",
        ),
    ] {
        assert_eq!(s, StatusCode::FORBIDDEN, "{what}");
    }
    // A global admin's demotion ends the sessions and links just the same.
    let token = reset_link(&g, a).await;
    let (s, _) = g
        .patch(&format!("/users/{a}"), json!({ "role": "user" }))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(link_status(&e, &token).await, StatusCode::NOT_FOUND);
    let ended = one(
        &e.db,
        &format!(
            "SELECT detail->'ended_sessions' AS n FROM audit
             WHERE action = 'user.update' AND target = 'app_user/{u}'"
        ),
    )
    .await;
    assert_eq!(ended["n"], 1);
}

#[tokio::test]
async fn an_admins_old_password_sessions_need_totp_and_end_with_it() {
    let e = common::env().await;
    let id = account(&e.db, "root@x.test", "global_admin", None, PW).await;
    // Two password sessions from before TOTP was mandatory: full rows, an hour left.
    let first = password_login(&e, "root@x.test").await;
    let second = password_login(&e, "root@x.test").await;
    sql(
        &e.db,
        &format!(
            "UPDATE session SET stage = 'full', expires_at = now() + interval '1 hour'
             WHERE user_id = {id}"
        ),
    )
    .await;
    for c in [&first, &second] {
        assert_eq!(c.get("/session").await.1["stage"], "enrol");
        let (s, v) = c.get("/tenants").await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("totp_required"))
        );
    }
    // Not right after a password login: setting TOTP up takes the password again.
    let (s, v) = first.post("/me/totp/setup", json!({})).await;
    assert_eq!(
        (s, v["message"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("the current password is required")
        )
    );
    let full = enrol(&first, &e.clock).await.client;
    assert_eq!(full.get("/tenants").await.0, StatusCode::OK);
    // It keeps its old cap; the other password-only session is over.
    let left = one(
        &e.db,
        &format!(
            "SELECT round(extract(epoch FROM expires_at - now())) <= 3600 AS capped, method
             FROM session WHERE user_id = {id}"
        ),
    )
    .await;
    assert_eq!(left, json!({ "capped": true, "method": "password_totp" }));
    assert_eq!(second.get("/session").await.0, StatusCode::UNAUTHORIZED);
    // A password-only full session of an admin with TOTP on is over at once.
    let third = password_login(&e, "root@x.test").await;
    sql(
        &e.db,
        &format!(
            "UPDATE session SET stage = 'full', method = 'password'
             WHERE user_id = {id} AND stage = 'totp'"
        ),
    )
    .await;
    assert_eq!(third.get("/session").await.0, StatusCode::UNAUTHORIZED);
    let rows = one(
        &e.db,
        &format!("SELECT count(*) AS n FROM session WHERE user_id = {id}"),
    )
    .await;
    assert_eq!(rows["n"], 1);
}
