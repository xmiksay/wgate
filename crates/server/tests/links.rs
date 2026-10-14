//! Invite and reset links: who may make them, single use, 24 hours, a new one voids
//! the old, and a reset ends the account's sessions and clears its lockouts.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::login::{self, PEER, Reply, account, login, login_from, one, send, tenant};
use common::{Client, Env, sign_in, sql};
use serde_json::json;

const PW: &str = "correct horse battery";
const NEW: &str = "a new and longer passphrase";

/// A link for `id` from `admin`: its token.
async fn link(admin: &Client, id: i64, purpose: &str) -> String {
    let (s, v) = admin
        .post(&format!("/users/{id}/{purpose}"), json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["expires_at"].as_str().unwrap().ends_with('Z'), "{v}");
    let url = v["url"].as_str().unwrap();
    url.strip_prefix("http://portal.test/account/")
        .unwrap_or_else(|| panic!("{url}"))
        .to_owned()
}

async fn follow(e: &Env, token: &str, password: Option<&str>) -> Reply {
    let uri = format!("/auth/account/{token}");
    match password {
        None => send(&e.app, "GET", &uri, None, PEER, &[]).await,
        Some(pw) => {
            let body = json!({ "password": pw });
            send(&e.app, "POST", &uri, Some(body), PEER, &[]).await
        }
    }
}

#[tokio::test]
async fn an_invite_sets_the_first_password_once() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let user = g
        .create(
            "/users",
            json!({ "tenant_id": t, "email": "u@acme.test", "role": "user" }),
        )
        .await;
    let id = user["id"].as_i64().unwrap();
    let token = link(&g, id, "invite").await;
    let r = follow(&e, &token, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body,
        json!({ "email": "u@acme.test", "purpose": "invite" })
    );
    for bad in ["nope", &token[1..]] {
        assert_eq!(follow(&e, bad, None).await.status, StatusCode::NOT_FOUND);
        assert_eq!(
            follow(&e, bad, Some(NEW)).await.status,
            StatusCode::NOT_FOUND
        );
    }
    let r = follow(&e, &token, Some("short")).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        follow(&e, &token, Some(NEW)).await.status,
        StatusCode::NO_CONTENT
    );
    // Used up.
    assert_eq!(follow(&e, &token, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        follow(&e, &token, Some(PW)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        login(&e.app, "u@acme.test", NEW).await.status,
        StatusCode::NO_CONTENT
    );
    // An invite stops working once the account has a password some other way.
    let other = g
        .create(
            "/users",
            json!({ "tenant_id": t, "email": "o@acme.test", "role": "user" }),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let invite = link(&g, other, "invite").await;
    sql(
        &e.db,
        &format!("UPDATE app_user SET password_hash = 'x' WHERE id = {other}"),
    )
    .await;
    assert_eq!(
        follow(&e, &invite, None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        follow(&e, &invite, Some(NEW)).await.status,
        StatusCode::NOT_FOUND
    );
    // Setting a password voids the account's links.
    let unused = format!(
        "SELECT count(*) AS n FROM account_token WHERE user_id = {other} AND used_at IS NULL"
    );
    assert_eq!(one(&e.db, &unused).await["n"], 1);
    wgate_server::set_password(&e.db, "o@acme.test", wgate_server::Password::new(PW.into()))
        .await
        .unwrap();
    assert_eq!(one(&e.db, &unused).await["n"], 0);
    // An account with a password gets a reset link instead.
    let (s, v) = g.post(&format!("/users/{id}/invite"), json!({})).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _) = g.post("/users/9999/invite", json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Audited, never the token.
    let audit = one(
        &e.db,
        "SELECT string_agg(action || ' ' || detail::text, '\n' ORDER BY id) AS t FROM audit",
    )
    .await;
    let audit = audit["t"].as_str().unwrap();
    assert!(audit.contains("user.invite_link"), "{audit}");
    assert!(audit.contains("\"via\": \"invite_link\""), "{audit}");
    assert!(!audit.contains(&token), "{audit}");
}

#[tokio::test]
async fn a_reset_link_ends_sessions_and_lockouts() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let id = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    let session = login::client(
        &e.app,
        &login(&e.app, "u@acme.test", PW).await.session().unwrap(),
    )
    .await;
    // A newer link voids the older one.
    let old = link(&g, id, "reset").await;
    let token = link(&g, id, "reset").await;
    assert_eq!(follow(&e, &old, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(follow(&e, &token, None).await.body["purpose"], "reset");
    // Locked out from one client, braked for strangers.
    sql(
        &e.db,
        &format!(
            "INSERT INTO login_failure (user_id, client, failed, locked_until)
             VALUES ({id}, '192.0.2.10', 9, now() + interval '1 hour');
             UPDATE app_user SET brake_since = now(), brake_failures = 100,
                                 brake_last_at = now() WHERE id = {id}"
        ),
    )
    .await;
    assert_eq!(
        follow(&e, &token, Some(NEW)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(session.get("/session").await.0, StatusCode::UNAUTHORIZED);
    let left = one(
        &e.db,
        &format!(
            "SELECT (SELECT count(*) FROM login_failure WHERE user_id = {id}) AS failed,
                    (SELECT count(*) FROM login_known WHERE user_id = {id}) AS known,
                    brake_failures AS brake
             FROM app_user WHERE id = {id}"
        ),
    )
    .await;
    assert_eq!(left, json!({ "failed": 0, "known": 0, "brake": 0 }));
    assert_eq!(
        login(&e.app, "u@acme.test", PW).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&e.app, "u@acme.test", NEW).await.status,
        StatusCode::NO_CONTENT
    );
    let ended = one(
        &e.db,
        "SELECT detail->'ended_sessions' AS n FROM audit WHERE action = 'user.password.set'
         ORDER BY id DESC LIMIT 1",
    )
    .await;
    assert_eq!(ended["n"], 1);

    // 24 hours, then gone.
    let token = link(&g, id, "reset").await;
    let row = one(
        &e.db,
        "SELECT round(extract(epoch FROM expires_at - created_at)) AS s FROM account_token
         WHERE used_at IS NULL",
    )
    .await;
    assert_eq!(row["s"], 86400);
    sql(
        &e.db,
        "UPDATE account_token SET expires_at = now() - interval '1 second'",
    )
    .await;
    assert_eq!(follow(&e, &token, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        follow(&e, &token, Some(PW)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        login(&e.app, "u@acme.test", NEW).await.status,
        StatusCode::NO_CONTENT
    );
    // Changing the password voids an unused link too.
    let token = link(&g, id, "reset").await;
    let r = login(&e.app, "u@acme.test", NEW).await;
    let me = login::client(&e.app, &r.session().unwrap()).await;
    let (s, _) = me
        .post("/me/password", json!({ "current": NEW, "new": PW }))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(follow(&e, &token, None).await.status, StatusCode::NOT_FOUND);

    // Tokens are not guessed faster than passwords: the client's 20 attempts a
    // minute (logins and links together) run out.
    let mut tries = 0;
    while follow(&e, "guess", None).await.status == StatusCode::NOT_FOUND {
        tries += 1;
        assert!(tries < 20, "no limit");
    }
    let r = follow(&e, "guess", None).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers.contains_key("retry-after"));
}

#[tokio::test]
async fn a_tenant_admin_links_only_their_tenants_accounts() {
    let e = common::env().await;
    let acme = tenant(&e.db, "acme").await;
    let beta = tenant(&e.db, "beta").await;
    let root = account(&e.db, "root@x.test", "global_admin", None, PW).await;
    let own = account(&e.db, "u@acme.test", "user", Some(acme), PW).await;
    let foreign = account(&e.db, "u@beta.test", "user", Some(beta), PW).await;
    let admin = account(&e.db, "ta2@acme.test", "tenant_admin", Some(acme), PW).await;
    let ta = sign_in(&e, "ta@acme.test", "tenant_admin", Some(acme)).await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    // A tenant admin: their tenant's plain users only; any admin is a global admin's;
    // nobody's own (that is /me).
    for (by, id, status) in [
        (&ta, root, StatusCode::FORBIDDEN),
        (&ta, foreign, StatusCode::FORBIDDEN),
        (&ta, admin, StatusCode::FORBIDDEN),
        (&ta, ta.user_id, StatusCode::UNPROCESSABLE_ENTITY),
        (&ta, own, StatusCode::OK),
        (&g, admin, StatusCode::OK),
        (&g, root, StatusCode::OK),
        (&g, g.user_id, StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        for purpose in ["reset", "invite"] {
            let (s, v) = by.post(&format!("/users/{id}/{purpose}"), json!({})).await;
            // An invite for an account with a password is a 409 once in reach.
            let want = match (purpose, status) {
                ("invite", StatusCode::OK) => StatusCode::CONFLICT,
                _ => status,
            };
            assert_eq!(s, want, "{purpose} {id}: {v}");
        }
    }
    // A plain user makes none.
    let u = login::client(
        &e.app,
        &login_from(&e.app, "u@acme.test", PW, PEER, &[])
            .await
            .session()
            .unwrap(),
    )
    .await;
    let (s, _) = u.post(&format!("/users/{own}/reset"), json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
