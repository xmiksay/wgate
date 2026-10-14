//! The account side of local logins: changing a password, session stages, one account
//! per email, the login options, and a portal without `[admin_oidc]`.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode, header};
use common::login::{self, PEER, account, login, send};
use common::{sign_in, sql};
use serde_json::json;

const PW: &str = "correct horse battery";
const NEW: &str = "a new and longer passphrase";

#[tokio::test]
async fn changing_the_password_ends_the_other_sessions() {
    let e = common::env().await;
    let g = sign_in(&e, "g@example.org", "global_admin", None).await;
    let t = g
        .create("/tenants", json!({ "slug": "acme", "name": "A" }))
        .await["id"]
        .as_i64()
        .unwrap();
    let id = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    let here = login::client(
        &e.app,
        &login(&e.app, "u@acme.test", PW).await.session().unwrap(),
    )
    .await;
    let there = login::client(
        &e.app,
        &login(&e.app, "u@acme.test", PW).await.session().unwrap(),
    )
    .await;
    let change = |current: &str, new: &str| json!({ "current": current, "new": new });

    // Too short, a wrong current password (counted), no CSRF token: nothing changes.
    let (s, v) = here.post("/me/password", change(PW, "short")).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("invalid"))
    );
    let (s, v) = here
        .post("/me/password", change("wrong horse battery", NEW))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["message"], "the current password is wrong");
    let (s, _) = here
        .call_with(Method::POST, "/me/password", Some(change(PW, NEW)), false)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(there.get("/session").await.0, StatusCode::OK);

    let (s, v) = here.post("/me/password", change(PW, NEW)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    assert_eq!(here.get("/session").await.0, StatusCode::OK);
    assert_eq!(there.get("/session").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        login(&e.app, "u@acme.test", PW).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&e.app, "u@acme.test", NEW).await.status,
        StatusCode::NO_CONTENT
    );
    let (_, audit) = g.get("/audit").await;
    let audit = audit.to_string();
    assert!(audit.contains("user.password.change"), "{audit}");
    assert!(audit.contains("user.password.failed"), "{audit}");
    for secret in [PW, NEW, "wrong horse battery"] {
        assert!(!audit.contains(secret), "{secret} in the audit");
    }
    // A wrong current password counts like a failed login from this client.
    sql(
        &e.db,
        &format!(
            "INSERT INTO login_failure (user_id, client, failed) VALUES ({id}, '127.0.0.1', 4)"
        ),
    )
    .await;
    let (s, _) = here
        .post("/me/password", change("wrong horse battery", PW))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = here.post("/me/password", change(NEW, PW)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "locked");
    // The refused attempt is audited like the wrong one before it.
    let (_, audit) = g.get("/audit").await;
    let reasons: Vec<_> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["action"] == "user.password.failed")
        .map(|a| a["detail"]["reason"].clone())
        .collect();
    assert_eq!(reasons[..2], [json!("locked"), json!("wrong_password")]);

    // An account without a password (an OIDC one) has none to change.
    let (s, v) = g.post("/me/password", change(PW, NEW)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["message"], "this account has no password");
}

#[tokio::test]
async fn only_a_full_session_is_signed_in() {
    let e = common::env().await;
    let g = sign_in(&e, "g@example.org", "global_admin", None).await;
    let routes = [
        (Method::GET, "/tenants"),
        (Method::GET, "/users"),
        (Method::GET, "/audit"),
        (Method::GET, "/openapi.json"),
        (Method::POST, "/me/password"),
        (Method::POST, "/me/recovery-codes"),
        (Method::DELETE, "/me/totp"),
        (Method::POST, "/peers"),
        (Method::POST, "/users/1/invite"),
    ];
    for (stage, status, error) in [
        ("totp", StatusCode::UNAUTHORIZED, "unauthorized"),
        ("enrol", StatusCode::FORBIDDEN, "totp_required"),
    ] {
        sql(&e.db, &format!("UPDATE session SET stage = '{stage}'")).await;
        // The session itself says how far the login got, in any stage.
        let (s, v) = g.get("/session").await;
        assert_eq!((s, v["stage"].as_str()), (StatusCode::OK, Some(stage)));
        for (method, uri) in &routes {
            let (s, v) = g.call(method.clone(), uri, Some(json!({}))).await;
            assert_eq!(
                (s, v["error"].as_str()),
                (status, Some(error)),
                "{stage} {uri}"
            );
        }
    }
    // The half-done login is kept for its next step.
    sql(&e.db, "UPDATE session SET stage = 'full'").await;
    assert_eq!(g.get("/tenants").await.0, StatusCode::OK);
}

#[tokio::test]
async fn the_server_needs_a_secret_key() {
    let e = common::env().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = common::config(&e.url, "http://127.0.0.1:9/");
    config.secret_key = None;
    let err = wgate_server::serve_on(listener, config).await.unwrap_err();
    assert!(err.to_string().contains("wgate keygen"), "{err:#}");
    let key = wgate_server::keygen().unwrap();
    assert_ne!(key, wgate_server::keygen().unwrap());
    assert!(wgate_server::SecretKey::parse(&key).is_ok());
}

#[tokio::test]
async fn an_email_is_one_account_across_wgate() {
    let e = common::env().await;
    let g = sign_in(&e, "g@example.org", "global_admin", None).await;
    let mut tenants = vec![];
    for slug in ["acme", "beta"] {
        let t = g
            .create("/tenants", json!({ "slug": slug, "name": slug }))
            .await;
        tenants.push(t["id"].as_i64().unwrap());
    }
    g.create(
        "/users",
        json!({ "tenant_id": tenants[0], "email": "u@x.test", "role": "user" }),
    )
    .await;
    for (tenant, role) in [
        (Some(tenants[1]), "user"),
        (Some(tenants[0]), "tenant_admin"),
        (None, "global_admin"),
    ] {
        let (s, v) = g
            .post(
                "/users",
                json!({ "tenant_id": tenant, "email": "U@X.test", "role": role }),
            )
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["message"], "an account with this email already exists");
    }
    // `admin grant` enables a disabled global admin again, the same account...
    let admin = wgate_server::grant_admin(&e.db, "root@x.test")
        .await
        .unwrap();
    sql(
        &e.db,
        &format!("UPDATE app_user SET disabled_at = now() WHERE id = {admin}"),
    )
    .await;
    assert_eq!(
        wgate_server::grant_admin(&e.db, "ROOT@x.test")
            .await
            .unwrap(),
        admin
    );
    let (_, users) = g.get("/users").await;
    let root = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == admin)
        .unwrap();
    assert_eq!(root["disabled"], false);
    // ...but does not turn a tenant's account into a global admin.
    let err = wgate_server::grant_admin(&e.db, "u@x.test")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("account of a tenant"), "{err}");
    // Nor does the CLI set a password for nobody.
    let err = wgate_server::set_password(
        &e.db,
        "nobody@x.test",
        wgate_server::Password::new(PW.into()),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no account"), "{err}");
    let err = wgate_server::set_password(
        &e.db,
        "u@x.test",
        wgate_server::Password::new("short".into()),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("12 to 256"), "{err}");
}

#[tokio::test]
async fn the_login_page_offers_a_password_and_the_admin_provider() {
    let e = common::env().await;
    for email in ["nobody@x.test", "g@example.org"] {
        let r = send(
            &e.app,
            "POST",
            "/auth/options",
            Some(json!({ "email": email })),
            PEER,
            &[],
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(
            r.body,
            json!({ "password": true, "providers": [{ "id": "admin", "name": "127.0.0.1" }] })
        );
    }
    let r = send(&e.app, "GET", "/auth/oidc/other", None, PEER, &[]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.headers[header::LOCATION], "/login?error=unavailable");
}

#[tokio::test]
async fn without_admin_oidc_the_password_is_the_way_in() {
    let e = common::env_with("http://127.0.0.1:9/", |c| c.admin_oidc = None).await;
    let r = send(
        &e.app,
        "POST",
        "/auth/options",
        Some(json!({ "email": "a@b.test" })),
        PEER,
        &[],
    )
    .await;
    assert_eq!(r.body, json!({ "password": true, "providers": [] }));
    for uri in [
        "/auth/login",
        "/auth/oidc/admin",
        "/auth/callback?code=c&state=s",
    ] {
        let r = send(&e.app, "GET", uri, None, PEER, &[]).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{uri}");
        let to = r.headers[header::LOCATION].to_str().unwrap();
        assert!(to.starts_with("/login?error="), "{uri}: {to}");
    }
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
    let r = login(&e.app, "root@example.org", PW).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    // The first admin sets TOTP up at the first login.
    let c = login::client(&e.app, &r.session().unwrap()).await;
    assert_eq!(c.get("/tenants").await.0, StatusCode::FORBIDDEN);
    let c = common::totp::enrol(&c, &e.clock).await.client;
    assert_eq!(c.get("/tenants").await.0, StatusCode::OK);
}

/// The real listener: it hands the handlers the peer address, and needs no provider.
#[tokio::test]
async fn the_server_serves_without_admin_oidc() {
    let e = common::env().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut config = common::config(&e.url, "http://127.0.0.1:9/");
    config.admin_oidc = None;
    let server = tokio::spawn(wgate_server::serve_on(listener, config));
    let http = openidconnect::reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/auth/password");
    let mut status = None;
    for _ in 0..100 {
        let res = http
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json!({ "email": "a@b.test", "password": PW }).to_string())
            .send()
            .await;
        if let Ok(res) = res {
            status = Some(res.status().as_u16());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(status, Some(401), "a refusal, not a missing peer address");
    server.abort();
    let g = sign_in(&e, "g@example.org", "global_admin", None).await;
    let (_, audit) = g.get("/audit").await;
    assert_eq!(audit[0]["detail"]["ip"], "127.0.0.1", "{audit}");
}
