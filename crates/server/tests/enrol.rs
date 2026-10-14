//! Setting TOTP up and taking it down: the `enrol` stage admins go through, removing
//! it (the password, never for admins), new recovery codes (a code), an account made
//! an admin, and a reset by an admin in reach or the CLI.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::login::{self, PEER, account, login, one, send, tenant};
use common::totp::{PW, code, enrol, secret_of};
use common::{Client, Env, sign_in, sql};
use serde_json::json;

async fn password_login(e: &Env, email: &str) -> Client {
    let r = login(&e.app, email, PW).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    login::client(&e.app, &r.session().unwrap()).await
}

#[tokio::test]
async fn an_admin_sets_totp_up_before_anything_else() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    account(&e.db, "root@x.test", "global_admin", None, PW).await;
    account(&e.db, "ta@acme.test", "tenant_admin", Some(t), PW).await;
    for email in ["root@x.test", "ta@acme.test"] {
        let c = password_login(&e, email).await;
        let (_, s) = c.get("/session").await;
        assert_eq!(
            (&s["stage"], &s["has_password"], &s["totp_enabled"]),
            (&json!("enrol"), &json!(true), &json!(false)),
            "{email}"
        );
        // The password alone neither makes the client known nor clears its count.
        let seen = one(
            &e.db,
            &format!(
                "SELECT (SELECT count(*) FROM login_known k JOIN app_user u ON u.id = k.user_id
                         WHERE u.email = '{email}') AS known,
                        (SELECT max(failed) FROM login_failure f JOIN app_user u
                         ON u.id = f.user_id WHERE u.email = '{email}') AS failed"
            ),
        )
        .await;
        assert_eq!(seen, json!({ "known": 0, "failed": 1 }), "{email}");
        for (method, uri) in [
            (Method::GET, "/tenants"),
            (Method::GET, "/users"),
            (Method::GET, "/devices"),
            (Method::POST, "/me/password"),
        ] {
            let (s, v) = c.call(method, uri, Some(json!({}))).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(v["error"], "totp_required", "{uri}");
        }
        // Not a login waiting for a code.
        let r = c.second(json!({ "code": "000000" })).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        // A new setup replaces a pending one; a wrong code confirms nothing.
        let (s, first) = c.post("/me/totp/setup", json!({})).await;
        assert_eq!(s, StatusCode::OK);
        let uri = first["otpauth_uri"].as_str().unwrap();
        let label = email.replace('@', "%40");
        assert!(
            uri.starts_with(&format!("otpauth://totp/wgate:{label}?secret=")),
            "{uri}"
        );
        assert!(uri.contains("&issuer=wgate"), "{uri}");
        assert!(first["qr_svg"].as_str().unwrap().contains("<svg"));
        let old = secret_of(uri);
        // The enrol stage needs no body (no password: it just had it).
        let (s, _) = c.call(Method::POST, "/me/totp/setup", None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(c.post_empty_json("/me/totp/setup").await, StatusCode::OK);
        let (s, v) = c
            .post(
                "/me/totp/confirm",
                json!({ "code": code(&old, e.clock.now()) }),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        let en = enrol(&c, &e.clock).await;
        assert_ne!(en.secret, old);
        assert_eq!(
            c.get("/session").await.0,
            StatusCode::UNAUTHORIZED,
            "the old token"
        );
        // Confirmed: a full session under a new token.
        let full = en.client;
        assert_ne!(full.token, c.token);
        assert_eq!(full.get("/tenants").await.0, StatusCode::OK);
        let (_, s) = full.get("/session").await;
        assert_eq!(
            (&s["stage"], &s["totp_enabled"]),
            (&json!("full"), &json!(true))
        );
        let (s, _) = full.post("/me/totp/setup", json!({ "password": PW })).await;
        assert_eq!(s, StatusCode::CONFLICT, "on already");
        let enrolled = one(
            &e.db,
            &format!(
                "SELECT a.detail->>'ip' AS ip, a.detail->>'method' AS method, s.method AS now
                 FROM audit a, session s
                 WHERE a.action = 'user.totp.enrol' AND a.target = 'app_user/' || s.user_id
                   AND s.user_id = {}",
                full.user_id
            ),
        )
        .await;
        assert_eq!(
            enrolled,
            json!({ "ip": "192.0.2.10", "method": "password", "now": "password_totp" })
        );
        // From now on its password logins ask for a code.
        let c = password_login(&e, email).await;
        assert_eq!(c.get("/session").await.1["stage"], "totp");
    }
    // An enrol session lasts 30 minutes, and logging out ends it.
    let id = account(&e.db, "ta2@acme.test", "tenant_admin", Some(t), PW).await;
    let c = password_login(&e, "ta2@acme.test").await;
    let ttl = one(
        &e.db,
        &format!(
            "SELECT round(extract(epoch FROM expires_at - created_at)) AS s FROM session
             WHERE user_id = {id}"
        ),
    )
    .await;
    assert_eq!(ttl["s"], 1800);
    let (s, v) = c
        .post("/me/totp/confirm", json!({ "code": "123456" }))
        .await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("the code is wrong"))
    );
    let cookie = c.cookie();
    let r = send(
        &e.app,
        "POST",
        "/auth/logout",
        None,
        PEER,
        &[("cookie", &cookie)],
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(c.get("/session").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn removing_totp_takes_the_password_and_new_codes_take_a_code() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let id = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    let c = password_login(&e, "u@acme.test").await;
    // A full session's setup takes the current password, counted when wrong.
    let (s, v) = c.post("/me/totp/setup", json!({})).await;
    assert_eq!(
        (s, v["message"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("the current password is required")
        )
    );
    let (s, v) = c
        .post(
            "/me/totp/setup",
            json!({ "password": "wrong horse battery" }),
        )
        .await;
    assert_eq!(
        (s, v["message"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("the password is wrong")
        )
    );
    let en = enrol(&c, &e.clock).await;
    let c = en.client;
    let failed = format!(
        "SELECT coalesce(max(failed), 0) AS n FROM login_failure
         WHERE user_id = {id} AND client = '127.0.0.1'"
    );
    // New recovery codes need a current code (counted when wrong); the old ones go.
    let (s, v) = c
        .post("/me/recovery-codes", json!({ "code": "000000" }))
        .await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("the code is wrong"))
    );
    // With the wrong setup password before it, from this client.
    assert_eq!(one(&e.db, &failed).await["n"], 2);
    let (s, v) = c
        .post(
            "/me/recovery-codes",
            json!({ "code": code(&en.secret, e.clock.now()) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let new: Vec<String> = serde_json::from_value(v["recovery_codes"].clone()).unwrap();
    assert_eq!(new.len(), 10);
    assert!(new.iter().all(|n| !en.recovery_codes.contains(n)));
    assert_eq!(one(&e.db, &failed).await["n"], 0);
    let codes = one(
        &e.db,
        &format!("SELECT count(*) AS n FROM recovery_code WHERE user_id = {id}"),
    )
    .await;
    assert_eq!(codes["n"], 10);

    // Removing it takes the password, counted like a login when wrong.
    let remove = |pw: &str| json!({ "password": pw });
    let (s, v) = c
        .call(
            Method::DELETE,
            "/me/totp",
            Some(remove("wrong horse battery")),
        )
        .await;
    assert_eq!(
        (s, v["message"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("the password is wrong")
        )
    );
    assert_eq!(one(&e.db, &failed).await["n"], 1);
    let (s, _) = c.call(Method::DELETE, "/me/totp", Some(remove(PW))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let off = one(
        &e.db,
        &format!(
            "SELECT totp_secret IS NULL AND totp_enabled_at IS NULL AS off,
                    (SELECT count(*) FROM recovery_code WHERE user_id = {id}) AS codes
             FROM app_user WHERE id = {id}"
        ),
    )
    .await;
    assert_eq!(off, json!({ "off": true, "codes": 0 }));
    let (s, v) = c
        .post("/me/recovery-codes", json!({ "code": "000000" }))
        .await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("TOTP is off"))
    );
    let c = password_login(&e, "u@acme.test").await;
    assert_eq!(c.get("/session").await.1["stage"], "full");

    // Admins keep theirs.
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let (s, v) = g.call(Method::DELETE, "/me/totp", Some(remove(PW))).await;
    assert_eq!(
        (s, v["message"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("admins need TOTP"))
    );
    // An account without a password has nothing for TOTP to guard.
    let (s, v) = g.post("/me/totp/setup", json!({ "password": PW })).await;
    assert_eq!(
        (s, v["message"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("this account has no password")
        )
    );
}

#[tokio::test]
async fn an_account_made_an_admin_sets_totp_up_too() {
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let id = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    // Its password session from before: an admin's without TOTP is in `enrol`.
    let c = password_login(&e, "u@acme.test").await;
    sql(
        &e.db,
        &format!("UPDATE app_user SET role = 'tenant_admin' WHERE id = {id}"),
    )
    .await;
    let (s, v) = c.get("/tenants").await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("totp_required"))
    );
    assert_eq!(c.get("/session").await.1["stage"], "enrol");
    let full = enrol(&c, &e.clock).await.client;
    assert_eq!(full.get("/tenants").await.0, StatusCode::OK);
    // Made one through the API: its sessions end.
    sql(
        &e.db,
        &format!("UPDATE app_user SET role = 'user' WHERE id = {id}"),
    )
    .await;
    let (s, v) = g
        .patch(&format!("/users/{id}"), json!({ "role": "tenant_admin" }))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["has_password"], &v["totp_enabled"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(full.get("/session").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_admin_in_reach_or_the_cli_resets_totp() {
    let e = common::env().await;
    let acme = tenant(&e.db, "acme").await;
    let beta = tenant(&e.db, "beta").await;
    let id = account(&e.db, "u@acme.test", "user", Some(acme), PW).await;
    let en = enrol(&password_login(&e, "u@acme.test").await, &e.clock).await;
    let root = account(&e.db, "root@x.test", "global_admin", None, PW).await;
    let ta = sign_in(&e, "ta@acme.test", "tenant_admin", Some(acme)).await;
    let ta2 = sign_in(&e, "ta2@acme.test", "tenant_admin", Some(acme)).await;
    let other = sign_in(&e, "ta@beta.test", "tenant_admin", Some(beta)).await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let reset = |c: &Client, id: i64| {
        let c = c.clone();
        async move {
            c.post(&format!("/users/{id}/totp-reset"), json!({}))
                .await
                .0
        }
    };
    assert_eq!(
        reset(&other, id).await,
        StatusCode::FORBIDDEN,
        "another tenant"
    );
    assert_eq!(
        reset(&ta, root).await,
        StatusCode::FORBIDDEN,
        "a global admin"
    );
    assert_eq!(
        reset(&ta, ta2.user_id).await,
        StatusCode::FORBIDDEN,
        "another admin of the tenant: a global admin's call"
    );
    assert_eq!(
        reset(&ta, ta.user_id).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "/me"
    );
    assert_eq!(
        reset(&g, g.user_id).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "/me"
    );
    assert_eq!(reset(&g, ta2.user_id).await, StatusCode::NO_CONTENT);
    assert_eq!(reset(&ta, 9999).await, StatusCode::NOT_FOUND);
    assert_eq!(reset(&ta, id).await, StatusCode::NO_CONTENT);
    assert_eq!(en.client.get("/session").await.0, StatusCode::UNAUTHORIZED);
    let state = format!(
        "SELECT totp_secret IS NULL AS off,
                (SELECT count(*) FROM recovery_code WHERE user_id = {id}) AS codes
         FROM app_user WHERE id = {id}"
    );
    assert_eq!(one(&e.db, &state).await, json!({ "off": true, "codes": 0 }));
    let audit = one(
        &e.db,
        &format!(
            "SELECT actor_user_id AS by, detail->>'via' AS via FROM audit
             WHERE action = 'user.totp.reset' AND target = 'app_user/{id}'"
        ),
    )
    .await;
    assert_eq!(audit, json!({ "by": ta.user_id, "via": "api" }));

    // The CLI, for anyone.
    let c = password_login(&e, "u@acme.test").await;
    enrol(&c, &e.clock).await;
    assert_eq!(
        wgate_server::totp_reset(&e.db, "U@acme.test")
            .await
            .unwrap(),
        id
    );
    assert_eq!(one(&e.db, &state).await, json!({ "off": true, "codes": 0 }));
    let err = wgate_server::totp_reset(&e.db, "nobody@x.test")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no account"), "{err}");
}
