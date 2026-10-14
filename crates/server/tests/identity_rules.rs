//! The rules around identities beyond linking itself: a promotion drops what a
//! tenant's admins bound, a pre-link names only usable providers, a provider's issuer
//! change or disable ends its sessions and never strands a fellow admin, and what
//! `/me` may link.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::idp;
use common::login::{self, PEER, account, one, send, tenant};
use common::oidc::{self as flow, provider, who};
use common::{sign_in, sql};
use serde_json::json;

const SECRET: &str = "client-secret";
const PW: &str = "correct horse battery";

/// A fresh account without a password.
async fn passwordless(e: &common::Env, email: &str, role: &str, t: i64) -> i64 {
    one(
        &e.db,
        &format!(
            "INSERT INTO app_user (tenant_id, email, role) VALUES ({t}, '{email}', '{role}')
             RETURNING id"
        ),
    )
    .await["id"]
        .as_i64()
        .unwrap()
}

#[tokio::test]
async fn a_promotion_drops_the_identities_at_tenant_providers() {
    let (ia, ig) = (idp::start("a", SECRET).await, idp::start("g", SECRET).await);
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let a = sign_in(&e, "admin@acme.test", "tenant_admin", Some(t)).await;
    let pa = provider(&g, &ia, Some(t), "Acme SSO", false).await;
    let pg = provider(&g, &ig, None, "Google", false).await;
    let u = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    // The tenant admin plants their own subject on a plain user...
    let link = |p: i64, s: &str| json!({ "provider_id": p, "subject": s });
    a.create(&format!("/users/{u}/identities"), link(pa, "planted"))
        .await;
    g.create(&format!("/users/{u}/identities"), link(pg, "google"))
        .await;
    // ...who a global admin then makes an admin: the planted identity goes with it.
    let (s, v) = g
        .patch(&format!("/users/{u}"), json!({ "role": "tenant_admin" }))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        flow::login(&e.app, &ia, pa, who("planted", "", false)).await,
        Err("forbidden".into())
    );
    let cookie = flow::login(&e.app, &ig, pg, who("google", "", false))
        .await
        .expect("the global provider's identity stays");
    assert_eq!(login::client(&e.app, &cookie).await.user_id, u);
    let audit = one(
        &e.db,
        "SELECT detail FROM audit WHERE action = 'user.update' ORDER BY id DESC LIMIT 1",
    )
    .await;
    assert_eq!(audit["detail"]["identities_removed"], 1);
    assert_eq!(v["stranded"], false, "u keeps a password and Google");
    // Without a password or another identity, the promotion says it left none.
    let n = passwordless(&e, "n@acme.test", "user", t).await;
    a.create(&format!("/users/{n}/identities"), link(pa, "n-planted"))
        .await;
    let (s, v) = g
        .patch(&format!("/users/{n}"), json!({ "role": "tenant_admin" }))
        .await;
    assert_eq!((s, &v["stranded"]), (StatusCode::OK, &json!(true)), "{v}");
    // A change that removes nothing says nothing.
    let (_, v) = g
        .patch(&format!("/users/{n}"), json!({ "disabled": false }))
        .await;
    assert!(v.get("stranded").is_none(), "{v}");
}

#[tokio::test]
async fn a_pre_link_names_only_providers_the_admin_may_use() {
    let i = idp::start("a", SECRET).await;
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let (ta, tb) = (tenant(&e.db, "acme").await, tenant(&e.db, "beta").await);
    let a = sign_in(&e, "admin@acme.test", "tenant_admin", Some(ta)).await;
    let own = provider(&g, &i, Some(ta), "Acme SSO", false).await;
    let theirs = provider(&g, &i, Some(tb), "Beta SSO", false).await;
    let off = provider(&g, &i, None, "Off", false).await;
    g.patch(&format!("/providers/{off}"), json!({ "disabled": true }))
        .await;
    let u = account(&e.db, "u@acme.test", "user", Some(ta), PW).await;
    let link = |p: i64| json!({ "provider_id": p, "subject": "s" });
    let mut answers = vec![];
    for p in [theirs, off, 999_999] {
        let (s, v) = a.post(&format!("/users/{u}/identities"), link(p)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{p}: {v}");
        answers.push(v);
    }
    assert!(answers.iter().all(|v| *v == answers[0]), "{answers:?}");
    // Disabled is refused for a global admin too.
    let (s, _) = g.post(&format!("/users/{u}/identities"), link(off)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    a.create(&format!("/users/{u}/identities"), link(own)).await;
}

#[tokio::test]
async fn a_provider_change_ends_its_sessions_and_strands_no_fellow_admin() {
    let (i1, i2) = (idp::start("a", SECRET).await, idp::start("b", SECRET).await);
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let a = sign_in(&e, "admin@acme.test", "tenant_admin", Some(t)).await;
    let p = provider(&a, &i1, Some(t), "Acme SSO", false).await;
    let u = passwordless(&e, "u@acme.test", "user", t).await;
    let peer = passwordless(&e, "peer@acme.test", "tenant_admin", t).await;
    sql(
        &e.db,
        &format!(
            "INSERT INTO identity (user_id, provider_id, subject) VALUES
                 ({u}, {p}, 'su'), ({peer}, {p}, 'sp')"
        ),
    )
    .await;
    let session = flow::login(&e.app, &i1, p, who("su", "", false))
        .await
        .unwrap();

    // The peer admin's only way in: the tenant admin may neither disable, repoint
    // nor delete it.
    let uri = format!("/providers/{p}");
    for change in [json!({ "disabled": true }), json!({ "issuer": i2.issuer })] {
        let (s, v) = a.patch(&uri, change.clone()).await;
        assert_eq!(s, StatusCode::CONFLICT, "{change}: {v}");
    }
    assert_eq!(a.delete(&uri).await.0, StatusCode::CONFLICT);
    // Once the peer has a password, a plain user may be stranded: counted.
    common::sql(
        &e.db,
        &format!("UPDATE app_user SET password_hash = 'x' WHERE id = {peer}"),
    )
    .await;
    let (s, v) = a.patch(&uri, json!({ "issuer": i2.issuer })).await;
    assert_eq!((s, &v["stranded"]), (StatusCode::OK, &json!(1)), "{v}");
    // A new issuer: the old one's sessions end with its subjects.
    let r = send(
        &e.app,
        "GET",
        "/api/v1/session",
        None,
        PEER,
        &[("cookie", &session)],
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let audit = one(
        &e.db,
        "SELECT detail FROM audit WHERE action = 'provider.update' ORDER BY id DESC LIMIT 1",
    )
    .await;
    assert_eq!(audit["detail"]["ended_sessions"], 1);
    assert_eq!(audit["detail"]["stranded"], 1);
    // A global admin may strand an admin (and is told).
    common::sql(
        &e.db,
        &format!(
            "UPDATE app_user SET password_hash = NULL WHERE id = {peer};
             INSERT INTO identity (user_id, provider_id, subject) VALUES ({peer}, {p}, 'sp')"
        ),
    )
    .await;
    let (s, v) = g.patch(&uri, json!({ "disabled": true })).await;
    assert_eq!((s, &v["stranded"]), (StatusCode::OK, &json!(1)), "{v}");
}

#[tokio::test]
async fn me_lists_the_providers_it_may_link() {
    let (ia, ig) = (idp::start("a", SECRET).await, idp::start("g", SECRET).await);
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let (ta, tb) = (tenant(&e.db, "acme").await, tenant(&e.db, "beta").await);
    let pg = provider(&g, &ig, None, "Google", false).await;
    let pa = provider(&g, &ia, Some(ta), "Acme SSO", false).await;
    provider(&g, &ia, Some(tb), "Beta SSO", false).await;
    let off = provider(&g, &ig, None, "Off", false).await;
    g.patch(&format!("/providers/{off}"), json!({ "disabled": true }))
        .await;
    let u = sign_in(&e, "u@acme.test", "user", Some(ta)).await;
    sql(
        &e.db,
        &format!(
            "INSERT INTO identity (user_id, provider_id, subject) VALUES ({}, {pg}, 's')",
            u.user_id
        ),
    )
    .await;
    let (s, v) = u.get("/me/providers").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v,
        json!([
            { "id": pg, "name": "Google", "global": true, "linked": true },
            { "id": pa, "name": "Acme SSO", "global": false, "linked": false },
        ])
    );
    let (_, v) = g.get("/me/providers").await;
    assert_eq!(
        v,
        json!([{ "id": pg, "name": "Google", "global": true, "linked": false }])
    );
}
