//! Logins through providers in the database, against two in-process providers: who
//! a tenant's provider and a global one may sign in, binding by verified email, a
//! disabled provider, the login options per email, and the discovery cache.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::idp;
use common::login::{self, PEER, one, send, tenant};
use common::oidc::{login, provider, start, who};
use common::{sign_in, sql};
use serde_json::json;

const SECRET: &str = "s3cret-of-the-client";

/// A fresh account without a password.
async fn account(e: &common::Env, email: &str, role: &str, tenant: Option<i64>) -> i64 {
    one(
        &e.db,
        &format!(
            "INSERT INTO app_user (tenant_id, email, role) VALUES ({}, '{email}', '{role}')
             RETURNING id",
            tenant.map_or("NULL".into(), |t| t.to_string())
        ),
    )
    .await["id"]
        .as_i64()
        .unwrap()
}

#[tokio::test]
async fn a_tenant_provider_signs_in_its_own_tenant_only() {
    let (ia, ib) = (idp::start("a", SECRET).await, idp::start("b", SECRET).await);
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let (ta, tb) = (tenant(&e.db, "acme").await, tenant(&e.db, "beta").await);
    let pa = provider(&g, &ia, Some(ta), "Acme SSO", false).await;
    let pb = provider(&g, &ib, Some(tb), "Beta SSO", false).await;
    let ua = account(&e, "u@acme.test", "user", Some(ta)).await;
    let ub = account(&e, "u@beta.test", "user", Some(tb)).await;
    let adm = account(&e, "admin@acme.test", "tenant_admin", Some(ta)).await;
    let root = account(&e, "root@x.test", "global_admin", None).await;

    // A plain user of the tenant binds by verified email at the first login, then by
    // subject (an email changed at the provider takes nothing over).
    let cookie = login(&e.app, &ia, pa, who("sa", "U@acme.test", true))
        .await
        .expect("bound by email");
    let c = login::client(&e.app, &cookie).await;
    assert_eq!(c.user_id, ua);
    let (_, s) = c.get("/session").await;
    assert_eq!(
        s["stage"], "full",
        "the provider does its own second factor"
    );
    let row = one(
        &e.db,
        "SELECT method, provider_id FROM session WHERE id = (SELECT max(id) FROM session)",
    )
    .await;
    assert_eq!(row, json!({ "method": "oidc", "provider_id": pa }));
    assert!(
        login(&e.app, &ia, pa, who("sa", "else@acme.test", true))
            .await
            .is_ok()
    );
    // Its email under another subject is someone else, and unverified matches nobody.
    for next in [
        who("sa2", "u@acme.test", true),
        who("sx", "u@acme.test", false),
    ] {
        assert_eq!(login(&e.app, &ia, pa, next).await, Err("forbidden".into()));
    }

    // Never another tenant's account, nor a global admin, nor (by email) an admin of
    // its own tenant: those are a global admin's to reach.
    for email in ["u@beta.test", "root@x.test", "admin@acme.test"] {
        let r = login(&e.app, &ia, pa, who(&format!("s-{email}"), email, true)).await;
        assert_eq!(r, Err("forbidden".into()), "{email}");
    }
    // Not even with an identity row put there by hand.
    sql(
        &e.db,
        &format!(
            "INSERT INTO identity (user_id, provider_id, subject) VALUES
                ({ub}, {pa}, 'planted-b'), ({root}, {pa}, 'planted-root'),
                ({adm}, {pa}, 'linked-admin')"
        ),
    )
    .await;
    for subject in ["planted-b", "planted-root"] {
        let r = login(&e.app, &ia, pa, who(subject, "", false)).await;
        assert_eq!(r, Err("forbidden".into()), "{subject}");
    }
    // A linked tenant admin of its own tenant is served.
    let cookie = login(&e.app, &ia, pa, who("linked-admin", "", false))
        .await
        .expect("linked admin");
    assert_eq!(login::client(&e.app, &cookie).await.user_id, adm);
    // Its own provider serves the other tenant.
    assert!(
        login(&e.app, &ib, pb, who("sb", "u@beta.test", true))
            .await
            .is_ok()
    );

    // Disabled accounts and accounts of disabled tenants are refused.
    sql(
        &e.db,
        &format!("UPDATE app_user SET disabled_at = now() WHERE id = {ua}"),
    )
    .await;
    assert_eq!(
        login(&e.app, &ia, pa, who("sa", "", false)).await,
        Err("forbidden".into())
    );
    sql(
        &e.db,
        &format!("UPDATE tenant SET disabled_at = now() WHERE id = {tb}"),
    )
    .await;
    assert_eq!(
        login(&e.app, &ib, pb, who("sb", "", false)).await,
        Err("forbidden".into())
    );

    let audit = one(
        &e.db,
        "SELECT jsonb_agg(detail->>'reason' ORDER BY id) AS r FROM audit
         WHERE action = 'login.oidc.failed'",
    )
    .await;
    for reason in ["unknown_subject", "not_served", "disabled"] {
        assert!(
            audit["r"].as_array().unwrap().iter().any(|r| r == reason),
            "{reason}: {audit}"
        );
    }
    let ok = one(
        &e.db,
        &format!(
            "SELECT detail FROM audit WHERE action = 'login.oidc.ok' AND actor_user_id = {ua}
             ORDER BY id LIMIT 1"
        ),
    )
    .await;
    assert_eq!(ok["detail"]["provider_id"], pa);
    assert_eq!(ok["detail"]["bound_by"], "email");
    assert_eq!(ok["detail"]["ip"], "192.0.2.10");
}

#[tokio::test]
async fn a_global_provider_binds_by_email_only_with_link_by_email() {
    let ig = idp::start("g", SECRET).await;
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let pg = provider(&g, &ig, None, "Google", false).await;
    let u = account(&e, "u@acme.test", "user", Some(t)).await;
    let adm = account(&e, "admin@acme.test", "tenant_admin", Some(t)).await;
    let root = account(&e, "root@x.test", "global_admin", None).await;

    assert_eq!(
        login(&e.app, &ig, pg, who("su", "u@acme.test", true)).await,
        Err("forbidden".into()),
        "no link_by_email: no binding"
    );
    let (s, v) = g
        .patch(
            &format!("/providers/{pg}"),
            json!({ "link_by_email": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for (subject, email, id) in [("su", "u@acme.test", u), ("sa", "admin@acme.test", adm)] {
        let cookie = login(&e.app, &ig, pg, who(subject, email, true))
            .await
            .expect(email);
        assert_eq!(login::client(&e.app, &cookie).await.user_id, id);
    }
    // A global admin never binds by email, however flagged.
    assert_eq!(
        login(&e.app, &ig, pg, who("sr", "root@x.test", true)).await,
        Err("forbidden".into())
    );
    // But may link a global provider (here by hand) and log in with it.
    sql(
        &e.db,
        &format!(
            "INSERT INTO identity (user_id, provider_id, subject) VALUES ({root}, {pg}, 'sr')"
        ),
    )
    .await;
    let cookie = login(&e.app, &ig, pg, who("sr", "", false)).await.unwrap();
    assert_eq!(login::client(&e.app, &cookie).await.user_id, root);
}

#[tokio::test]
async fn the_login_page_offers_providers_per_email_and_never_a_disabled_one() {
    let (ia, ig) = (idp::start("a", SECRET).await, idp::start("g", SECRET).await);
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let (ta, tb) = (tenant(&e.db, "acme").await, tenant(&e.db, "beta").await);
    let pg = provider(&g, &ig, None, "Google", true).await;
    let pa = provider(&g, &ia, Some(ta), "Acme SSO", false).await;
    account(&e, "u@acme.test", "user", Some(ta)).await;
    account(&e, "u@beta.test", "user", Some(tb)).await;
    let options = async |email: &str| {
        let body = Some(json!({ "email": email }));
        let r = send(&e.app, "POST", "/auth/options", body, PEER, &[]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body["password"], true);
        r.body["providers"].clone()
    };
    let google = json!({ "id": pg.to_string(), "name": "Google" });
    let acme = json!({ "id": pa.to_string(), "name": "Acme SSO" });
    assert_eq!(options(" U@ACME.test ").await, json!([google, acme]));
    for email in ["u@beta.test", "nobody@x.test", "g@x.test", "not an email"] {
        assert_eq!(options(email).await, json!([google]), "{email}");
    }

    // A round trip started before the provider is disabled ends with it; sessions
    // made through it end, and it is no longer offered or started.
    let session = login(&e.app, &ia, pa, who("sa", "u@acme.test", true))
        .await
        .unwrap();
    let pending = start(&e.app, &pa.to_string()).await.unwrap();
    let (s, v) = g
        .patch(&format!("/providers/{pa}"), json!({ "disabled": true }))
        .await;
    assert_eq!((s, &v["disabled"]), (StatusCode::OK, &json!(true)), "{v}");
    let r = pending
        .finish(&e.app, &ia, who("sa", "", false), &[&pending.cookie])
        .await;
    assert_eq!(common::oidc::location(&r), "/login?error=unavailable");
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
    assert_eq!(options("u@acme.test").await, json!([google]));
    for id in [pa.to_string(), "999999".into(), "admin".into()] {
        assert_eq!(
            start(&e.app, &id).await.err().as_deref(),
            Some("unavailable"),
            "{id}"
        );
    }
}

#[tokio::test]
async fn the_discovery_cache_follows_the_provider_row() {
    let (i1, i2) = (
        idp::start("one", SECRET).await,
        idp::start("two", "other").await,
    );
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let p = provider(&g, &i1, Some(t), "SSO", false).await;
    let u = account(&e, "u@acme.test", "user", Some(t)).await;
    for _ in 0..2 {
        login(&e.app, &i1, p, who("s1", "u@acme.test", true))
            .await
            .unwrap();
    }
    assert_eq!(i1.discovered(), 1, "cached between logins");

    // Another issuer (with its own client): the next round trip goes there, and the
    // old issuer's subjects are gone.
    let (s, v) = g
        .patch(
            &format!("/providers/{p}"),
            json!({ "issuer": i2.issuer, "client_id": "two" }),
        )
        .await;
    assert_eq!((s, &v["identities"]), (StatusCode::OK, &json!(0)), "{v}");
    // The stored secret is still the first one's: the second refuses it.
    assert_eq!(
        login(&e.app, &i2, p, who("s2", "u@acme.test", true)).await,
        Err("forbidden".into())
    );
    let (s, _) = g
        .patch(
            &format!("/providers/{p}"),
            json!({ "client_secret": "other" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let cookie = login(&e.app, &i2, p, who("s2", "u@acme.test", true))
        .await
        .expect("the new secret");
    assert_eq!(login::client(&e.app, &cookie).await.user_id, u);
    assert_eq!(i2.discovered(), 2, "rediscovered after each change");
    assert_eq!(i1.discovered(), 1);
}
