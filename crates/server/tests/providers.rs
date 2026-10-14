//! Managing providers: a global admin all of them, a tenant admin their own tenant's;
//! `link_by_email` is a global admin's and a global provider's; the client secret is
//! write-only.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::login::{one, tenant};
use common::{sign_in, sql};
use sea_orm::ConnectionTrait;
use serde_json::{Value, json};

const SECRET: &str = "never-shown-client-secret";

fn body(tenant: Option<i64>, name: &str) -> Value {
    json!({ "tenant_id": tenant, "name": name, "issuer": "https://idp.example.org",
            "client_id": "wgate", "client_secret": SECRET })
}

fn no_secret(v: &Value) {
    let text = v.to_string();
    assert!(
        !text.contains(SECRET) && !text.contains("client_secret"),
        "{text}"
    );
}

#[tokio::test]
async fn a_global_admin_manages_providers_and_never_sees_a_secret() {
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let p = g.create("/providers", body(None, " Google ")).await;
    no_secret(&p);
    assert_eq!(
        p,
        json!({ "id": p["id"], "tenant_id": null, "name": "Google", "disabled": false,
                "link_by_email": false, "managed": true, "issuer": "https://idp.example.org",
                "client_id": "wgate", "identities": 0 })
    );
    let id = p["id"].as_i64().unwrap();
    // The secret is sealed to its row.
    let stored = one(
        &e.db,
        &format!("SELECT encode(client_secret, 'escape') AS s FROM oidc_provider WHERE id = {id}"),
    )
    .await;
    assert!(!stored["s"].as_str().unwrap().contains(SECRET));

    let tp = g.create("/providers", body(Some(t), "Google")).await;
    assert_eq!(tp["tenant_id"], t, "the same name on another login page");
    let (s, v) = g.post("/providers", body(None, "google")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    for bad in [
        json!({ "issuer": "ftp://idp.example.org" }),
        json!({ "issuer": "not a url" }),
        json!({ "name": "  " }),
        json!({ "client_id": "" }),
        json!({ "client_secret": "" }),
    ] {
        let mut b = body(None, "Other");
        for (k, v) in bad.as_object().unwrap() {
            b[k] = v.clone();
        }
        let (s, v) = g.post("/providers", b).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {v}");
    }
    // `link_by_email` is for global providers.
    let mut flagged = body(Some(t), "Flagged");
    flagged["link_by_email"] = json!(true);
    assert_eq!(
        g.post("/providers", flagged).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let tid = tp["id"].as_i64().unwrap();
    let (s, _) = g
        .patch(
            &format!("/providers/{tid}"),
            json!({ "link_by_email": true }),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let (s, v) = g
        .patch(
            &format!("/providers/{id}"),
            json!({ "name": "Google Workspace", "client_secret": "rotated-secret",
                    "link_by_email": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    no_secret(&v);
    assert!(!v.to_string().contains("rotated-secret"));
    assert_eq!(
        (&v["name"], &v["link_by_email"]),
        (&json!("Google Workspace"), &json!(true))
    );
    let (_, list) = g.get("/providers").await;
    assert_eq!(list.as_array().unwrap().len(), 2);
    no_secret(&list);
    let (_, got) = g.get(&format!("/providers/{id}")).await;
    no_secret(&got);
    assert_eq!(got, v);

    // A delete takes the identities and the sessions made through it along.
    let u = one(
        &e.db,
        &format!("INSERT INTO app_user (tenant_id, email, role) VALUES ({t}, 'u@acme.test', 'user') RETURNING id"),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    sql(
        &e.db,
        &format!(
            "INSERT INTO identity (user_id, provider_id, subject) VALUES ({u}, {id}, 's');
             INSERT INTO session (token_hash, user_id, csrf, expires_at, method, provider_id)
             VALUES ('\\x01', {u}, 'c', now() + interval '1 hour', 'oidc', {id})"
        ),
    )
    .await;
    let (_, got) = g.get(&format!("/providers/{id}")).await;
    assert_eq!(got["identities"], 1);
    // u has no password: the delete leaves it without a way in, and says so.
    let (s, v) = g.delete(&format!("/providers/{id}")).await;
    assert_eq!((s, v), (StatusCode::OK, json!({ "stranded": 1 })));
    assert_eq!(
        g.get(&format!("/providers/{id}")).await.0,
        StatusCode::NOT_FOUND
    );
    let left = one(
        &e.db,
        "SELECT (SELECT count(*) FROM identity) AS i, (SELECT count(*) FROM session WHERE method = 'oidc') AS s",
    )
    .await;
    assert_eq!(left, json!({ "i": 0, "s": 0 }));
    let audit = one(
        &e.db,
        "SELECT detail FROM audit WHERE action = 'provider.delete'",
    )
    .await;
    assert_eq!(audit["detail"]["identities_removed"], 1);
    assert_eq!(audit["detail"]["ended_sessions"], 1);
    let all = one(
        &e.db,
        "SELECT string_agg(detail::text, ' ') AS t FROM audit",
    )
    .await;
    let all = all["t"].as_str().unwrap();
    assert!(
        !all.contains(SECRET) && !all.contains("rotated-secret"),
        "{all}"
    );
    assert!(all.contains("\"client_secret_changed\": true"), "{all}");
}

#[tokio::test]
async fn a_tenant_admin_manages_only_their_tenants_providers() {
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let (ta, tb) = (tenant(&e.db, "acme").await, tenant(&e.db, "beta").await);
    let a = sign_in(&e, "admin@acme.test", "tenant_admin", Some(ta)).await;
    let global = g.create("/providers", body(None, "Google")).await["id"]
        .as_i64()
        .unwrap();
    let mut off = body(None, "Hidden");
    off["disabled"] = json!(true);
    let hidden = g.create("/providers", off).await["id"].as_i64().unwrap();
    let theirs = g.create("/providers", body(Some(tb), "Beta SSO")).await["id"]
        .as_i64()
        .unwrap();

    let own = a.create("/providers", body(Some(ta), "Acme SSO")).await;
    no_secret(&own);
    let own = own["id"].as_i64().unwrap();
    // Not another tenant's, not a global one, never `link_by_email`.
    for b in [body(Some(tb), "X"), body(None, "X")] {
        assert_eq!(a.post("/providers", b).await.0, StatusCode::FORBIDDEN);
    }
    let mut flagged = body(Some(ta), "Flagged");
    flagged["link_by_email"] = json!(true);
    assert_eq!(a.post("/providers", flagged).await.0, StatusCode::FORBIDDEN);
    let (s, _) = a
        .patch(
            &format!("/providers/{own}"),
            json!({ "link_by_email": true }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A global one they see by name: 403; another tenant's or a disabled global one
    // is not there for them, whatever the method.
    for (other, want) in [
        (global, StatusCode::FORBIDDEN),
        (theirs, StatusCode::NOT_FOUND),
        (hidden, StatusCode::NOT_FOUND),
    ] {
        let uri = format!("/providers/{other}");
        assert_eq!(a.patch(&uri, json!({ "name": "Mine" })).await.0, want);
        assert_eq!(a.delete(&uri).await.0, want);
    }
    for other in [theirs, hidden] {
        assert_eq!(
            a.get(&format!("/providers/{other}")).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let (s, v) = a
        .patch(
            &format!("/providers/{own}"),
            json!({ "name": "Acme", "client_secret": "new-one", "disabled": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Their own in full; the enabled global ones by name only (what users can link).
    let (_, list) = a.get("/providers").await;
    no_secret(&list);
    assert_eq!(
        list,
        json!([
            { "id": global, "tenant_id": null, "name": "Google", "disabled": false,
              "link_by_email": false, "managed": false, "issuer": null, "client_id": null,
              "identities": null },
            { "id": own, "tenant_id": ta, "name": "Acme", "disabled": true,
              "link_by_email": false, "managed": true, "issuer": "https://idp.example.org",
              "client_id": "wgate", "identities": 0 },
        ])
    );
    let (s, v) = a.delete(&format!("/providers/{own}")).await;
    assert_eq!((s, v), (StatusCode::OK, json!({ "stranded": 0 })));
    // A plain user manages none.
    let u = sign_in(&e, "u@acme.test", "user", Some(ta)).await;
    assert_eq!(u.get("/providers").await.0, StatusCode::FORBIDDEN);
    // A provider stays in its tenant.
    let moved =
        e.db.execute_unprepared(&format!(
            "UPDATE oidc_provider SET tenant_id = {ta} WHERE id = {theirs}"
        ))
        .await;
    assert!(moved.is_err());
}
