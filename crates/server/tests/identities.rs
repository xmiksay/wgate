//! Linked identities: linking from `/me` binds the session's own account only (a
//! round trip finished elsewhere links nothing), unlinking never takes the last way
//! in, and an admin pre-links and unlinks as far as invite and reset links reach.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::idp::{self, Idp};
use common::login::{self, account, one, tenant};
use common::oidc::{self as flow, location, provider, start_link, who};
use common::{Client, Env, sign_in, sql};
use serde_json::json;

const SECRET: &str = "client-secret";
const PW: &str = "correct horse battery";

/// A password login of a plain user (a full session).
async fn user(e: &Env, email: &str, tenant: i64) -> Client {
    account(&e.db, email, "user", Some(tenant), PW).await;
    login::client(
        &e.app,
        &login::login(&e.app, email, PW).await.session().unwrap(),
    )
    .await
}

struct World {
    e: Env,
    g: Client,
    ig: Idp,
    ia: Idp,
    /// A global provider and tenant A's.
    pg: i64,
    pa: i64,
    ta: i64,
    tb: i64,
}

async fn world() -> World {
    let (ig, ia) = (idp::start("g", SECRET).await, idp::start("a", SECRET).await);
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let (ta, tb) = (tenant(&e.db, "acme").await, tenant(&e.db, "beta").await);
    let pg = provider(&g, &ig, None, "Google", false).await;
    let pa = provider(&g, &ia, Some(ta), "Acme SSO", false).await;
    World {
        e,
        g,
        ig,
        ia,
        pg,
        pa,
        ta,
        tb,
    }
}

#[tokio::test]
async fn linking_from_me_binds_the_sessions_own_account_only() {
    let w = world().await;
    let u = user(&w.e, "u@acme.test", w.ta).await;
    let v = user(&w.e, "v@acme.test", w.ta).await;
    let b = user(&w.e, "b@beta.test", w.tb).await;

    // No email matching: whatever the provider says the email is.
    let to = flow::link(&u, &w.ig, w.pg, who("su", "v@acme.test", true)).await;
    assert_eq!(to, format!("/me?linked={}", w.pg));
    let (_, mine) = u.get("/me/identities").await;
    assert_eq!(mine.as_array().unwrap().len(), 1);
    assert_eq!(
        (&mine[0]["provider_name"], &mine[0]["subject"]),
        (&json!("Google"), &json!("su"))
    );
    assert!(mine[0]["created_at"].as_str().unwrap().ends_with('Z'));
    let cookie = flow::login(&w.e.app, &w.ig, w.pg, who("su", "", false))
        .await
        .unwrap();
    assert_eq!(login::client(&w.e.app, &cookie).await.user_id, u.user_id);

    // Taken: the subject is u's; and u has one at Google already.
    let to = flow::link(&v, &w.ig, w.pg, who("su", "", false)).await;
    assert_eq!(to, "/me?error=taken");
    let (s, _) = start_link(&u, w.pg).await.err().unwrap();
    assert_eq!(s, StatusCode::CONFLICT);
    // A tenant's provider serves its own tenant's accounts only.
    let (s, _) = start_link(&b, w.pa).await.err().unwrap();
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        start_link(&b, 999_999).await.err().unwrap().0,
        StatusCode::NOT_FOUND
    );

    // Finished in another browser: without the login cookie, or with it but another
    // account's session (or none), nothing is linked.
    let started = start_link(&v, w.pa).await.unwrap();
    let elsewhere = [
        vec![format!("wgate_session={}", v.token)],
        vec![started.cookie.clone(), format!("wgate_session={}", b.token)],
        vec![started.cookie.clone()],
    ];
    for cookies in &elsewhere {
        let cookies: Vec<&str> = cookies.iter().map(String::as_str).collect();
        let r = started
            .finish(&w.e.app, &w.ia, who("sv", "", false), &cookies)
            .await;
        let to = location(&r);
        assert!(to.ends_with("error=expired"), "{cookies:?}: {to}");
    }
    // The session that started it ended meanwhile: nothing either.
    let started = start_link(&v, w.pa).await.unwrap();
    let session = format!("wgate_session={}", v.token);
    let r = login::send(
        &w.e.app,
        "POST",
        "/auth/logout",
        None,
        login::PEER,
        &[("cookie", &session)],
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = started
        .finish(
            &w.e.app,
            &w.ia,
            who("sv", "", false),
            &[&started.cookie, &session],
        )
        .await;
    assert_eq!(location(&r), "/me?error=expired");
    let linked = one(
        &w.e.db,
        &format!(
            "SELECT count(*) AS n FROM identity WHERE user_id = {}",
            v.user_id
        ),
    )
    .await;
    assert_eq!(linked["n"], 0);

    // An admin still to set TOTP up links nothing.
    account(&w.e.db, "admin@acme.test", "tenant_admin", Some(w.ta), PW).await;
    let r = login::login(&w.e.app, "admin@acme.test", PW).await;
    let enrol = login::client(&w.e.app, &r.session().unwrap()).await;
    let (s, body) = start_link(&enrol, w.pa).await.err().unwrap();
    assert_eq!(
        (s, &body["error"]),
        (StatusCode::FORBIDDEN, &json!("totp_required"))
    );

    let audit = one(
        &w.e.db,
        "SELECT jsonb_agg(action || ':' || coalesce(detail->>'reason', '') ORDER BY id) AS a
         FROM audit WHERE action LIKE 'user.identity.%'",
    )
    .await;
    assert_eq!(
        audit["a"],
        json!(["user.identity.link:", "user.identity.link.failed:taken"])
    );
}

#[tokio::test]
async fn unlinking_never_takes_the_last_way_in() {
    let w = world().await;
    // An account without a password, in through Google.
    let id = one(
        &w.e.db,
        &format!("INSERT INTO app_user (tenant_id, email, role) VALUES ({}, 'n@acme.test', 'user') RETURNING id", w.ta),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    sql(
        &w.e.db,
        &format!(
            "INSERT INTO identity (user_id, provider_id, subject) VALUES ({id}, {}, 'sn')",
            w.pg
        ),
    )
    .await;
    let cookie = flow::login(&w.e.app, &w.ig, w.pg, who("sn", "", false))
        .await
        .unwrap();
    let n = login::client(&w.e.app, &cookie).await;
    let (_, mine) = n.get("/me/identities").await;
    let google = mine[0]["id"].as_i64().unwrap();
    let (s, v) = n.delete(&format!("/me/identities/{google}")).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    // A second identity, at a provider that is disabled: still the last way in.
    let to = flow::link(&n, &w.ia, w.pa, who("sn-a", "", false)).await;
    assert_eq!(to, format!("/me?linked={}", w.pa));
    let (s, _) =
        w.g.patch(&format!("/providers/{}", w.pa), json!({ "disabled": true }))
            .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        n.delete(&format!("/me/identities/{google}")).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    w.g.patch(
        &format!("/providers/{}", w.pa),
        json!({ "disabled": false }),
    )
    .await;
    // Enabled again: Google may go (this session, made through it, stays).
    assert_eq!(
        n.delete(&format!("/me/identities/{google}")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(n.get("/session").await.0, StatusCode::OK);
    let (_, mine) = n.get("/me/identities").await;
    let acme = mine[0]["id"].as_i64().unwrap();
    assert_eq!(
        n.delete(&format!("/me/identities/{acme}")).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Someone else's identity is not found.
    let u = user(&w.e, "u@acme.test", w.ta).await;
    assert_eq!(
        u.delete(&format!("/me/identities/{acme}")).await.0,
        StatusCode::NOT_FOUND
    );
    // With a password, the only identity may go.
    let to = flow::link(&u, &w.ig, w.pg, who("su", "", false)).await;
    assert!(to.starts_with("/me?linked="), "{to}");
    let (_, mine) = u.get("/me/identities").await;
    let only = mine[0]["id"].as_i64().unwrap();
    assert_eq!(
        u.delete(&format!("/me/identities/{only}")).await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn admins_pre_link_and_unlink_within_their_reach() {
    let w = world().await;
    let a = sign_in(&w.e, "admin@acme.test", "tenant_admin", Some(w.ta)).await;
    let peer = sign_in(&w.e, "peer@acme.test", "tenant_admin", Some(w.ta)).await;
    let u = account(&w.e.db, "u@acme.test", "user", Some(w.ta), PW).await;
    let b = account(&w.e.db, "b@beta.test", "user", Some(w.tb), PW).await;
    let link = |p: i64, s: &str| json!({ "provider_id": p, "subject": s });

    // A tenant admin: their tenant's plain users, at their tenant's or a global provider.
    let made = a
        .create(&format!("/users/{u}/identities"), link(w.pa, "su"))
        .await;
    assert_eq!(
        (&made["provider_name"], &made["subject"]),
        (&json!("Acme SSO"), &json!("su"))
    );
    let cookie = flow::login(&w.e.app, &w.ia, w.pa, who("su", "", false))
        .await
        .unwrap();
    assert_eq!(login::client(&w.e.app, &cookie).await.user_id, u);
    a.create(&format!("/users/{u}/identities"), link(w.pg, "su-g"))
        .await;
    for (target, why) in [
        (b, StatusCode::FORBIDDEN),
        (peer.user_id, StatusCode::FORBIDDEN),
        (w.g.user_id, StatusCode::FORBIDDEN),
        (a.user_id, StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let (s, v) = a
            .post(&format!("/users/{target}/identities"), link(w.pg, "x"))
            .await;
        assert_eq!(s, why, "{target}: {v}");
    }
    // A tenant's provider serves only its tenant; taken and duplicate are 409.
    let (s, _) =
        w.g.post(&format!("/users/{b}/identities"), link(w.pa, "sb"))
            .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) =
        w.g.post(&format!("/users/{b}/identities"), link(w.pg, "su-g"))
            .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = a
        .post(&format!("/users/{u}/identities"), link(w.pa, "other"))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = a
        .post(&format!("/users/{u}/identities"), link(w.pa, " "))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // A global admin reaches admins too.
    w.g.create(
        &format!("/users/{}/identities", peer.user_id),
        link(w.pa, "sp"),
    )
    .await;

    let (s, list) = a.get(&format!("/users/{u}/identities")).await;
    assert_eq!((s, list.as_array().unwrap().len()), (StatusCode::OK, 2));
    assert_eq!(
        a.get(&format!("/users/{b}/identities")).await.0,
        StatusCode::FORBIDDEN
    );
    let first = list[0]["id"].as_i64().unwrap();
    let (_, peers) =
        w.g.get(&format!("/users/{}/identities", peer.user_id))
            .await;
    let peers_one = peers[0]["id"].as_i64().unwrap();
    let uri = format!("/users/{}/identities/{peers_one}", peer.user_id);
    assert_eq!(a.delete(&uri).await.0, StatusCode::FORBIDDEN);
    // The identity's sessions end with it; u keeps a password and Google.
    assert_eq!(
        a.delete(&format!("/users/{u}/identities/{first}")).await.0,
        StatusCode::NO_CONTENT
    );
    let r = login::send(
        &w.e.app,
        "GET",
        "/api/v1/session",
        None,
        login::PEER,
        &[("cookie", &cookie)],
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        a.delete(&format!("/users/{u}/identities/{first}")).await.0,
        StatusCode::NOT_FOUND
    );
    // peer has no password (signed in by hand): its only identity is its last way in.
    let (s, v) = w.g.delete(&uri).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let audit = one(
        &w.e.db,
        "SELECT count(*) FILTER (WHERE action = 'user.identity.link') AS l,
                count(*) FILTER (WHERE action = 'user.identity.unlink') AS u FROM audit",
    )
    .await;
    assert_eq!(audit, json!({ "l": 3, "u": 1 }));
}
