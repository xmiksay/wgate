//! What wgate asks a provider, and what it takes back: no request into private
//! addresses (unless `oidc_allow_private` lists them), no plain http outside that
//! list, capped answers, a failed discovery not retried at once, and an ID token
//! for another login, client or issuer refused; and a callback counts only with the
//! sealed cookie of the browser that started the round trip.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::idp::{self, Forge, Next};
use common::login::{self, PEER, one, send, tenant};
use common::oidc::{login, provider, start, who};
use common::sign_in;
use serde_json::json;

const SECRET: &str = "client-secret";

#[tokio::test]
async fn a_provider_on_a_private_address_is_refused_without_the_allowlist() {
    let i = idp::start("c", SECRET).await;
    let e = common::env_with(|c| c.oidc_allow_private.clear()).await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    // Created (where a name resolves to is the request's business), never asked.
    let p = provider(&g, &i, None, "Loopback", false).await;
    assert_eq!(
        start(&e.app, &p.to_string()).await.err().as_deref(),
        Some("unavailable")
    );
    assert_eq!(i.discovered(), 0, "nothing was sent to it");
}

#[tokio::test]
async fn discovered_endpoints_are_checked_and_answers_capped() {
    let (i1, i2) = (idp::start("c", SECRET).await, idp::start("c", SECRET).await);
    // Only the provider itself is allowed.
    let host = i1.issuer.trim_start_matches("http://").to_owned();
    let e =
        common::env_with(|c| c.oidc_allow_private = vec!["127.0.0.1/32".parse().unwrap()]).await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;

    // Keys at the cloud's metadata address, at a private one, or over plain http
    // elsewhere: discovery fails, the login page says unavailable.
    for jwks in [
        "http://169.254.169.254/latest/meta-data",
        "https://10.0.0.1/jwks",
        "http://127.0.0.2/jwks",
        &format!("http://{host}/jwks"),
    ] {
        i1.quirks.lock().unwrap().jwks_uri = Some(jwks.to_owned());
        let name = format!("P {}", jwks.replace('/', "_"));
        let p = provider(&g, &i1, Some(t), &name, false).await;
        let r = start(&e.app, &p.to_string()).await;
        if jwks.contains(&host) {
            assert!(r.is_ok(), "{jwks}: its own address is allowed");
        } else {
            assert_eq!(r.err().as_deref(), Some("unavailable"), "{jwks}");
        }
    }

    // An answer over 1 MiB is refused; the failure is remembered for a while, so the
    // next hit does not ask again. A link start says so as 503 `unavailable`.
    i2.quirks.lock().unwrap().pad = 2 << 20;
    let p = provider(&g, &i2, Some(t), "Big", false).await;
    for _ in 0..2 {
        assert_eq!(
            start(&e.app, &p.to_string()).await.err().as_deref(),
            Some("unavailable")
        );
    }
    login::account(
        &e.db,
        "u@acme.test",
        "user",
        Some(t),
        "correct horse battery",
    )
    .await;
    let r = login::login(&e.app, "u@acme.test", "correct horse battery").await;
    let c = login::client(&e.app, &r.session().unwrap()).await;
    let (s, v) = common::oidc::start_link(&c, p).await.err().unwrap();
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::SERVICE_UNAVAILABLE, &json!("unavailable"))
    );
    assert_eq!(i2.discovered(), 1);
}

#[tokio::test]
async fn an_id_token_for_another_login_client_or_issuer_is_refused() {
    let i = idp::start("c", SECRET).await;
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let p = provider(&g, &i, Some(t), "SSO", false).await;
    login::account(
        &e.db,
        "u@acme.test",
        "user",
        Some(t),
        "correct horse battery",
    )
    .await;
    for forge in [Forge::Nonce, Forge::Audience, Forge::Issuer] {
        let next = Next {
            forge: Some(forge),
            ..who("s", "u@acme.test", true)
        };
        assert_eq!(
            login(&e.app, &i, p, next).await,
            Err("forbidden".into()),
            "{forge:?}"
        );
    }
    // Refused as it is: no claim mismatch makes it rediscover.
    assert_eq!(i.discovered(), 1);
    let none = one(&e.db, "SELECT count(*) AS n FROM identity").await;
    assert_eq!(none["n"], 0);
    assert!(
        login(&e.app, &i, p, who("s", "u@acme.test", true))
            .await
            .is_ok()
    );
}

/// The round trip belongs to the browser that started it, for 10 minutes.
#[tokio::test]
async fn a_callback_counts_only_for_the_browser_that_started_it() {
    let ia = idp::start("a", SECRET).await;
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let p = provider(&g, &ia, Some(t), "SSO", false).await;
    login::account(
        &e.db,
        "u@acme.test",
        "user",
        Some(t),
        "correct horse battery",
    )
    .await;
    let started = start(&e.app, &p.to_string()).await.unwrap();
    for cookies in [vec![], vec!["wgate_login=another"]] {
        let r = started
            .finish(&e.app, &ia, who("s", "u@acme.test", true), &cookies)
            .await;
        assert_eq!(common::oidc::location(&r), "/login?error=expired");
    }
    let r = started
        .finish(
            &e.app,
            &ia,
            who("s", "u@acme.test", true),
            &[&started.cookie],
        )
        .await;
    assert_eq!(common::oidc::location(&r), "/");

    // Cancelled at the provider, back without a code, or another login's state.
    for (query, to) in [
        (
            "error=access_denied&state={state}",
            "/login?error=cancelled",
        ),
        ("state={state}", "/login?error=expired"),
        ("error=access_denied&state=other", "/login?error=expired"),
    ] {
        let started = start(&e.app, &p.to_string()).await.unwrap();
        let uri = format!(
            "/auth/callback?{}",
            query.replace("{state}", &started.query()["state"])
        );
        let r = send(
            &e.app,
            "GET",
            &uri,
            None,
            PEER,
            &[("cookie", &started.cookie)],
        )
        .await;
        assert_eq!(common::oidc::location(&r), to, "{query}");
    }
    // The cookie is sealed: one made up (as an unsealed one looked) or edited is none.
    use base64::Engine;
    let started = start(&e.app, &p.to_string()).await.unwrap();
    let state = started.query()["state"].clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let forged = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        json!({ "started": now, "state": state, "nonce": "n", "verifier": "v", "provider": p })
            .to_string(),
    );
    let mut edited = started.cookie.clone().into_bytes();
    let last = edited.len() - 2;
    edited[last] = if edited[last] == b'A' { b'B' } else { b'A' };
    let edited = String::from_utf8(edited).unwrap();
    for cookie in [format!("wgate_login={forged}"), edited] {
        let uri = format!("/auth/callback?error=access_denied&state={state}");
        let r = send(&e.app, "GET", &uri, None, PEER, &[("cookie", &cookie)]).await;
        assert_eq!(common::oidc::location(&r), "/login?error=expired");
    }

    // Logging out ends the session; a dead one still gets its cookie cleared.
    let session = login(&e.app, &ia, p, who("s", "", false)).await.unwrap();
    for _ in 0..2 {
        let r = send(
            &e.app,
            "POST",
            "/auth/logout",
            None,
            PEER,
            &[("cookie", &session)],
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        assert_eq!(
            common::oidc::set_cookies(&r)["wgate_session"],
            "wgate_session="
        );
    }
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
}
