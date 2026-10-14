//! A provider's client secret never reaches the log nor the audit trail: not as it
//! was sent, not as the token request carries it; and a provider that cannot be
//! asked is logged with why. Its own test binary, as `log.rs`
//! (a global subscriber).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use base64::Engine;
use common::capture::Captured;
use common::idp;
use common::login::{one, tenant};
use common::oidc::{login, provider, start, who};
use common::{sign_in, sql};
use serde_json::json;

#[tokio::test]
async fn a_client_secret_stays_out_of_the_log_and_the_audit() {
    let captured = Captured::install();
    let first = "first-client-secret-value";
    let second = "second-client-secret-value";
    let (i1, i2) = (
        idp::start("one", first).await,
        idp::start("one", second).await,
    );
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let p = provider(&g, &i1, Some(t), "SSO", false).await;
    sql(
        &e.db,
        &format!(
            "INSERT INTO app_user (tenant_id, email, role) VALUES ({t}, 'u@acme.test', 'user')"
        ),
    )
    .await;
    login(&e.app, &i1, p, who("s", "u@acme.test", true))
        .await
        .unwrap();
    let (s, v) = g
        .patch(
            &format!("/providers/{p}"),
            json!({ "issuer": i2.issuer, "client_secret": second }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    login(&e.app, &i2, p, who("s", "u@acme.test", true))
        .await
        .unwrap();
    // A wrong one, refused by the provider (its error is logged).
    g.patch(
        &format!("/providers/{p}"),
        json!({ "client_secret": "third-wrong-secret" }),
    )
    .await;
    assert!(login(&e.app, &i2, p, who("s", "", false)).await.is_err());

    // A provider whose keys are at the cloud's metadata address: unavailable, and the
    // log says which provider and why.
    let bad = idp::start("bad", "whatever").await;
    bad.quirks.lock().unwrap().jwks_uri = Some("http://169.254.169.254/keys".into());
    let pb = provider(&g, &bad, Some(t), "Bad", false).await;
    assert_eq!(
        start(&e.app, &pb.to_string()).await.err().as_deref(),
        Some("unavailable")
    );

    let log = captured.text();
    let refusal = log
        .lines()
        .find(|l| l.contains("OIDC provider unavailable"))
        .expect("the refusal is logged");
    // Without the terminal colours around the fields.
    let mut plain = String::new();
    let mut chars = refusal.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            chars.by_ref().find(|c| *c == 'm');
        } else {
            plain.push(c);
        }
    }
    let refusal = plain;
    assert!(
        refusal.contains(&format!("provider={pb}"))
            && refusal.contains("169.254.169.254")
            && refusal.contains("plain http outside oidc_allow_private"),
        "{refusal}"
    );
    assert!(log.contains("UPDATE"), "the subscriber missed the queries");
    assert!(log.contains("token exchange"), "the refusal was not logged");
    let audit = one(
        &e.db,
        "SELECT string_agg(action || ' ' || detail::text, '\n') AS t FROM audit",
    )
    .await;
    let audit = audit["t"].as_str().unwrap();
    for action in ["provider.create", "provider.update", "login.oidc.ok"] {
        assert!(audit.contains(action), "{action} missing: {audit}");
    }
    for secret in [first, second, "third-wrong-secret"] {
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("one:{secret}"));
        for form in [secret.to_owned(), basic] {
            assert!(!log.contains(&form), "{form} was logged");
            assert!(!audit.contains(&form), "{form} in the audit");
        }
    }
}
