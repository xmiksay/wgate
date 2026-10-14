//! A TOTP secret, a recovery code or a link's token never reaches the log nor the
//! audit trail; a sealed secret copied to another row does not open there. Its own
//! test binary, as `log.rs` (a global subscriber).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::StatusCode;
use common::capture::Captured;
use common::login::{self, PEER, account, login, one, send, tenant};
use common::totp::{self, PW, code, enrol};
use common::{sign_in, sql};
use serde_json::json;

const NEW: &str = "a new and longer passphrase";

#[tokio::test]
async fn totp_secrets_codes_and_tokens_stay_out_of_the_log() {
    let captured = Captured::install();
    let e = common::env().await;
    let t = tenant(&e.db, "acme").await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let u = account(&e.db, "u@acme.test", "user", Some(t), PW).await;
    let v = account(&e.db, "v@acme.test", "user", Some(t), PW).await;
    let app = e.app.clone();
    let client = |email: &'static str| {
        let app = app.clone();
        async move { login::client(&app, &login(&app, email, PW).await.session().unwrap()).await }
    };
    let mut secrets: Vec<String> = vec![PW.into(), NEW.into()];

    let en = enrol(&client("u@acme.test").await, &e.clock).await;
    secrets.push(data_encoding::BASE32_NOPAD.encode(&en.secret));
    secrets.extend(en.recovery_codes.iter().cloned());
    let c = totp::sign_in(&e.app, &e.clock, "u@acme.test", &en.secret).await;
    let r = client("u@acme.test")
        .await
        .second(json!({ "recovery_code": en.recovery_codes[0] }))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let body = json!({ "code": code(&en.secret, e.clock.now()) });
    let (s, fresh) = c.post("/me/recovery-codes", body).await;
    assert_eq!(s, StatusCode::OK);
    let fresh: Vec<String> = serde_json::from_value(fresh["recovery_codes"].clone()).unwrap();
    secrets.extend(fresh);

    // u's sealed secret in v's row: bound to u's row, it does not open for v.
    enrol(&client("v@acme.test").await, &e.clock).await;
    sql(
        &e.db,
        &format!(
            "UPDATE app_user SET totp_secret = (SELECT totp_secret FROM app_user WHERE id = {u})
             WHERE id = {v}"
        ),
    )
    .await;
    let r = client("v@acme.test")
        .await
        .second(json!({ "code": code(&en.secret, e.clock.now()) }))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);

    // An invite and a reset, followed.
    let w = g
        .create(
            "/users",
            json!({ "tenant_id": t, "email": "w@acme.test", "role": "user" }),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    for (id, purpose) in [(w, "invite"), (u, "reset")] {
        let (_, l) = g.post(&format!("/users/{id}/{purpose}"), json!({})).await;
        let url = l["url"].as_str().unwrap();
        let token = url.rsplit('/').next().unwrap().to_owned();
        let uri = format!("/auth/account/{token}");
        let r = send(
            &e.app,
            "POST",
            &uri,
            Some(json!({ "password": NEW })),
            PEER,
            &[],
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        secrets.push(token);
    }

    let log = captured.text();
    assert!(
        log.contains("UPDATE app_user"),
        "the subscriber missed the queries"
    );
    assert!(
        log.contains("does not open"),
        "the copied blob was not refused"
    );
    let audit = one(
        &e.db,
        "SELECT string_agg(action || ' ' || detail::text, '\n') AS t FROM audit",
    )
    .await;
    let audit = audit["t"].as_str().unwrap();
    for action in [
        "user.totp.setup",
        "user.totp.enable",
        "login.totp.ok",
        "login.totp.failed",
        "user.recovery_codes.new",
        "user.invite_link",
        "user.reset_link",
        "user.password.set",
    ] {
        assert!(audit.contains(action), "{action} missing: {audit}");
    }
    for secret in &secrets {
        assert!(!log.contains(secret.as_str()), "{secret} was logged");
        assert!(!audit.contains(secret.as_str()), "{secret} in the audit");
    }
}
