//! The global admins' OIDC login against an in-process provider.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::idp::{self, Next};
use tower::ServiceExt;

/// `/auth/login`, then the provider's answer at `/auth/callback`: the session cookie
/// (or the refusal's status).
async fn log_in(app: &axum::Router, idp: &idp::Idp, who: Next) -> Result<String, StatusCode> {
    let res = app
        .clone()
        .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let location = res.headers()[header::LOCATION].to_str().unwrap();
    let url = url::Url::parse(location).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert!(
        location.starts_with(&format!("{}/authorize", idp.issuer)),
        "{location}"
    );
    assert_eq!(query["code_challenge_method"], "S256");
    *idp.next.lock().unwrap() = Next {
        nonce: query["nonce"].clone(),
        ..who
    };
    let callback = format!("/auth/callback?code=c&state={}", query["state"]);
    let res = app
        .clone()
        .oneshot(Request::get(&callback).body(Body::empty()).unwrap())
        .await
        .unwrap();
    if res.status() != StatusCode::SEE_OTHER {
        return Err(res.status());
    }
    let cookie = res.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"),
        "{cookie}"
    );
    // A replayed callback finds nothing.
    let replay = app
        .clone()
        .oneshot(Request::get(&callback).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    Ok(cookie.split(';').next().unwrap().to_owned())
}

async fn session_role(app: &axum::Router, cookie: &str) -> StatusCode {
    let res = app
        .clone()
        .oneshot(
            Request::get("/api/v1/session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    res.status()
}

fn who(subject: &str, email: &str, verified: bool) -> Next {
    Next {
        subject: subject.into(),
        email: email.into(),
        email_verified: verified,
        nonce: String::new(),
    }
}

#[tokio::test]
async fn a_global_admin_logs_in_and_their_subject_is_pinned() {
    let idp = idp::start("wgate").await;
    let e = common::env_with_issuer(&idp.issuer).await;
    wgate_server::grant_admin(&e.db, "Admin@Example.org")
        .await
        .unwrap();

    // First login: matched by the verified email (any case), the subject pinned.
    let cookie = log_in(&e.app, &idp, who("sub-1", "admin@example.org", true))
        .await
        .expect("logged in");
    assert_eq!(session_role(&e.app, &cookie).await, StatusCode::OK);
    // Again with the same subject: in.
    assert!(
        log_in(&e.app, &idp, who("sub-1", "other@example.org", true))
            .await
            .is_ok()
    );
    // The same email under another subject is someone else.
    assert_eq!(
        log_in(&e.app, &idp, who("sub-2", "admin@example.org", true)).await,
        Err(StatusCode::FORBIDDEN)
    );
}

#[tokio::test]
async fn unverified_emails_and_strangers_are_refused() {
    let idp = idp::start("wgate").await;
    let e = common::env_with_issuer(&idp.issuer).await;
    wgate_server::grant_admin(&e.db, "admin@example.org")
        .await
        .unwrap();
    assert_eq!(
        log_in(&e.app, &idp, who("sub-1", "admin@example.org", false)).await,
        Err(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        log_in(&e.app, &idp, who("sub-9", "nobody@example.org", true)).await,
        Err(StatusCode::FORBIDDEN)
    );
    // Without a session: not signed in.
    assert_eq!(
        session_role(&e.app, "wgate_session=forged").await,
        StatusCode::UNAUTHORIZED
    );
}
