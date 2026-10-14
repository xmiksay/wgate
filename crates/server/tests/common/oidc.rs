//! Round trips through the mock providers as a browser makes them: start, the
//! provider's answer at `/auth/callback`, and where the browser lands.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::HashMap;

use axum::Router;
use axum::http::{StatusCode, header};
use serde_json::{Value, json};

use super::Client;
use super::idp::{Idp, Next};
use super::login::{PEER, Reply, send};

pub fn who(subject: &str, email: &str, verified: bool) -> Next {
    Next {
        subject: subject.into(),
        email: email.into(),
        email_verified: verified,
        ..Next::default()
    }
}

/// A provider for `idp` made by `admin` through the API: its id.
pub async fn provider(
    admin: &Client,
    idp: &Idp,
    tenant: Option<i64>,
    name: &str,
    link_by_email: bool,
) -> i64 {
    let body = json!({ "tenant_id": tenant, "name": name, "issuer": idp.issuer,
                       "client_id": idp.client_id, "client_secret": idp.client_secret,
                       "link_by_email": link_by_email });
    admin.create("/providers", body).await["id"]
        .as_i64()
        .unwrap()
}

/// `name=value` of each cookie a reply sets.
pub fn set_cookies(r: &Reply) -> HashMap<String, String> {
    r.headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|c| {
            let pair = c.to_str().unwrap().split(';').next().unwrap();
            let (name, _) = pair.split_once('=').unwrap();
            (name.to_owned(), pair.to_owned())
        })
        .collect()
}

/// Where a redirect sends the browser.
pub fn location(r: &Reply) -> String {
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    r.headers[header::LOCATION].to_str().unwrap().to_owned()
}

/// A round trip on its way to the provider.
pub struct Started {
    /// `wgate_login=…`
    pub cookie: String,
    pub url: url::Url,
}

impl Started {
    pub fn query(&self) -> HashMap<String, String> {
        self.url.query_pairs().into_owned().collect()
    }

    /// The provider answers as `who`; the browser comes back with `cookies` (the
    /// login cookie among them, or not): where it lands, and the cookies it gets.
    pub async fn finish(&self, app: &Router, idp: &Idp, who: Next, cookies: &[&str]) -> Reply {
        let q = self.query();
        assert!(
            self.url
                .as_str()
                .starts_with(&format!("{}/authorize", idp.issuer)),
            "{} is not {}",
            self.url,
            idp.issuer
        );
        assert_eq!(q["code_challenge_method"], "S256");
        *idp.next.lock().unwrap() = Next {
            nonce: q["nonce"].clone(),
            ..who
        };
        let uri = format!("/auth/callback?code=c&state={}", q["state"]);
        let cookie = cookies.join("; ");
        let headers: Vec<(&str, &str)> = if cookie.is_empty() {
            vec![]
        } else {
            vec![("cookie", cookie.as_str())]
        };
        send(app, "GET", &uri, None, PEER, &headers).await
    }
}

/// `GET /auth/oidc/{id}`: on its way, or the login page's `error`.
pub async fn start(app: &Router, provider: &str) -> Result<Started, String> {
    let r = send(
        app,
        "GET",
        &format!("/auth/oidc/{provider}"),
        None,
        PEER,
        &[],
    )
    .await;
    let to = location(&r);
    if let Some(why) = to.strip_prefix("/login?error=") {
        return Err(why.to_owned());
    }
    let cookie = set_cookies(&r)
        .remove("wgate_login")
        .expect("a login cookie");
    let all = r.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        all.contains("HttpOnly") && all.contains("Path=/auth"),
        "{all}"
    );
    Ok(Started {
        cookie,
        url: url::Url::parse(&to).unwrap(),
    })
}

/// A login through `provider` as `who`: the session cookie, or the refusal's reason.
pub async fn login(app: &Router, idp: &Idp, provider: i64, who: Next) -> Result<String, String> {
    let started = start(app, &provider.to_string()).await?;
    let r = started.finish(app, idp, who, &[&started.cookie]).await;
    let to = location(&r);
    if let Some(why) = to.strip_prefix("/login?error=") {
        return Err(why.to_owned());
    }
    assert_eq!(to, "/");
    let cookies = set_cookies(&r);
    assert_eq!(
        cookies["wgate_login"], "wgate_login=",
        "the round trip is over"
    );
    Ok(cookies["wgate_session"].clone())
}

/// `POST /me/identities/{provider}/link` from `c`: on its way, or the API's answer.
pub async fn start_link(c: &Client, provider: i64) -> Result<Started, (StatusCode, Value)> {
    let session = format!("wgate_session={}", c.token);
    let uri = format!("/api/v1/me/identities/{provider}/link");
    let headers = [
        ("cookie", session.as_str()),
        ("x-csrf-token", c.csrf.as_str()),
    ];
    let r = send(&c.app, "POST", &uri, None, PEER, &headers).await;
    if r.status != StatusCode::OK {
        return Err((r.status, r.body));
    }
    let cookie = set_cookies(&r)
        .remove("wgate_login")
        .expect("a login cookie");
    Ok(Started {
        cookie,
        url: url::Url::parse(r.body["url"].as_str().unwrap()).unwrap(),
    })
}

/// A link from `c`'s browser through `provider` as `who`: where it lands on `/me`.
pub async fn link(c: &Client, idp: &Idp, provider: i64, who: Next) -> String {
    let started = start_link(c, provider).await.expect("link started");
    let session = format!("wgate_session={}", c.token);
    let r = started
        .finish(&c.app, idp, who, &[&started.cookie, &session])
        .await;
    location(&r)
}
