//! TOTP as an authenticator app computes it (independent of the server's code), and
//! TOTP set up on a session the way the UI does it.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use axum::Router;
use axum::http::StatusCode;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha1::Sha1;

use super::login::{self, PEER, Reply, send};
use wgate_server::Clock;

use super::Client;

/// The 6 digits for Unix time `t`.
pub fn code(secret: &[u8], t: i64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
    mac.update(&u64::try_from(t / 30).unwrap().to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = usize::from(h[19] & 15);
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]) % 1_000_000;
    format!("{n:06}")
}

/// The secret an otpauth URI carries.
pub fn secret_of(uri: &str) -> Vec<u8> {
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    data_encoding::BASE32_NOPAD.decode(b32.as_bytes()).unwrap()
}

/// The tests' password: a full session gives it to set TOTP up.
pub const PW: &str = "correct horse battery";

/// A fresh step: every code accepted so far is from an earlier one.
pub fn next_step(clock: &Clock) {
    clock.advance(30);
}

/// A request with session `cookie` and its CSRF token, from the default client.
pub async fn send_as(
    app: &Router,
    cookie: &str,
    csrf: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> Reply {
    let headers = [("cookie", cookie), ("x-csrf-token", csrf)];
    send(app, method, uri, body, PEER, &headers).await
}

impl Client {
    pub fn cookie(&self) -> String {
        format!("wgate_session={}", self.token)
    }

    /// `POST /auth/totp` with `body`.
    pub async fn second(&self, body: Value) -> Reply {
        self.second_from(body, PEER).await
    }

    /// As [`Client::second`], from client `peer`.
    pub async fn second_from(&self, body: Value, peer: &str) -> Reply {
        let (cookie, csrf) = (self.cookie(), self.csrf.clone());
        let headers = [("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
        send(&self.app, "POST", "/auth/totp", Some(body), peer, &headers).await
    }

    /// This session's client after a reply that may have replaced its cookie.
    pub fn after(&self, r: &Reply) -> Self {
        match r.session() {
            Some(cookie) => Self {
                token: cookie.strip_prefix("wgate_session=").unwrap().to_owned(),
                ..self.clone()
            },
            None => self.clone(),
        }
    }
}

pub struct Enrolled {
    pub secret: Vec<u8>,
    pub recovery_codes: Vec<String>,
    /// The session after the setup (a new cookie if it was in the `enrol` stage).
    pub client: Client,
}

/// Sets TOTP up on `c`'s session (giving [`PW`], which only a full one needs) and
/// confirms it with the current code; then moves on to the next step.
pub async fn enrol(c: &Client, clock: &Clock) -> Enrolled {
    let cookie = c.cookie();
    let body = json!({ "password": PW });
    let uri = "/api/v1/me/totp/setup";
    let r = send_as(&c.app, &cookie, &c.csrf, "POST", uri, Some(body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let secret = secret_of(r.body["otpauth_uri"].as_str().unwrap());
    let body = json!({ "code": code(&secret, clock.now()) });
    let uri = "/api/v1/me/totp/confirm";
    let r = send_as(&c.app, &cookie, &c.csrf, "POST", uri, Some(body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    next_step(clock);
    let recovery_codes = r.body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    Enrolled {
        secret,
        recovery_codes,
        client: c.after(&r),
    }
}

/// A password login, finished with the current code; then the next step.
pub async fn sign_in(app: &Router, clock: &Clock, email: &str, secret: &[u8]) -> Client {
    let r = login::login(app, email, PW).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let c = login::client(app, &r.session().unwrap()).await;
    let r = c.second(json!({ "code": code(secret, clock.now()) })).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    next_step(clock);
    c.after(&r)
}
