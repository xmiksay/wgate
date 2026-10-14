//! The round trip through an OpenID Connect provider: authorization code with PKCE
//! and a nonce, to log in (`GET /auth/oidc/{id}`) or to link an identity to the
//! signed-in account (started from `/me`). The round trip lives in the browser that
//! started it: the `wgate_login` cookie holds the provider, its state, nonce and PKCE
//! verifier, when it started, and for a link the session it is for, sealed with
//! `secret_key` (a browser can neither make one up nor edit one). A callback that
//! comes back without the cookie that started it counts for nothing, and an
//! abandoned round trip leaves nothing behind on the server.

use std::net::IpAddr;

use axum::extract::{Path, Query, State};
use axum::response::Redirect;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::CoreAuthenticationFlow;
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, CsrfToken, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RequestTokenError, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use url::Url;

use super::local::ClientIp;
use super::outbound::chain;
use super::provider::{self, Provider};
use super::session;
use crate::error::ApiError;
use crate::seal::Place;
use crate::state::AppState;

/// Between the redirect and the callback.
const LOGIN_TTL_SECS: i64 = 600;
const LOGIN_COOKIE: &str = "wgate_login";
/// Where the login routes are (see `router`): the only place the cookie goes.
const LOGIN_COOKIE_PATH: &str = "/auth";

/// A round trip that links an identity: for this account, in this session only.
#[derive(Clone, Serialize, Deserialize)]
pub struct Link {
    pub user: i64,
    /// The session token's SHA-256 (base64): only the browser holding that token
    /// finishes it.
    pub session: String,
}

impl Link {
    pub fn new(user: i64, token: &str) -> Self {
        Self {
            user,
            session: URL_SAFE_NO_PAD.encode(session::hash(token)),
        }
    }

    /// Whether `token` is the session this link was started in.
    pub fn of(&self, token: &str) -> bool {
        let hash = URL_SAFE_NO_PAD.encode(session::hash(token));
        bool::from(hash.as_bytes().ct_eq(self.session.as_bytes()))
    }
}

/// Where the cookie's seal is bound: no row, the cookie itself.
const COOKIE_PLACE: Place = Place {
    table: "cookie",
    column: LOGIN_COOKIE,
    id: 0,
};

/// One round trip between the redirect and the callback, kept in the browser that
/// started it: nothing is stored for one that never comes back.
#[derive(Serialize, Deserialize)]
struct Pending {
    /// Unix seconds: the server, not only the cookie's max-age, ends a stale one.
    started: i64,
    state: String,
    nonce: String,
    verifier: String,
    provider: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link: Option<Link>,
}

/// Off to provider `p`: the login cookie, and where to send the browser.
pub async fn round_trip(
    state: &AppState,
    p: &Provider,
    link: Option<Link>,
) -> Result<(Cookie<'static>, Url), ApiError> {
    let client = state.discovery.client(state, p).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, csrf, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(challenge)
        .url();
    let pending = Pending {
        started: unix_now(),
        state: csrf.secret().clone(),
        nonce: nonce.secret().clone(),
        verifier: verifier.secret().clone(),
        provider: p.id,
        link,
    };
    let json = serde_json::to_vec(&pending).map_err(anyhow::Error::from)?;
    let value = URL_SAFE_NO_PAD.encode(state.key.seal(COOKIE_PLACE, &json)?);
    let cookie = Cookie::build((LOGIN_COOKIE, value))
        .http_only(true)
        .secure(state.config.secure_cookies())
        .same_site(SameSite::Lax)
        .path(LOGIN_COOKIE_PATH)
        .max_age(time::Duration::seconds(LOGIN_TTL_SECS))
        .build();
    Ok((cookie, url))
}

/// Why a round trip ended without what it was for: the page it lands on says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    Expired,
    Cancelled,
    Forbidden,
    /// No such provider, or it is disabled.
    Unavailable,
    /// (link) The identity is another account's.
    Taken,
    /// (link) The account has an identity at this provider already.
    Exists,
    Failed,
}

impl Why {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Forbidden => "forbidden",
            Self::Unavailable => "unavailable",
            Self::Taken => "taken",
            Self::Exists => "exists",
            Self::Failed => "failed",
        }
    }

    /// An error of ours: logged here (with its causes), the browser only learns
    /// that it failed; a provider that cannot be reached is `unavailable` (logged
    /// where that was found out).
    pub fn failed(e: ApiError) -> Self {
        if let ApiError::ProviderUnavailable = e {
            return Self::Unavailable;
        }
        tracing::error!(error = e.chain(), "OIDC round trip failed");
        Self::Failed
    }
}

fn refuse(jar: CookieJar, page: &str, why: Why) -> (CookieJar, Redirect) {
    (jar, Redirect::to(&format!("{page}?error={}", why.as_str())))
}

/// `GET /auth/oidc/{id}`: off to provider `id` to log in; the login page says so
/// when there is no such provider (or it is disabled).
pub async fn start(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> (CookieJar, Redirect) {
    let found = match id.parse::<i64>() {
        Ok(id) => provider::enabled(&state.db, id).await,
        Err(_) => Ok(None),
    };
    let p = match found {
        Ok(Some(p)) => p,
        Ok(None) => return refuse(jar, "/login", Why::Unavailable),
        Err(e) => return refuse(jar, "/login", Why::failed(e)),
    };
    match round_trip(&state, &p, None).await {
        Ok((cookie, url)) => (jar.add(cookie), Redirect::to(url.as_str())),
        Err(e) => refuse(jar, "/login", Why::failed(e)),
    }
}

#[derive(Deserialize)]
/// The provider's answer: a code, or an `error` (the user cancelled, or it refused).
/// All optional, so any answer reaches the handler and ends on a page of the UI.
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /auth/callback`: back from the provider. A login gets a session (or the
/// login page saying why not); a link lands on `/me` (`?linked=<provider id>` or
/// `?error=`). A browser lands here, not a script.
pub async fn callback(
    State(state): State<AppState>,
    ip: ClientIp,
    jar: CookieJar,
    Query(q): Query<Callback>,
) -> (CookieJar, Redirect) {
    // Nothing counts, and nothing is cleared, unless it answers this browser's round
    // trip: a stray link to the callback must not cancel a sign-in in progress.
    let Some(pending) = pending_login(&state, &jar, q.state.as_deref()) else {
        return refuse(jar, "/login", Why::Expired);
    };
    let page = if pending.link.is_some() {
        "/me"
    } else {
        "/login"
    };
    let jar = jar.remove(Cookie::build(LOGIN_COOKIE).path(LOGIN_COOKIE_PATH));
    if !(0..=LOGIN_TTL_SECS).contains(&(unix_now() - pending.started)) {
        return refuse(jar, page, Why::Expired);
    }
    if let Some(error) = &q.error {
        let error: String = error.chars().take(64).collect();
        tracing::warn!(error = ?error, "refused by the provider");
        return refuse(jar, page, Why::Cancelled);
    }
    match complete(&state, ip.0, &jar, pending, q.code).await {
        Ok(Done::Login(token)) => {
            let cookie = session::cookie(token, state.config.secure_cookies());
            (jar.add(cookie), Redirect::to("/"))
        }
        Ok(Done::Linked(p)) => (jar, Redirect::to(&format!("/me?linked={p}"))),
        Err(why) => refuse(jar, page, why),
    }
}

/// This browser's round trip, if `state` is its (stale or not).
fn pending_login(app: &AppState, jar: &CookieJar, state: Option<&str>) -> Option<Pending> {
    jar.get(LOGIN_COOKIE)
        .and_then(|c| URL_SAFE_NO_PAD.decode(c.value()).ok())
        .and_then(|b| app.key.open(COOKIE_PLACE, &b).ok())
        .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
        .filter(|p| state.is_some_and(|s| bool::from(p.state.as_bytes().ct_eq(s.as_bytes()))))
}

pub enum Done {
    /// A session's token.
    Login(String),
    /// The provider an identity was linked at.
    Linked(i64),
}

async fn complete(
    state: &AppState,
    ip: IpAddr,
    jar: &CookieJar,
    pending: Pending,
    code: Option<String>,
) -> Result<Done, Why> {
    // Disabled meanwhile: it logs in nobody, and links nothing, from now on.
    let p = provider::enabled(&state.db, pending.provider)
        .await
        .map_err(Why::failed)?
        .ok_or(Why::Unavailable)?;
    let code = code.ok_or(Why::Expired)?;
    let (subject, email) = verify(state, &p, code, pending.nonce, pending.verifier).await?;
    match pending.link {
        None => super::oidc_done::login(state, ip, &p, &subject, email.as_deref()).await,
        Some(link) => {
            let token = jar.get(session::COOKIE).map(|c| c.value().to_owned());
            super::oidc_done::link(state, ip, &p, link, token, &subject).await
        }
    }
}

/// The code exchanged for an ID token, verified (signature, issuer, audience,
/// nonce): its subject and verified email (an unverified one is none).
async fn verify(
    state: &AppState,
    p: &Provider,
    code: String,
    nonce: String,
    verifier: String,
) -> Result<(String, Option<String>), Why> {
    let nonce = Nonce::new(nonce);
    let client = state
        .discovery
        .client(state, p)
        .await
        .map_err(Why::failed)?;
    let refused = |what: &str, e: &dyn std::error::Error| {
        tracing::warn!(provider = p.id, error = chain(e), "OIDC refused: {what}");
        Why::Forbidden
    };
    let exchange = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| refused("no token endpoint", &e))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&state.http)
        .await;
    let response = match exchange {
        Ok(r) => r,
        // Unreachable: the provider may have moved its endpoints. Anything it answered
        // (a refused made-up code, in whatever shape) must not flush the cache: anyone
        // can cause that.
        Err(e @ RequestTokenError::Request(_)) => {
            state.discovery.forget(p.id);
            tracing::warn!(
                provider = p.id,
                error = chain(&e),
                "OIDC token endpoint unavailable"
            );
            return Err(Why::Unavailable);
        }
        Err(e) => return Err(refused("token exchange", &e)),
    };
    let id_token = response.id_token().ok_or_else(|| {
        tracing::warn!(provider = p.id, "OIDC refused: no ID token");
        Why::Forbidden
    })?;
    let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(claims) => claims.clone(),
        // A bad nonce, audience or issuer is refused as it is; only a signature the
        // cached keys do not verify is worth a fresh look.
        Err(e @ ClaimsVerificationError::SignatureVerification(_)) => {
            tracing::debug!(provider = p.id, error = %e, "rediscovering the keys");
            // Perhaps signed with a key newer than the cached ones: once more, fresh.
            state.discovery.forget(p.id);
            let fresh = state
                .discovery
                .client(state, p)
                .await
                .map_err(Why::failed)?;
            id_token
                .claims(&fresh.id_token_verifier(), &nonce)
                .map_err(|e| refused("ID token", &e))?
                .clone()
        }
        Err(e) => return Err(refused("ID token", &e)),
    };
    let email = claims
        .email()
        .filter(|_| claims.email_verified() == Some(true))
        .map(|e| e.as_str().to_owned());
    Ok((claims.subject().as_str().to_owned(), email))
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
