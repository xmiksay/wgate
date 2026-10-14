//! The global admins' login: OpenID Connect authorization code with PKCE. A login
//! matches a global admin by the issuer's subject, or the first time by their verified
//! email (which then pins the subject: an email changed at the IdP takes nothing over).
//! The round trip lives in the browser that started it (the `wgate_login` cookie holds
//! its state, nonce and PKCE verifier), so nobody can hand someone else a callback to
//! their account, and an abandoned login leaves nothing behind.

use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RequestTokenError, Scope, TokenResponse,
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use super::session;
use crate::audit;
use crate::config::Oidc;
use crate::error::ApiError;
use crate::state::AppState;

/// Between the redirect and the callback.
const LOGIN_TTL_SECS: i64 = 600;
const LOGIN_COOKIE: &str = "wgate_login";
/// Where the login routes are (see `router`): the only place the cookie goes.
const LOGIN_COOKIE_PATH: &str = "/auth";
/// How long discovered metadata (endpoints, signing keys) is reused.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// The provider's discovered client, reused for [`DISCOVERY_TTL`]: neither a login nor
/// a stream of unauthenticated `/auth/login` hits rediscovers it each time.
#[derive(Default)]
pub struct Provider(Mutex<Option<(Instant, Client)>>);

impl Provider {
    async fn client(&self, state: &AppState) -> Result<Client, ApiError> {
        let mut cached = self.0.lock().await;
        if let Some((at, client)) = cached.as_ref()
            && at.elapsed() < DISCOVERY_TTL
        {
            return Ok(client.clone());
        }
        let client = discover(state).await?;
        *cached = Some((Instant::now(), client.clone()));
        Ok(client)
    }

    /// The next login rediscovers (the provider may have rotated its keys).
    async fn forget(&self) {
        *self.0.lock().await = None;
    }
}

/// The one provider of plan 1.8, as `/auth/options` lists it.
pub const ADMIN_PROVIDER: &str = "admin";

/// `NotFound` without `[admin_oidc]`.
fn config(state: &AppState) -> Result<&Oidc, ApiError> {
    state.config.admin_oidc.as_ref().ok_or(ApiError::NotFound)
}

async fn discover(state: &AppState) -> Result<Client, ApiError> {
    let oidc = config(state)?;
    let issuer = IssuerUrl::new(oidc.issuer.clone()).map_err(anyhow::Error::from)?;
    let metadata = CoreProviderMetadata::discover_async(issuer, &state.http)
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery: {e}"))?;
    let redirect = state
        .config
        .public_url
        .join("auth/callback")
        .map_err(anyhow::Error::from)?;
    Ok(CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(oidc.client_id.clone()),
        Some(ClientSecret::new(oidc.client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::from_url(redirect)))
}

/// `GET /auth/oidc/{id}`: off to provider `id` (only [`ADMIN_PROVIDER`] for now).
pub async fn start(
    state: State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> Result<(CookieJar, Redirect), ApiError> {
    if id != ADMIN_PROVIDER {
        return Ok((jar, Redirect::to(UNAVAILABLE)));
    }
    login(state, jar).await
}

/// Where a login through a provider that is not configured lands.
const UNAVAILABLE: &str = "/login?error=unavailable";

/// `GET /auth/login`: off to the admins' provider; the login page says so when there
/// is none.
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), ApiError> {
    if state.config.admin_oidc.is_none() {
        return Ok((jar, Redirect::to(UNAVAILABLE)));
    }
    let client = state.oidc.client(&state).await?;
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
    };
    let value = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&pending).map_err(anyhow::Error::from)?);
    let cookie = Cookie::build((LOGIN_COOKIE, value))
        .http_only(true)
        .secure(state.config.secure_cookies())
        .same_site(SameSite::Lax)
        .path(LOGIN_COOKIE_PATH)
        .max_age(time_secs(LOGIN_TTL_SECS))
        .build();
    Ok((jar.add(cookie), Redirect::to(url.as_str())))
}

/// One login between the redirect and the callback, kept in the browser that started
/// it: nothing is stored for a login that never comes back.
#[derive(Serialize, Deserialize)]
struct Pending {
    /// Unix seconds: the server, not only the cookie's max-age, ends a stale login.
    started: i64,
    state: String,
    nonce: String,
    verifier: String,
}

#[derive(Deserialize)]
/// The provider's answer: a code, or an `error` (the user cancelled, or it refused).
/// All optional, so any answer reaches the handler and ends on the login page.
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /auth/callback`: back from the provider; a session for a global admin, or
/// the UI's login page saying why not (a browser lands here, not a script).
pub async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<Callback>,
) -> (CookieJar, Redirect) {
    let refuse = |jar: CookieJar, why: &str| (jar, Redirect::to(&format!("/login?error={why}")));
    // Nothing counts, and nothing is cleared, unless it answers this browser's login:
    // a stray link to the callback must not cancel a sign-in in progress.
    let Some(pending) = pending_login(&jar, q.state.as_deref()) else {
        return refuse(jar, "expired");
    };
    let jar = jar.remove(Cookie::build(LOGIN_COOKIE).path(LOGIN_COOKIE_PATH));
    if !(0..=LOGIN_TTL_SECS).contains(&(unix_now() - pending.started)) {
        return refuse(jar, "expired");
    }
    if let Some(error) = &q.error {
        let error: String = error.chars().take(64).collect();
        tracing::warn!(error = ?error, "login refused by the provider");
        return refuse(jar, "cancelled");
    }
    match complete(&state, jar.clone(), pending, q.code).await {
        Ok(done) => done,
        Err(e) => {
            let why = match e {
                ApiError::Forbidden => "forbidden",
                ApiError::BadRequest(_) => "expired",
                ApiError::NotFound => "unavailable",
                e => {
                    tracing::error!(error = %e, "login failed");
                    "failed"
                }
            };
            refuse(jar, why)
        }
    }
}

/// This browser's login, if `state` is its (stale or not).
fn pending_login(jar: &CookieJar, state: Option<&str>) -> Option<Pending> {
    jar.get(LOGIN_COOKIE)
        .and_then(|c| URL_SAFE_NO_PAD.decode(c.value()).ok())
        .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
        .filter(|p| state.is_some_and(|s| bool::from(p.state.as_bytes().ct_eq(s.as_bytes()))))
}

async fn complete(
    state: &AppState,
    jar: CookieJar,
    pending: Pending,
    code: Option<String>,
) -> Result<(CookieJar, Redirect), ApiError> {
    let nonce = Nonce::new(pending.nonce);

    let client = state.oidc.client(state).await?;
    let refused = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(error = %e, "login refused: {what}");
        ApiError::Forbidden
    };
    let exchange = client
        .exchange_code(AuthorizationCode::new(code.ok_or_else(|| {
            ApiError::BadRequest("no code from the provider".into())
        })?))
        .map_err(|e| refused("no token endpoint", &e))?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.verifier))
        .request_async(&state.http)
        .await;
    let response = match exchange {
        Ok(r) => r,
        // Unreachable: the provider may have moved its endpoints. Anything it answered
        // (a refused made-up code, in whatever shape) must not flush the cache: anyone
        // can cause that.
        Err(e @ RequestTokenError::Request(_)) => {
            state.oidc.forget().await;
            return Err(refused("token exchange", &e));
        }
        Err(e) => return Err(refused("token exchange", &e)),
    };
    let id_token = response
        .id_token()
        .ok_or_else(|| refused("no ID token", &"missing"))?;
    let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(claims) => claims.clone(),
        Err(_) => {
            // Perhaps signed with a key newer than the cached ones: once more, fresh.
            state.oidc.forget().await;
            let fresh = state.oidc.client(state).await?;
            id_token
                .claims(&fresh.id_token_verifier(), &nonce)
                .map_err(|e| refused("ID token", &e))?
                .clone()
        }
    };
    let subject = claims.subject().as_str();
    // An unverified email never matches anyone.
    let email = claims
        .email()
        .filter(|_| claims.email_verified() == Some(true))
        .map(|e| e.as_str());

    let user_id = global_admin(state, subject, email).await?;
    let token = session::create(
        &state.db,
        user_id,
        session::Method::Oidc,
        session::Stage::Full,
    )
    .await?;
    audit::record(
        &state.db,
        Some(user_id),
        "login",
        format!("app_user/{user_id}"),
        json!({ "issuer": config(state)?.issuer }),
    )
    .await?;
    let cookie = session::cookie(token, state.config.secure_cookies());
    Ok((jar.add(cookie), Redirect::to("/")))
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn time_secs(secs: i64) -> time::Duration {
    time::Duration::seconds(secs)
}

/// The global admin this login is: by subject, or (first login) by verified email,
/// pinning the subject. Anyone else is refused.
async fn global_admin(
    state: &AppState,
    subject: &str,
    email: Option<&str>,
) -> Result<i64, ApiError> {
    let row = state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id, oidc_sub IS NULL AS unpinned FROM app_user
             WHERE tenant_id IS NULL AND disabled_at IS NULL
               AND (oidc_sub = $1 OR (oidc_sub IS NULL AND lower(email) = lower($2)))
             ORDER BY oidc_sub IS NULL LIMIT 1",
            [subject.into(), email.unwrap_or_default().into()],
        ))
        .await?;
    let Some(row) = row else {
        tracing::warn!(%subject, "login refused: not a global admin");
        return Err(ApiError::Forbidden);
    };
    let id: i64 = row.try_get("", "id")?;
    if row.try_get::<bool>("", "unpinned")? {
        state
            .db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE app_user SET oidc_sub = $1 WHERE id = $2 AND oidc_sub IS NULL",
                [subject.into(), id.into()],
            ))
            .await?;
    }
    Ok(id)
}

/// `POST /auth/logout`: ends the session if it is still there and clears the cookie
/// (also for a session that already went idle). A failure to end it is an error, not
/// a quiet success: the session would live on behind the user's back. No CSRF token:
/// the cookie is `SameSite=Lax`, so no other site can post with it.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), ApiError> {
    if let Some(cookie) = jar.get(session::COOKIE) {
        end_session(&state, cookie.value()).await?;
    }
    Ok((
        jar.remove(Cookie::build(session::COOKIE).path("/")),
        StatusCode::NO_CONTENT,
    ))
}

async fn end_session(state: &AppState, token: &str) -> Result<(), ApiError> {
    let txn = crate::api::begin(&state.db).await?;
    if let Some(user_id) = session::end(&txn, token).await? {
        audit::record(
            &txn,
            Some(user_id),
            "logout",
            format!("app_user/{user_id}"),
            json!({}),
        )
        .await?;
    }
    txn.commit().await?;
    Ok(())
}
