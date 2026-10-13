//! The global admins' login: OpenID Connect authorization code with PKCE. A login
//! matches a global admin by the issuer's subject, or the first time by their verified
//! email (which then pins the subject: an email changed at the IdP takes nothing over).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::Deserialize;
use serde_json::json;

use super::{Actor, session};
use crate::audit;
use crate::error::ApiError;
use crate::state::AppState;

/// Between the redirect and the callback.
const LOGIN_TTL: &str = "10 minutes";

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

async fn client(state: &AppState) -> Result<Client, ApiError> {
    let oidc = &state.config.admin_oidc;
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

/// `GET /auth/login`: off to the provider.
pub async fn login(State(state): State<AppState>) -> Result<Redirect, ApiError> {
    let client = client(&state).await?;
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
    state
        .db
        .execute_raw(Statement::from_string(
            DbBackend::Postgres,
            format!("DELETE FROM login_state WHERE created_at < now() - interval '{LOGIN_TTL}'"),
        ))
        .await?;
    state
        .db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO login_state (state, nonce, pkce_verifier) VALUES ($1, $2, $3)",
            [
                csrf.secret().clone().into(),
                nonce.secret().clone().into(),
                verifier.secret().clone().into(),
            ],
        ))
        .await?;
    Ok(Redirect::to(url.as_str()))
}

#[derive(Deserialize)]
pub struct Callback {
    code: String,
    state: String,
}

/// `GET /auth/callback`: back from the provider; a session for a global admin.
pub async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<Callback>,
) -> Result<(CookieJar, Redirect), ApiError> {
    // Taken once: a replayed callback finds nothing.
    let pending = state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "DELETE FROM login_state
                 WHERE state = $1 AND created_at > now() - interval '{LOGIN_TTL}'
                 RETURNING nonce, pkce_verifier"
            ),
            [q.state.into()],
        ))
        .await?
        .ok_or_else(|| ApiError::BadRequest("the login expired; start again".into()))?;
    let nonce: String = pending.try_get("", "nonce")?;
    let verifier: String = pending.try_get("", "pkce_verifier")?;

    let client = client(&state).await?;
    let refused = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(error = %e, "login refused: {what}");
        ApiError::Forbidden
    };
    let response = client
        .exchange_code(AuthorizationCode::new(q.code))
        .map_err(|e| refused("no token endpoint", &e))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&state.http)
        .await
        .map_err(|e| refused("token exchange", &e))?;
    let id_token = response
        .id_token()
        .ok_or_else(|| refused("no ID token", &"missing"))?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(nonce))
        .map_err(|e| refused("ID token", &e))?;
    let subject = claims.subject().as_str();
    // An unverified email never matches anyone.
    let email = claims
        .email()
        .filter(|_| claims.email_verified() == Some(true))
        .map(|e| e.as_str());

    let user_id = global_admin(&state, subject, email).await?;
    let token = session::create(&state.db, user_id).await?;
    audit::record(
        &state.db,
        Some(user_id),
        "login",
        format!("app_user/{user_id}"),
        json!({ "issuer": state.config.admin_oidc.issuer }),
    )
    .await?;
    let cookie = Cookie::build((session::COOKIE, token))
        .http_only(true)
        .secure(state.config.secure_cookies())
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time_secs(session::MAX_AGE_SECS))
        .build();
    Ok((jar.add(cookie), Redirect::to("/")))
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

/// `POST /auth/logout`.
pub async fn logout(
    State(state): State<AppState>,
    actor: Actor,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), ApiError> {
    if let Some(cookie) = jar.get(session::COOKIE) {
        session::end(&state.db, cookie.value()).await?;
    }
    tracing::info!(user = actor.user_id, "logged out");
    Ok((
        jar.remove(Cookie::build(session::COOKIE).path("/")),
        StatusCode::NO_CONTENT,
    ))
}
