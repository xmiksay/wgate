//! The email-first login: `POST /auth/options` says which methods the login page
//! offers, `POST /auth/password` signs in with a local password. Every failure gets
//! the same 401, costs the same argon2 verify, and is audited (without the password).
//! JSON only: a cross-site form cannot send `application/json` without a preflight,
//! so nobody can sign a browser into their own account.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use super::account::{self, Verdict};
use super::password::{Password, Permit};
use super::{limit, oidc, session};
use crate::audit;
use crate::error::ApiError;
use crate::state::AppState;

/// The client a request comes from ([`limit::client_ip`]).
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let ConnectInfo(peer) = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("no peer address (served without connect info)"))?;
        Ok(Self(limit::client_ip(
            peer,
            &parts.headers,
            &state.config.trusted_proxies,
        )))
    }
}

impl ClientIp {
    /// One attempt from this client at `email`'s account, if it has any left: its
    /// IPv6 site's limit (which a client the account knows skips), then its own. The
    /// site is counted first: what it refuses takes no client window, so it cannot
    /// churn everyone else's out of the table.
    pub async fn attempt(&self, state: &AppState, email: &str) -> Result<(), ApiError> {
        let over = |wait| {
            tracing::warn!(ip = %self.0, "login attempts over the limit");
            ApiError::TooManyAttempts(wait)
        };
        let (limiter, now) = (&state.limiter, Instant::now());
        // A client its own limit refuses anyway costs its site (and the lookups)
        // nothing: one host must not fill its whole /48.
        if let Some(wait) = limiter.client_full(self.0, now) {
            return Err(over(wait));
        }
        if let Err(wait) = limiter.check_site(self.0, now)
            && !(limiter.may_look_up(self.0, now)
                && account::known(&state.db, email, self.0).await?)
        {
            return Err(over(wait));
        }
        limiter.check(self.0, now).map_err(over)
    }
}

/// Runs an attempt's claim → verify → audit to the end on its own task: a client
/// that hangs up mid-verify must not leave a counted failure without its audit entry,
/// or a success without its reset.
pub async fn detached<T: Send + 'static>(
    work: impl Future<Output = Result<T, ApiError>> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::spawn(work).await.map_err(anyhow::Error::from)?
}

#[derive(Deserialize, ToSchema)]
pub struct OptionsRequest {
    #[allow(dead_code, reason = "tenants' own providers depend on it (plan 1.10)")]
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginOptions {
    /// Always offered.
    pub password: bool,
    /// Sign in through one of these at `GET /auth/oidc/{id}`.
    pub providers: Vec<ProviderOption>,
}

#[derive(Serialize, ToSchema)]
pub struct ProviderOption {
    /// Opaque: `admin` for the configured `[admin_oidc]` (later, database ids).
    pub id: String,
    /// For the button.
    pub name: String,
}

/// The same answer for every email for now (no tenant providers yet).
#[utoipa::path(
    post, path = "/auth/options", operation_id = "login_options", servers((url = "/")),
    request_body = OptionsRequest, responses((status = 200, body = LoginOptions))
)]
pub async fn options(
    State(s): State<AppState>,
    Json(_body): Json<OptionsRequest>,
) -> Json<LoginOptions> {
    let providers = s
        .config
        .admin_oidc
        .iter()
        .map(|o| ProviderOption {
            id: oidc::ADMIN_PROVIDER.into(),
            name: o.display_name(),
        })
        .collect();
    Json(LoginOptions {
        password: true,
        providers,
    })
}

#[derive(Deserialize, ToSchema)]
pub struct PasswordLogin {
    pub email: String,
    #[schema(value_type = String)]
    pub password: Password,
}

/// 204 with the session cookie, or 401 `invalid_credentials` for any failure; 429
/// (with `Retry-After`) after 20 attempts a minute from one client or 100 from one
/// IPv6 /48; 503 `busy` when every hashing slot stays taken for 2 s.
#[utoipa::path(
    post, path = "/auth/password", operation_id = "login_password", servers((url = "/")),
    request_body = PasswordLogin,
    responses(
        (status = 204, description = "Signed in: the session cookie is set"),
        (status = 401, body = crate::error::ErrorBody),
        (status = 429, body = crate::error::ErrorBody),
        (status = 503, body = crate::error::ErrorBody),
    )
)]
pub async fn login(
    State(s): State<AppState>,
    ip: ClientIp,
    jar: CookieJar,
    Json(body): Json<PasswordLogin>,
) -> Result<(CookieJar, StatusCode), ApiError> {
    let email = body.email.trim().to_owned();
    ip.attempt(&s, &email).await?;
    let permit = s.hasher.permit().await?;
    let secure = s.config.secure_cookies();
    let token = detached(attempt(s, ip.0, email, body.password, permit)).await?;
    Ok((
        jar.add(session::cookie(token, secure)),
        StatusCode::NO_CONTENT,
    ))
}

/// A session token, or the one refusal.
async fn attempt(
    s: AppState,
    ip: IpAddr,
    email: String,
    password: Password,
    permit: Permit,
) -> Result<String, ApiError> {
    // Every failure costs the same: this statement, one verify, one audit entry.
    let claim = account::claim(&s.db, &email, ip).await?;
    let claimed = claim.verdict == Verdict::Claimed;
    let right = s
        .hasher
        .verify(permit, password, claim.hash.clone())
        .await?;
    let mut detail = attempt_detail(&claim, ip);
    detail["email"] = audit_email(&email);
    if !email_like(&email) {
        detail["email_chars"] = json!(email.chars().count());
    }
    let target = claim
        .account
        .map_or_else(|| "app_user".into(), |id| format!("app_user/{id}"));
    let (Some(id), true, true) = (claim.account, claimed, right) else {
        detail["reason"] = json!(match claim.verdict {
            Verdict::Claimed => "wrong_password",
            v => v.as_str(),
        });
        audit::record(
            &s.db,
            claim.account,
            "login.password.failed",
            target,
            detail,
        )
        .await?;
        return Err(ApiError::InvalidCredentials);
    };
    account::succeeded(&s.db, id, ip).await?;
    let token = session::create(&s.db, id, session::Method::Password).await?;
    audit::record(&s.db, Some(id), "login.password.ok", target, detail).await?;
    Ok(token)
}

/// The audit's view of an attempt: the client, the failures in a row so far and, when
/// this one locked the client out, until when.
pub fn attempt_detail(claim: &account::Claim, ip: IpAddr) -> serde_json::Value {
    let mut d = json!({ "ip": ip.to_string() });
    if let Some(n) = claim.failures {
        d["failed_logins"] = json!(n);
    }
    if let Some(until) = &claim.locked_until {
        d["locked_until"] = json!(until);
    }
    d
}

/// People type their password into the email box: only something shaped like an
/// email is kept.
fn email_like(s: &str) -> bool {
    s.contains('@') && !s.chars().any(char::is_whitespace) && s.chars().count() <= 320
}

fn audit_email(s: &str) -> serde_json::Value {
    if email_like(s) {
        json!(s)
    } else {
        serde_json::Value::Null
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_email_shaped_login_is_audited() {
        assert_eq!(audit_email("u@acme.test"), json!("u@acme.test"));
        assert_eq!(
            audit_email("correct horse battery"),
            serde_json::Value::Null
        );
        assert_eq!(audit_email("hunter2hunter2"), serde_json::Value::Null);
        assert_eq!(audit_email("a@b c"), serde_json::Value::Null);
        assert_eq!(
            audit_email(&format!("{}@x", "a".repeat(320))),
            serde_json::Value::Null
        );
    }
}
