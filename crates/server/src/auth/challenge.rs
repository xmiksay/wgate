//! `POST /auth/totp`: the second step of a password login to an account with TOTP
//! on. A code (or a recovery code) is claimed like a password attempt: it counts
//! toward the client's lockout and the account's brake, and every failure is the same
//! 401, audited. The password's own claim is still counted
//! ([`account::password_only`]): logging in with the password again resets nothing,
//! so guesses at the code lock the client out as guesses at the password do. On top,
//! the account paces code attempts from all clients together
//! ([`factor::wait_turn`]).

use std::net::IpAddr;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

use super::account::{self, Verdict};
use super::factor::{self, Secret};
use super::local::{ClientIp, detached};
use super::session::{self, Stage};
use super::{Actor, AnyStage};
use crate::audit;
use crate::error::ApiError;
use crate::state::AppState;

/// One of the two.
#[derive(Deserialize, ToSchema)]
pub struct TotpLogin {
    /// The authenticator's 6 digits.
    pub code: Option<String>,
    /// One of the account's recovery codes, instead (each works once).
    pub recovery_code: Option<String>,
}

enum Factor {
    Code(String),
    Recovery(String),
}

/// Only for a session in the `totp` stage (5 minutes from the password), with its
/// `X-CSRF-Token` (from `GET /api/v1/session`). 204 with a new session cookie for the
/// now `full` session; 401 `invalid_credentials` for any failure (the session stays
/// for another try until it expires, or until the client is locked out: then it
/// ends), 401 `unauthorized` without such a session; 400 unless exactly one of
/// `code` and `recovery_code`; 403 without the CSRF token; 429 (with `Retry-After`)
/// as for `/auth/password`, or when the account's next code attempt is more than
/// 30 s away (attempts since the last right code are spaced out: the first two at
/// once, then 1 s, 2 s, 4 s, … at most 5 minutes apart; a reply may take up to 30 s).
#[utoipa::path(
    post, path = "/auth/totp", operation_id = "login_totp", servers((url = "/")),
    request_body = TotpLogin,
    responses(
        (status = 204, description = "Signed in: a new session cookie is set"),
        (status = 400, body = crate::error::ErrorBody),
        (status = 401, body = crate::error::ErrorBody),
        (status = 403, body = crate::error::ErrorBody),
        (status = 429, body = crate::error::ErrorBody),
    )
)]
pub async fn login(
    State(s): State<AppState>,
    ip: ClientIp,
    jar: CookieJar,
    AnyStage(actor): AnyStage,
    Json(body): Json<TotpLogin>,
) -> Result<(CookieJar, StatusCode), ApiError> {
    if actor.stage != Stage::Totp {
        return Err(ApiError::Unauthorized);
    }
    let factor = match (body.code, body.recovery_code) {
        (Some(c), None) => Factor::Code(c),
        (None, Some(r)) => Factor::Recovery(r),
        _ => {
            return Err(ApiError::BadRequest(
                "send either code or recovery_code".into(),
            ));
        }
    };
    ip.attempt(&s, Some(&actor.email)).await?;
    let secure = s.config.secure_cookies();
    let token = detached(attempt(s, ip.0, actor, factor)).await?;
    Ok((
        jar.add(session::cookie(token, secure)),
        StatusCode::NO_CONTENT,
    ))
}

async fn attempt(
    s: AppState,
    ip: IpAddr,
    actor: Actor,
    factor: Factor,
) -> Result<String, ApiError> {
    let id = actor.user_id;
    // The code is from when it was sent, not from after its wait.
    let now = s.clock.now();
    factor::wait_turn(&s.db, id).await?;
    let claim = account::claim(&s.db, &actor.email, ip).await?;
    let mut detail = claim.detail(ip);
    let mut outcome = Err(claim.verdict.as_str());
    if claim.verdict == Verdict::Claimed && claim.account == Some(id) {
        outcome = match &factor {
            Factor::Code(code) => {
                detail["via"] = json!("code");
                factor::check_code(&s.db, &s.key, id, code, now, Secret::Enabled)
                    .await?
                    .result()
            }
            Factor::Recovery(code) => {
                detail["via"] = json!("recovery_code");
                match factor::use_recovery_code(&s.db, id, code).await? {
                    Some(left) => {
                        detail["recovery_codes_left"] = json!(left);
                        Ok(())
                    }
                    None => Err("wrong_recovery_code"),
                }
            }
        };
    }
    let target = format!("app_user/{id}");
    if let Err(reason) = outcome {
        detail["reason"] = json!(reason);
        // Locked out: back to the password, which is refused until the lockout ends.
        if claim.locked_until.is_some() || claim.verdict == Verdict::Locked {
            session::end_id(&s.db, actor.session_id).await?;
        }
        audit::record(&s.db, Some(id), "login.totp.failed", target, detail).await?;
        return Err(ApiError::InvalidCredentials);
    }
    // The session first: one that ran out while the code waited its turn is not
    // signed in, and the claims stay counted (audited as such).
    let method = session::Method::PasswordTotp;
    let Some(token) = session::upgrade(&s.db, actor.session_id, method).await? else {
        detail["reason"] = json!("expired");
        audit::record(&s.db, Some(id), "login.totp.failed", target, detail).await?;
        return Err(ApiError::Unauthorized);
    };
    account::second_succeeded(&s.db, id, ip).await?;
    audit::record(&s.db, Some(id), "login.totp.ok", target, detail).await?;
    Ok(token)
}
