//! The signed-in account's TOTP: set it up (also in the `enrol` stage, which a
//! confirmed setup finishes), remove it, and regenerate the recovery codes. The
//! secret leaves the server only in the setup's answer; the recovery codes only in
//! the answer that makes them.

use std::net::IpAddr;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use super::begin;
use super::me::target;
use crate::audit;
use crate::auth::factor::{self, Check, Secret};
use crate::auth::local::{ClientIp, detached};
use crate::auth::password::{Password, Permit};
use crate::auth::session::{self, Stage};
use crate::auth::{Account, Actor, AnyStage, Role, account, totp};
use crate::error::ApiError;
use crate::state::AppState;
use crate::wgkey;

#[derive(Serialize, ToSchema)]
pub struct TotpSetup {
    /// For an authenticator app; holds the secret. Shown this once.
    pub otpauth_uri: String,
    /// The same as a QR code.
    pub qr_svg: String,
}

#[derive(Deserialize, ToSchema)]
pub struct TotpCode {
    /// The authenticator's 6 digits.
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryCodes {
    /// Ten single-use codes for when the authenticator is gone. Shown this once.
    pub recovery_codes: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct PasswordProof {
    /// The account's current password.
    #[schema(value_type = String)]
    pub password: Password,
}

/// A `full` session, or one that has to set TOTP up first.
fn setting_up(actor: AnyStage) -> Result<Actor, ApiError> {
    match actor.0.stage {
        Stage::Full | Stage::Enrol => Ok(actor.0),
        Stage::Totp => Err(ApiError::Unauthorized),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct SetupRequest {
    /// The current password; not needed right after a password login (the `enrol`
    /// stage of one).
    #[schema(value_type = Option<String>)]
    pub password: Option<Password>,
}

/// A new secret, pending until `/me/totp/confirm` (a pending one is replaced). In a
/// `full` session it takes the current password, counted like a login attempt as
/// for a password change (422 when wrong, then 429); the `enrol` stage sends no
/// body. 409 with TOTP on; 422 for an account without a password.
#[utoipa::path(
    post, path = "/me/totp/setup", operation_id = "setup_totp",
    request_body = Option<SetupRequest>,
    responses(
        (status = 200, body = TotpSetup),
        (status = 409, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
        (status = 429, body = crate::error::ErrorBody),
        (status = 503, body = crate::error::ErrorBody),
    )
)]
pub async fn setup(
    State(s): State<AppState>,
    ip: ClientIp,
    actor: AnyStage,
    body: axum::body::Bytes,
) -> Result<Json<TotpSetup>, ApiError> {
    // The enrol stage sends nothing, and a client may still label that empty body JSON.
    let body: Option<SetupRequest> = if body.is_empty() {
        None
    } else {
        let malformed = |_| ApiError::invalid("a malformed request body");
        Some(serde_json::from_slice(&body).map_err(malformed)?)
    };
    let actor = setting_up(actor)?;
    let id = actor.user_id;
    // Without the password only right after one: a session that was full (an old one
    // counted as `enrol`, or any signed-in one) gives it again.
    if actor.row_stage == Stage::Full {
        if factor::enabled(&s.db, id).await? {
            return Err(factor::already_on());
        }
        let password = body
            .and_then(|b| b.password)
            .ok_or_else(|| ApiError::invalid("the current password is required"))?;
        ip.attempt(&s, Some(&actor.email)).await?;
        let permit = s.hasher.permit().await?;
        let (s, actor) = (s.clone(), actor.clone());
        detached(async move {
            let wrong = "the password is wrong";
            account::recheck(
                &s.db,
                ip.0,
                &actor,
                "user.totp.setup.failed",
                wrong,
                async |c| {
                    let right = s.hasher.verify(permit, password, c.hash.clone()).await?;
                    Ok(right.then_some(()).ok_or("wrong_password"))
                },
            )
            .await
        })
        .await?;
    }
    let txn = begin(&s.db).await?;
    let secret = factor::start_setup(&txn, &s.key, id).await?;
    audit::record(&txn, Some(id), "user.totp.setup", target(id), json!({})).await?;
    txn.commit().await?;
    let otpauth_uri = totp::otpauth_uri(&secret, &actor.email);
    let qr_svg = wgkey::qr_svg(&otpauth_uri)
        .ok_or_else(|| anyhow::anyhow!("an otpauth URI too long for a QR code"))?;
    Ok(Json(TotpSetup {
        otpauth_uri,
        qr_svg,
    }))
}

/// Turns the pending secret on with one of its codes: the recovery codes. In the
/// `enrol` stage the session becomes `full` under a new cookie (audited as the
/// enrolment). 422 for a wrong code (or none pending); not counted as a login
/// attempt: it checks the secret the setup just handed out.
#[utoipa::path(
    post, path = "/me/totp/confirm", operation_id = "confirm_totp", request_body = TotpCode,
    responses(
        (status = 200, body = RecoveryCodes),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn confirm(
    State(s): State<AppState>,
    ip: ClientIp,
    jar: CookieJar,
    actor: AnyStage,
    Json(body): Json<TotpCode>,
) -> Result<(CookieJar, Json<RecoveryCodes>), ApiError> {
    let actor = setting_up(actor)?;
    let id = actor.user_id;
    let txn = begin(&s.db).await?;
    let check = factor::check_code(&txn, &s.key, id, &body.code, s.clock.now(), Secret::Pending);
    if check.await? != Check::Accepted {
        return Err(ApiError::invalid("the code is wrong"));
    }
    let recovery_codes = factor::new_recovery_codes(&txn, id).await?;
    let (token, action) = match actor.stage {
        Stage::Enrol => {
            let method = session::Method::PasswordTotp;
            // Expired meanwhile: nothing is turned on (the transaction rolls back).
            let token = session::upgrade(&txn, actor.session_id, method)
                .await?
                .ok_or(ApiError::Unauthorized)?;
            (Some(token), "user.totp.enrol")
        }
        _ => (None, "user.totp.enable"),
    };
    let ended = session::end_password_only(&txn, id, actor.session_id).await?;
    let detail = json!({ "ip": ip.0.to_string(), "method": actor.method, "ended_sessions": ended });
    audit::record(&txn, Some(id), action, target(id), detail).await?;
    txn.commit().await?;
    let jar = match token {
        Some(token) => jar.add(session::cookie(token, s.config.secure_cookies())),
        None => jar,
    };
    Ok((jar, Json(RecoveryCodes { recovery_codes })))
}

/// Needs the current password, counted like a login attempt as for a password
/// change (422 when wrong, then 429). Admins may not: they need TOTP (422). Removes
/// the recovery codes too.
#[utoipa::path(
    delete, path = "/me/totp", operation_id = "remove_totp", request_body = PasswordProof,
    responses(
        (status = 204, description = "TOTP is off"),
        (status = 422, body = crate::error::ErrorBody),
        (status = 429, body = crate::error::ErrorBody),
        (status = 503, body = crate::error::ErrorBody),
    )
)]
pub async fn remove(
    State(s): State<AppState>,
    ip: ClientIp,
    Account(actor): Account,
    Json(body): Json<PasswordProof>,
) -> Result<StatusCode, ApiError> {
    if actor.role != Role::User {
        return Err(ApiError::invalid("admins need TOTP"));
    }
    ip.attempt(&s, Some(&actor.email)).await?;
    let permit = s.hasher.permit().await?;
    detached(remove_with(s, ip.0, actor, body.password, permit)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_with(
    s: AppState,
    ip: IpAddr,
    actor: Actor,
    password: Password,
    permit: Permit,
) -> Result<(), ApiError> {
    let id = actor.user_id;
    let wrong = "the password is wrong";
    account::recheck(
        &s.db,
        ip,
        &actor,
        "user.totp.remove.failed",
        wrong,
        async |claim| {
            let right = s
                .hasher
                .verify(permit, password, claim.hash.clone())
                .await?;
            Ok(right.then_some(()).ok_or("wrong_password"))
        },
    )
    .await?;
    let txn = begin(&s.db).await?;
    factor::clear(&txn, id).await?;
    let detail = json!({ "ip": ip.to_string() });
    audit::record(&txn, Some(id), "user.totp.remove", target(id), detail).await?;
    txn.commit().await?;
    Ok(())
}

/// Needs a current TOTP code, counted like a login attempt (422 when wrong, then
/// 429): ten new recovery codes, the old ones void. 422 with TOTP off.
#[utoipa::path(
    post, path = "/me/recovery-codes", operation_id = "regenerate_recovery_codes",
    request_body = TotpCode,
    responses(
        (status = 200, body = RecoveryCodes),
        (status = 422, body = crate::error::ErrorBody),
        (status = 429, body = crate::error::ErrorBody),
    )
)]
pub async fn regenerate(
    State(s): State<AppState>,
    ip: ClientIp,
    Account(actor): Account,
    Json(body): Json<TotpCode>,
) -> Result<Json<RecoveryCodes>, ApiError> {
    if !factor::enabled(&s.db, actor.user_id).await? {
        return Err(ApiError::invalid("TOTP is off"));
    }
    ip.attempt(&s, Some(&actor.email)).await?;
    detached(regenerate_with(s, ip.0, actor, body.code))
        .await
        .map(Json)
}

async fn regenerate_with(
    s: AppState,
    ip: IpAddr,
    actor: Actor,
    code: String,
) -> Result<RecoveryCodes, ApiError> {
    let id = actor.user_id;
    let failed = "user.recovery_codes.failed";
    // The code is from when it was sent, not from after its wait.
    let now = s.clock.now();
    factor::wait_turn(&s.db, id).await?;
    account::recheck(&s.db, ip, &actor, failed, "the code is wrong", async |_| {
        let check = factor::check_code(&s.db, &s.key, id, &code, now, Secret::Enabled);
        Ok(check.await?.result())
    })
    .await?;
    let txn = begin(&s.db).await?;
    let recovery_codes = factor::new_recovery_codes(&txn, id).await?;
    let detail = json!({ "ip": ip.to_string() });
    audit::record(
        &txn,
        Some(id),
        "user.recovery_codes.new",
        target(id),
        detail,
    )
    .await?;
    txn.commit().await?;
    Ok(RecoveryCodes { recovery_codes })
}
