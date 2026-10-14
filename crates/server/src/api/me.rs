//! The signed-in account's own profile, whatever its role.

use std::net::IpAddr;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

use super::begin;
use crate::audit;
use crate::auth::local::{ClientIp, detached};
use crate::auth::password::{self, Password, Permit};
use crate::auth::{Account, Actor, account, session};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
pub struct PasswordChange {
    #[schema(value_type = String)]
    pub current: Password,
    /// 12 to 256 characters.
    #[schema(value_type = String)]
    pub new: Password,
}

/// Needs the current password. A wrong one counts like a failed login from this
/// client: 422 while attempts remain, then 429 (with `Retry-After`) during the
/// lockout. 422 for an account without a password, 503 `busy` as for a login. Ends
/// every other session of the account.
#[utoipa::path(
    post, path = "/me/password", operation_id = "change_password",
    request_body = PasswordChange,
    responses(
        (status = 204, description = "Changed; the other sessions are over"),
        (status = 422, body = crate::error::ErrorBody),
        (status = 429, body = crate::error::ErrorBody),
        (status = 503, body = crate::error::ErrorBody),
    )
)]
pub async fn change_password(
    State(s): State<AppState>,
    ip: ClientIp,
    Account(actor): Account,
    Json(body): Json<PasswordChange>,
) -> Result<StatusCode, ApiError> {
    body.new.check()?;
    ip.attempt(&s, Some(&actor.email)).await?;
    let permit = s.hasher.permit().await?;
    detached(change(s, ip.0, actor, body, permit)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn change(
    s: AppState,
    ip: IpAddr,
    actor: Actor,
    body: PasswordChange,
    permit: Permit,
) -> Result<(), ApiError> {
    let id = actor.user_id;
    let wrong = "the current password is wrong";
    account::recheck(
        &s.db,
        ip,
        &actor,
        "user.password.failed",
        wrong,
        async |claim| {
            let right = s
                .hasher
                .verify(permit, body.current, claim.hash.clone())
                .await?;
            Ok(right.then_some(()).ok_or("wrong_password"))
        },
    )
    .await?;
    let hash = password::hash_blocking(s.hasher.permit().await?, body.new).await?;
    let txn = begin(&s.db).await?;
    account::store(&txn, id, hash).await?;
    let ended = session::end_others(&txn, id, Some(actor.session_id)).await?;
    audit::record(
        &txn,
        Some(id),
        "user.password.change",
        target(id),
        json!({ "ended_sessions": ended, "ip": ip.to_string() }),
    )
    .await?;
    txn.commit().await.map_err(ApiError::from)
}

pub(super) fn target(id: i64) -> String {
    format!("app_user/{id}")
}
