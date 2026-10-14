//! An admin's hand in another account's login: invite and reset links, and a TOTP
//! reset. Narrower than managing users: a tenant admin reaches only their tenant's
//! plain users, any admin account needs a global admin (or the CLI); nobody their
//! own (that is `/me`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

use super::begin;

use crate::audit;
use crate::auth::links::{self, Purpose};
use crate::auth::{Actor, Role, factor};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct AccountLink {
    /// `<public_url>/account/<token>`, for the account's owner. Shown this once.
    pub url: String,
    /// 24 hours from now (RFC 3339, UTC).
    pub expires_at: String,
}

/// Account `id`, locked (no link is made for an account whose password or role
/// changes meanwhile), if `actor` may reach it: whether it has a password.
pub(super) async fn reach(
    txn: &DatabaseTransaction,
    actor: &Actor,
    id: i64,
) -> Result<bool, ApiError> {
    reach_as(txn, actor, id, " FOR UPDATE").await
}

/// As [`reach`], for a read: nothing locked.
pub(super) async fn reach_read<C: ConnectionTrait>(
    db: &C,
    actor: &Actor,
    id: i64,
) -> Result<bool, ApiError> {
    reach_as(db, actor, id, "").await
}

async fn reach_as<C: ConnectionTrait>(
    db: &C,
    actor: &Actor,
    id: i64,
    lock: &str,
) -> Result<bool, ApiError> {
    if id == actor.user_id {
        return Err(ApiError::invalid("your own account: see /me"));
    }
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT tenant_id, role, password_hash IS NOT NULL AS password FROM app_user
                 WHERE id = $1{lock}"
            ),
            [id.into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    let tenant: Option<i64> = row.try_get("", "tenant_id")?;
    match (Role::parse(&row.try_get::<String>("", "role")?), tenant) {
        (Some(Role::User), Some(t)) => actor.tenant(t)?,
        _ => actor.global()?,
    }
    Ok(row.try_get("", "password")?)
}

/// A link to set the first password of an account that has none (409 if it has
/// one: send a reset link). Voids the account's older links. 403 out of reach (a
/// tenant admin: their tenant's plain users only), 422 for your own account.
#[utoipa::path(
    post, path = "/users/{id}/invite", operation_id = "invite_user",
    responses(
        (status = 200, body = AccountLink),
        (status = 403, body = crate::error::ErrorBody),
        (status = 404, body = crate::error::ErrorBody),
        (status = 409, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn invite(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<AccountLink>, ApiError> {
    link(s, actor, id, Purpose::Invite).await
}

/// A link to set a new password; following it also ends the account's sessions and
/// clears its lockouts. Voids the account's older links. 403/404/422 as for an
/// invite.
#[utoipa::path(
    post, path = "/users/{id}/reset", operation_id = "reset_user_password",
    responses(
        (status = 200, body = AccountLink),
        (status = 403, body = crate::error::ErrorBody),
        (status = 404, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn reset(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<AccountLink>, ApiError> {
    link(s, actor, id, Purpose::Reset).await
}

async fn link(
    s: AppState,
    actor: Actor,
    id: i64,
    purpose: Purpose,
) -> Result<Json<AccountLink>, ApiError> {
    let txn = begin(&s.db).await?;
    let has_password = reach(&txn, &actor, id).await?;
    if purpose == Purpose::Invite && has_password {
        return Err(ApiError::Conflict(
            "this account has a password: send a reset link".into(),
        ));
    }
    let (url, expires_at, voided) =
        links::create(&txn, &s.config.public_url, id, purpose, actor.user_id).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        &format!("user.{}_link", purpose.as_str()),
        format!("app_user/{id}"),
        json!({ "expires_at": expires_at, "voided": voided }),
    )
    .await?;
    txn.commit().await?;
    Ok(Json(AccountLink { url, expires_at }))
}

/// Turns the account's TOTP off (with its recovery codes) and ends its sessions: its
/// next password login sets TOTP up again (an admin's must). 403/404/422 as for an
/// invite.
#[utoipa::path(
    post, path = "/users/{id}/totp-reset", operation_id = "reset_user_totp",
    responses(
        (status = 204, description = "TOTP is off; the account's sessions are over"),
        (status = 403, body = crate::error::ErrorBody),
        (status = 404, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn totp_reset(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let txn = begin(&s.db).await?;
    reach(&txn, &actor, id).await?;
    factor::reset(&txn, id, Some(actor.user_id), "api").await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `wgate user totp-reset <email>`, as [`totp_reset`].
pub async fn totp_reset_cli<C: ConnectionTrait>(db: &C, email: &str) -> Result<i64, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM app_user WHERE lower(email) = lower($1) FOR UPDATE",
            [email.into()],
        ))
        .await?
        .ok_or_else(|| ApiError::invalid(format!("no account with email {email}")))?;
    let id: i64 = row.try_get("", "id")?;
    factor::reset(db, id, None, "cli").await?;
    Ok(id)
}
