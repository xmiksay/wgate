//! Invite and reset links, `<public_url>/account/<token>`: an admin makes one and is
//! shown it once (wgate sends no mail). 24 hours, single use, only the token's
//! SHA-256 is stored, and a new link voids the account's older unused ones. Following
//! one sets a password; a reset also ends the account's sessions and clears its
//! lockouts, the brake and the known clients, as `wgate user password` does.

use std::net::IpAddr;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;
use utoipa::ToSchema;

use super::local::{ClientIp, detached};
use super::password::{self, Password, Permit};
use super::{account, session};
use crate::audit;
use crate::error::ApiError;
use crate::state::AppState;

const TTL: &str = "24 hours";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// For an account without a password yet.
    Invite,
    Reset,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invite => "invite",
            Self::Reset => "reset",
        }
    }

    fn parse(s: &str) -> Result<Self, ApiError> {
        match s {
            "invite" => Ok(Self::Invite),
            "reset" => Ok(Self::Reset),
            other => Err(anyhow::anyhow!("account_token purpose {other}").into()),
        }
    }
}

/// A new link for account `id`, voiding its older unused ones: (url, expires_at,
/// how many were voided). The caller audits it, never the url.
pub async fn create<C: ConnectionTrait>(
    db: &C,
    public_url: &Url,
    id: i64,
    purpose: Purpose,
    by: i64,
) -> Result<(String, String, u64), ApiError> {
    let voided = account::void_links(db, id).await?;
    let token = session::random_token();
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "INSERT INTO account_token (user_id, token_hash, purpose, created_by, expires_at)
                 VALUES ($1, $2, $3, $4, now() + interval '{TTL}')
                 RETURNING to_char(expires_at AT TIME ZONE 'UTC',
                                   'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires_at"
            ),
            [
                id.into(),
                session::hash(&token).into(),
                purpose.as_str().into(),
                by.into(),
            ],
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no row"))?;
    let url = public_url
        .join(&format!("account/{token}"))
        .map_err(anyhow::Error::from)?;
    Ok((url.into(), row.try_get("", "expires_at")?, voided))
}

#[derive(Serialize, ToSchema)]
pub struct LinkInfo {
    /// The account the link is for.
    pub email: String,
    pub purpose: Purpose,
}

/// A live link's account and purpose; 404 for any other token (unknown, used,
/// expired, voided, or an invite for an account that has a password by now). Limited per client as login attempts are.
#[utoipa::path(
    get, path = "/auth/account/{token}", operation_id = "account_link", servers((url = "/")),
    params(("token" = String, Path)),
    responses(
        (status = 200, body = LinkInfo),
        (status = 404, body = crate::error::ErrorBody),
        (status = 429, body = crate::error::ErrorBody),
    )
)]
pub async fn info(
    State(s): State<AppState>,
    ip: ClientIp,
    Path(token): Path<String>,
) -> Result<Json<LinkInfo>, ApiError> {
    ip.attempt(&s, None).await?;
    Ok(Json(live(&s, &token).await?))
}

async fn live(s: &AppState, token: &str) -> Result<LinkInfo, ApiError> {
    let row =
        s.db.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT u.email, t.purpose FROM account_token t JOIN app_user u ON u.id = t.user_id
             WHERE t.token_hash = $1 AND t.used_at IS NULL AND t.expires_at > now()
               AND (t.purpose = 'reset' OR u.password_hash IS NULL)",
            [session::hash(token).into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(LinkInfo {
        email: row.try_get("", "email")?,
        purpose: Purpose::parse(&row.try_get::<String>("", "purpose")?)?,
    })
}

#[derive(Deserialize, ToSchema)]
pub struct NewPassword {
    /// 12 to 256 characters.
    #[schema(value_type = String)]
    pub password: Password,
}

/// Sets the account's password and uses the link up; a reset link also ends the
/// account's sessions and clears its lockouts. No session: log in next. 404 as for
/// the `GET`, 422 for a password out of bounds, 429/503 as for a login.
#[utoipa::path(
    post, path = "/auth/account/{token}", operation_id = "use_account_link",
    servers((url = "/")), params(("token" = String, Path)), request_body = NewPassword,
    responses(
        (status = 204, description = "The password is set"),
        (status = 404, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
        (status = 429, body = crate::error::ErrorBody),
        (status = 503, body = crate::error::ErrorBody),
    )
)]
pub async fn redeem(
    State(s): State<AppState>,
    ip: ClientIp,
    Path(token): Path<String>,
    Json(body): Json<NewPassword>,
) -> Result<StatusCode, ApiError> {
    body.password.check()?;
    ip.attempt(&s, None).await?;
    // A dead link costs no hash.
    live(&s, &token).await?;
    let permit = s.hasher.permit().await?;
    detached(set(s, ip.0, token, body.password, permit)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set(
    s: AppState,
    ip: IpAddr,
    token: String,
    password: Password,
    permit: Permit,
) -> Result<(), ApiError> {
    let hash = password::hash_blocking(permit, password).await?;
    let txn = crate::api::begin(&s.db).await?;
    // The account first (the lock order: app_user, then what hangs off it), so an
    // invite's "no password yet" holds until the password is stored.
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT u.id FROM account_token t JOIN app_user u ON u.id = t.user_id
         WHERE t.token_hash = $1 FOR UPDATE OF u",
        [session::hash(&token).into()],
    ))
    .await?;
    // Used up here, atomically: of two at once, one gets it.
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE account_token t SET used_at = now()
             FROM app_user u
             WHERE t.token_hash = $1 AND t.used_at IS NULL AND t.expires_at > now()
               AND u.id = t.user_id AND (t.purpose = 'reset' OR u.password_hash IS NULL)
             RETURNING t.user_id, t.purpose",
            [session::hash(&token).into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    let id: i64 = row.try_get("", "user_id")?;
    let purpose = Purpose::parse(&row.try_get::<String>("", "purpose")?)?;
    account::store(&txn, id, hash).await?;
    let ended = match purpose {
        Purpose::Reset => account::start_over(&txn, id).await?,
        Purpose::Invite => 0,
    };
    audit::record(
        &txn,
        Some(id),
        "user.password.set",
        format!("app_user/{id}"),
        json!({ "via": format!("{}_link", purpose.as_str()), "ip": ip.to_string(),
                "ended_sessions": ended }),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
