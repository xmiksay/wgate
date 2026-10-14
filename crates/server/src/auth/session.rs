//! Portal sessions: a random token in an `HttpOnly` cookie, only its SHA-256 in the
//! database. A session ends after 8 hours idle or 7 days, at logout, or as soon as
//! its user is disabled. Only a `full` session is signed in; the other stages
//! (plan 1.9) only finish their login.

use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, Value};
use sha2::{Digest, Sha256};

use super::{Actor, Role};
use crate::error::ApiError;

pub const COOKIE: &str = "wgate_session";
/// The hard cap, also the cookie's `Max-Age`.
pub const MAX_AGE_SECS: i64 = 7 * 24 * 3600;
const IDLE: &str = "8 hours";

/// 32 random bytes, URL-safe base64.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// How a session was made, for the audit log.
#[derive(Clone, Copy)]
pub enum Method {
    Password,
    Oidc,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Oidc => "oidc",
        }
    }
}

/// A new (`full`) session for `user_id`: the cookie's token.
pub async fn create(
    db: &DatabaseConnection,
    user_id: i64,
    method: Method,
) -> Result<String, ApiError> {
    let token = random_token();
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO session (token_hash, user_id, csrf, expires_at, method)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5)",
        [
            hash(&token).into(),
            user_id.into(),
            random_token().into(),
            (MAX_AGE_SECS as f64).into(),
            method.as_str().into(),
        ],
    ))
    .await?;
    Ok(token)
}

/// The session cookie carrying `token` (whichever way the login went).
pub fn cookie(token: String, secure: bool) -> Cookie<'static> {
    Cookie::build((COOKIE, token))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::seconds(MAX_AGE_SECS))
        .build()
}

/// Ends every session of `user_id` but `keep`; how many.
pub async fn end_others<C: ConnectionTrait>(
    db: &C,
    user_id: i64,
    keep: Option<i64>,
) -> Result<u64, ApiError> {
    Ok(db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM session WHERE user_id = $1 AND id IS DISTINCT FROM $2",
            [user_id.into(), keep.into()],
        ))
        .await?
        .rows_affected())
}

/// Whose session it was, if it was still there.
pub async fn end<C: ConnectionTrait>(db: &C, token: &str) -> Result<Option<i64>, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM session WHERE token_hash = $1 RETURNING user_id",
            [hash(token).into()],
        ))
        .await?;
    Ok(row.map(|r| r.try_get("", "user_id")).transpose()?)
}

/// The signed-in user of a live session, refreshing its idle clock; a dead session is
/// removed.
pub async fn lookup(db: &DatabaseConnection, token: &str) -> Result<Option<Actor>, ApiError> {
    let token_hash: Value = hash(token).into();
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT s.id, s.csrf, s.stage, u.id AS user_id, u.role, u.tenant_id, u.email,
                        s.expires_at > now() AND s.seen_at > now() - interval '{IDLE}'
                            AND u.disabled_at IS NULL AND t.disabled_at IS NULL AS live,
                        s.seen_at < now() - interval '1 minute' AS stale
                 FROM session s
                 JOIN app_user u ON u.id = s.user_id
                 LEFT JOIN tenant t ON t.id = u.tenant_id
                 WHERE s.token_hash = $1"
            ),
            [token_hash],
        ))
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id: i64 = row.try_get("", "id")?;
    let live: bool = row.try_get("", "live")?;
    let role = Role::parse(&row.try_get::<String>("", "role")?);
    let (true, Some(role)) = (live, role) else {
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM session WHERE id = $1",
            [id.into()],
        ))
        .await?;
        return Ok(None);
    };
    // Kept: the login it belongs to is still going.
    if row.try_get::<String>("", "stage")? != "full" {
        return Ok(None);
    }
    if row.try_get::<bool>("", "stale")? {
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE session SET seen_at = now() WHERE id = $1",
            [id.into()],
        ))
        .await?;
    }
    Ok(Some(Actor {
        session_id: id,
        user_id: row.try_get("", "user_id")?,
        role,
        tenant_id: row.try_get("", "tenant_id")?,
        email: row.try_get("", "email")?,
        csrf: row.try_get("", "csrf")?,
    }))
}
