//! Portal sessions: a random token in an `HttpOnly` cookie, only its SHA-256 in the
//! database. A session ends after 8 hours idle or 7 days, at logout, or as soon as
//! its user is disabled. Only a `full` session is signed in; `totp` (5 minutes) and
//! `enrol` (30 minutes) only finish their login, and the session's token is replaced
//! when they do (a token seen before the login was done never becomes a full one).

use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, Value};
use sha2::{Digest, Sha256};

use serde::Serialize;
use utoipa::ToSchema;

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

/// What is stored of a token (sessions, invite and reset links).
pub fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// How a session was made, for the audit log; an OIDC session names its provider
/// (`session.provider_id`) and ends with it.
#[derive(Clone, Copy)]
pub enum Method {
    Password,
    PasswordTotp,
    Oidc(i64),
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PasswordTotp => "password_totp",
            Self::Oidc(_) => "oidc",
        }
    }

    fn provider(self) -> Option<i64> {
        match self {
            Self::Oidc(p) => Some(p),
            _ => None,
        }
    }
}

/// How far a login got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Signed in: everything the role allows.
    Full,
    /// The password was right; a TOTP or recovery code (`POST /auth/totp`) is next.
    Totp,
    /// An admin with a password and no TOTP: setting it up is next.
    Enrol,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Totp => "totp",
            Self::Enrol => "enrol",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::Full, Self::Totp, Self::Enrol]
            .into_iter()
            .find(|v| v.as_str() == s)
    }

    /// How long a session in this stage lasts.
    fn ttl_secs(self) -> i64 {
        match self {
            Self::Full => MAX_AGE_SECS,
            Self::Totp => 5 * 60,
            // Long enough to install an authenticator app.
            Self::Enrol => 30 * 60,
        }
    }
}

/// A new session for `user_id` in `stage`: the cookie's token.
pub async fn create(
    db: &DatabaseConnection,
    user_id: i64,
    method: Method,
    stage: Stage,
) -> Result<String, ApiError> {
    let token = random_token();
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO session (token_hash, user_id, csrf, expires_at, method, provider_id, stage)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5, $6, $7)",
        [
            hash(&token).into(),
            user_id.into(),
            random_token().into(),
            (stage.ttl_secs() as f64).into(),
            method.as_str().into(),
            method.provider().into(),
            stage.as_str().into(),
        ],
    ))
    .await?;
    Ok(token)
}

/// The login of session `id` is done: it becomes `full`, made by `method`, under a
/// new token, which this returns; `None` if it is gone or expired meanwhile (a
/// `totp` row that ran out while its code waited its turn stays dead). A row that was `full`
/// already (an admin's old password session, see [`lookup`]) keeps its expiry: no
/// upgrade outlives the cap of the login it came from.
pub async fn upgrade<C: ConnectionTrait>(
    db: &C,
    id: i64,
    method: Method,
) -> Result<Option<String>, ApiError> {
    let token = random_token();
    let done = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE session SET token_hash = $2, stage = 'full', method = $3, provider_id = $5,
                 expires_at = CASE WHEN stage = 'full' THEN expires_at
                                   ELSE now() + make_interval(secs => $4) END,
                 seen_at = now()
             WHERE id = $1 AND expires_at > now()",
            [
                id.into(),
                hash(&token).into(),
                method.as_str().into(),
                (MAX_AGE_SECS as f64).into(),
                method.provider().into(),
            ],
        ))
        .await?
        .rows_affected();
    Ok((done == 1).then_some(token))
}

/// Ends `user_id`'s sessions made by a password alone but `keep`: TOTP is on now.
pub async fn end_password_only<C: ConnectionTrait>(
    db: &C,
    user_id: i64,
    keep: i64,
) -> Result<u64, ApiError> {
    Ok(db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM session WHERE user_id = $1 AND id <> $2 AND method = 'password'",
            [user_id.into(), keep.into()],
        ))
        .await?
        .rows_affected())
}

/// Ends session `id`.
pub async fn end_id<C: ConnectionTrait>(db: &C, id: i64) -> Result<(), ApiError> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM session WHERE id = $1",
        [id.into()],
    ))
    .await?;
    Ok(())
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

/// The user of a live session (in any stage), refreshing its idle clock; a dead
/// session is removed (so is one made through a provider disabled since: disabling
/// ends them, and this catches a login that raced it). An admin's `full` session
/// made by a password alone (from before TOTP was mandatory) is in the `enrol` stage
/// while TOTP is off, and over once it is on (set up in another session).
pub async fn lookup(db: &DatabaseConnection, token: &str) -> Result<Option<Actor>, ApiError> {
    let token_hash: Value = hash(token).into();
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "SELECT s.id, s.csrf, s.stage, s.method, u.id AS user_id, u.role, u.tenant_id,
                        u.email, u.totp_enabled_at IS NOT NULL AS totp,
                        s.expires_at > now() AND s.seen_at > now() - interval '{IDLE}'
                            AND u.disabled_at IS NULL AND t.disabled_at IS NULL
                            AND p.disabled_at IS NULL AS live,
                        s.seen_at < now() - interval '1 minute' AS stale
                 FROM session s
                 JOIN app_user u ON u.id = s.user_id
                 LEFT JOIN tenant t ON t.id = u.tenant_id
                 LEFT JOIN oidc_provider p ON p.id = s.provider_id
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
    let stage = Stage::parse(&row.try_get::<String>("", "stage")?);
    let (true, Some(role), Some(row_stage)) = (live, role, stage) else {
        end_id(db, id).await?;
        return Ok(None);
    };
    let method: String = row.try_get("", "method")?;
    let mut stage = row_stage;
    if row_stage == Stage::Full && role != Role::User && method == Method::Password.as_str() {
        if row.try_get::<bool>("", "totp")? {
            end_id(db, id).await?;
            return Ok(None);
        }
        stage = Stage::Enrol;
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
        stage,
        row_stage,
        method,
    }))
}
