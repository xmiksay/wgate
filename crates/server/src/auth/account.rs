//! The guessing brakes in Postgres (they survive a restart): a lockout per account and
//! client, and a brake per account against guessing from many clients, which the
//! clients the account logged in from skip. An attempt is
//! claimed (counted) before its password is verified, atomically, so parallel guesses
//! cannot all slip past one check (`login_claim` in m0002).

use std::net::IpAddr;
use std::time::Duration;

use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
use serde_json::json;

use super::password::{self, BRAKE_AFTER, LOCK_AFTER, Password};
use super::{limit, session};
use crate::audit;
use crate::error::ApiError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    UnknownEmail,
    Disabled,
    NoPassword,
    /// This client is locked out of the account.
    Locked,
    /// The account takes one attempt a minute, and had it.
    Braked,
    /// Counted: verify the password, then [`succeeded`] if it matches.
    Claimed,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownEmail => "unknown_email",
            Self::Disabled => "disabled",
            Self::NoPassword => "no_password",
            Self::Locked => "locked",
            Self::Braked => "braked",
            Self::Claimed => "claimed",
        }
    }

    fn parse(s: &str) -> Result<Self, ApiError> {
        Ok(match s {
            "unknown_email" => Self::UnknownEmail,
            "disabled" => Self::Disabled,
            "no_password" => Self::NoPassword,
            "locked" => Self::Locked,
            "braked" => Self::Braked,
            "claimed" => Self::Claimed,
            other => return Err(anyhow::anyhow!("login_claim said {other}").into()),
        })
    }
}

pub struct Claim {
    pub account: Option<i64>,
    /// Only for a claimed attempt: anything else verifies against the dummy.
    pub hash: Option<String>,
    pub verdict: Verdict,
    /// This client's failures in a row, this one included.
    pub failures: Option<i32>,
    /// When this attempt locked the client out: until when.
    pub locked_until: Option<String>,
    /// Refused (locked, braked): how long until the next attempt is taken.
    pub wait: Option<Duration>,
}

/// One statement, the same for every email (known or not): the attempt from `ip`.
pub async fn claim(db: &DatabaseConnection, email: &str, ip: IpAddr) -> Result<Claim, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT account, hash, verdict, failures, lock_until::text AS lock_until, wait_secs
             FROM login_claim($1, $2::inet, $3, $4, $5)",
            [
                email.into(),
                limit::bucket(ip).to_string().into(),
                LOCK_AFTER.into(),
                password::lock_schedule().into(),
                BRAKE_AFTER.into(),
            ],
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("login_claim returned no row"))?;
    let wait: Option<i32> = row.try_get("", "wait_secs")?;
    Ok(Claim {
        account: row.try_get("", "account")?,
        hash: row.try_get("", "hash")?,
        verdict: Verdict::parse(&row.try_get::<String>("", "verdict")?)?,
        failures: row.try_get("", "failures")?,
        locked_until: row.try_get("", "lock_until")?,
        wait: wait.map(|s| Duration::from_secs(u64::try_from(s.max(1)).unwrap_or(1))),
    })
}

/// The claimed attempt was right: it no longer counts, this client's failures start
/// over (other clients' stay), and the client is known to the account from now on.
pub async fn succeeded(db: &DatabaseConnection, id: i64, ip: IpAddr) -> Result<(), ApiError> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT login_succeeded($1, $2::inet)",
        [id.into(), limit::bucket(ip).to_string().into()],
    ))
    .await?;
    Ok(())
}

/// Whether the account of `email` logged in from `ip`'s client lately (then the
/// account-wide brake and the wide limit do not hold it up).
pub async fn known(db: &DatabaseConnection, email: &str, ip: IpAddr) -> Result<bool, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT EXISTS (SELECT FROM login_known k JOIN app_user a ON a.id = k.user_id
                            WHERE lower(a.email) = lower($1) AND k.client = $2::inet
                              AND k.last_ok_at > now() - interval '30 days') AS known",
            [email.into(), limit::bucket(ip).to_string().into()],
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no row"))?;
    Ok(row.try_get("", "known")?)
}

/// Stores a new hash; `false` if there is no such account.
pub async fn store<C: ConnectionTrait>(db: &C, id: i64, hash: String) -> Result<bool, ApiError> {
    Ok(db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE app_user SET password_hash = $2 WHERE id = $1",
            [id.into(), hash.into()],
        ))
        .await?
        .rows_affected()
        == 1)
}

/// `wgate user password <email>`: sets the password, clears every lockout, the brake
/// and the known clients, and ends the account's sessions (whoever had it before is
/// out, and so are the clients they used).
pub async fn set_password(
    db: &DatabaseConnection,
    email: &str,
    password: Password,
) -> Result<i64, ApiError> {
    password.check()?;
    let hasher = password::Hasher::new(1)?;
    let hash = password::hash_blocking(hasher.permit().await?, password).await?;
    let txn = db.begin().await?;
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE app_user SET password_hash = $2,
                 brake_since = NULL, brake_failures = 0, brake_last_at = NULL
             WHERE lower(email) = lower($1) RETURNING id",
            [email.into(), hash.into()],
        ))
        .await?
        .ok_or_else(|| ApiError::invalid(format!("no account with email {email}")))?;
    let id: i64 = row.try_get("", "id")?;
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "WITH known AS (DELETE FROM login_known WHERE user_id = $1)
         DELETE FROM login_failure WHERE user_id = $1",
        [id.into()],
    ))
    .await?;
    let ended = session::end_others(&txn, id, None).await?;
    audit::record(
        &txn,
        None,
        "user.password.set",
        format!("app_user/{id}"),
        json!({ "via": "cli", "ended_sessions": ended }),
    )
    .await?;
    txn.commit().await?;
    Ok(id)
}
