//! The second factor in the database: the sealed TOTP secret (pending until a code
//! confirms it), the last step a code was accepted for, the account-wide pace of code
//! attempts, and the recovery codes. Columns read and written in SQL only, as the
//! password hash.

use std::time::Duration;

use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
use serde_json::json;
use zeroize::Zeroizing;

use super::{session, totp};
use crate::audit;
use crate::error::ApiError;
use crate::seal::{Place, SecretKey};

fn place(id: i64) -> Place<'static> {
    Place {
        table: "app_user",
        column: "totp_secret",
        id,
    }
}

/// An attempt further off than this is refused (429), not kept waiting: a bounded
/// number of requests sleep per account.
const MAX_WAIT_SECS: f64 = 30.0;
/// Gaps between an account's code attempts, by how many it had since its last right
/// code: the first two go at once, then 1 s, doubling, at most 5 minutes.
const MAX_GAP_SECS: i64 = 300;

pub fn gap_schedule() -> Vec<i64> {
    let mut out = vec![0];
    let mut gap = 1;
    while gap < MAX_GAP_SECS {
        out.push(gap);
        gap *= 2;
    }
    out.push(MAX_GAP_SECS);
    out
}

/// Takes the account's next slot for a code attempt (TOTP or recovery), whichever
/// client asks: reserved up front and counted as wrong until a right code resets the
/// pace, so parallel attempts queue instead of all being checked at once. Then waits
/// for it, holding no connection, transaction or permit; 429 if it is more than
/// [`MAX_WAIT_SECS`] away (nothing reserved then). Run detached, as the attempt it
/// belongs to.
pub async fn wait_turn(db: &DatabaseConnection, id: i64) -> Result<(), ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "WITH cur AS (
                 SELECT id, totp_wrong AS n,
                        greatest(now(), coalesce(totp_next_at, now())) AS slot
                 FROM app_user WHERE id = $1 FOR UPDATE),
             taken AS (
                 UPDATE app_user a SET totp_wrong = least(cur.n + 1, 1000000),
                     totp_next_at = cur.slot + make_interval(
                         secs => ($2::bigint[])[least(cur.n + 1, cardinality($2::bigint[]))])
                 FROM cur
                 WHERE a.id = cur.id AND cur.slot <= now() + make_interval(secs => $3)
                 RETURNING a.id)
             SELECT extract(epoch FROM cur.slot - now())::float8 AS wait,
                    EXISTS (SELECT FROM taken) AS taken
             FROM cur",
            [id.into(), gap_schedule().into(), MAX_WAIT_SECS.into()],
        ))
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let wait: f64 = row.try_get("", "wait")?;
    if !row.try_get::<bool>("", "taken")? {
        return Err(ApiError::TooManyAttempts(Duration::from_secs_f64(
            (wait - MAX_WAIT_SECS).max(1.0),
        )));
    }
    if wait > 0.0 {
        tokio::time::sleep(Duration::from_secs_f64(wait)).await;
    }
    Ok(())
}

/// Which secret a code is checked against.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Secret {
    /// The one in use.
    Enabled,
    /// One being set up: a right code turns it on.
    Pending,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    Accepted,
    Wrong,
    /// Right, but its step (or a later one) was used already.
    Replayed,
}

impl Check {
    /// `Err` with the audit's reason unless accepted.
    pub fn result(&self) -> Result<(), &'static str> {
        match self {
            Self::Accepted => Ok(()),
            Self::Wrong => Err("wrong_code"),
            Self::Replayed => Err("replayed_code"),
        }
    }
}

/// Whether the account has TOTP on.
pub async fn enabled<C: ConnectionTrait>(db: &C, id: i64) -> Result<bool, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT totp_enabled_at IS NOT NULL AS on FROM app_user WHERE id = $1",
            [id.into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(row.try_get("", "on")?)
}

pub fn already_on() -> ApiError {
    ApiError::Conflict("TOTP is on already; remove it first".into())
}

/// A new pending secret, replacing a pending one: what the QR code shows. Refused
/// once TOTP is on (409) and for an account without a password (422: TOTP guards
/// password logins only; a provider does its own).
pub async fn start_setup<C: ConnectionTrait>(
    db: &C,
    key: &SecretKey,
    id: i64,
) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT password_hash IS NOT NULL AS password, totp_enabled_at IS NOT NULL AS on
             FROM app_user WHERE id = $1 FOR UPDATE",
            [id.into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    if row.try_get::<bool>("", "on")? {
        return Err(already_on());
    }
    if !row.try_get::<bool>("", "password")? {
        return Err(ApiError::invalid(
            "TOTP protects a password login, and this account has no password",
        ));
    }
    let secret = totp::new_secret();
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE app_user SET totp_secret = $2, totp_last_step = NULL WHERE id = $1",
        [id.into(), key.seal(place(id), &secret)?.into()],
    ))
    .await?;
    Ok(secret)
}

/// Checks `code` against the account's `which` secret at `now` (Unix seconds). An
/// accepted code uses up its step: neither it nor an earlier one is taken again. A
/// right code for a pending secret turns TOTP on.
pub async fn check_code<C: ConnectionTrait>(
    db: &C,
    key: &SecretKey,
    id: i64,
    code: &str,
    now: i64,
    which: Secret,
) -> Result<Check, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT totp_secret FROM app_user
             WHERE id = $1 AND (totp_enabled_at IS NOT NULL) = $2",
            [id.into(), (which == Secret::Enabled).into()],
        ))
        .await?;
    let Some(blob) = row
        .map(|r| r.try_get::<Option<Vec<u8>>>("", "totp_secret"))
        .transpose()?
        .flatten()
    else {
        return Ok(Check::Wrong);
    };
    // Not a 500: the attempt is claimed already and must reach its audit entry.
    let secret = match key.open(place(id), &blob) {
        Ok(secret) => secret,
        Err(e) => {
            tracing::error!(error = %e, "a TOTP secret does not open (another secret_key?)");
            return Ok(Check::Wrong);
        }
    };
    let Some(step) = totp::matching_step(&secret, code, now) else {
        return Ok(Check::Wrong);
    };
    // The same blob: a setup started meanwhile has a new secret this code is not for.
    let sql = match which {
        Secret::Enabled => {
            "UPDATE app_user SET totp_last_step = $2, totp_wrong = 0, totp_next_at = NULL
             WHERE id = $1 AND totp_secret = $3 AND totp_enabled_at IS NOT NULL
               AND (totp_last_step IS NULL OR totp_last_step < $2)"
        }
        Secret::Pending => {
            "UPDATE app_user SET totp_last_step = $2, totp_enabled_at = now(), totp_wrong = 0,
                 totp_next_at = NULL
             WHERE id = $1 AND totp_secret = $3 AND totp_enabled_at IS NULL
               AND (totp_last_step IS NULL OR totp_last_step < $2)"
        }
    };
    let taken = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            [id.into(), step.into(), blob.into()],
        ))
        .await?
        .rows_affected();
    Ok(if taken == 1 {
        Check::Accepted
    } else {
        Check::Replayed
    })
}

/// Ten new recovery codes, the old ones void: what to show, once.
pub async fn new_recovery_codes<C: ConnectionTrait>(
    db: &C,
    id: i64,
) -> Result<Vec<String>, ApiError> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM recovery_code WHERE user_id = $1",
        [id.into()],
    ))
    .await?;
    let mut codes = Vec::with_capacity(totp::RECOVERY_CODES);
    for _ in 0..totp::RECOVERY_CODES {
        let code = totp::new_recovery_code();
        let hash = totp::recovery_hash(&code)
            .ok_or_else(|| anyhow::anyhow!("a new recovery code does not parse"))?;
        db.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO recovery_code (user_id, code_hash) VALUES ($1, $2)",
            [id.into(), hash.into()],
        ))
        .await?;
        codes.push(code);
    }
    Ok(codes)
}

/// Uses up recovery code `code` of an account with TOTP on: how many are left, or
/// `None` if it is not one of its unused ones.
pub async fn use_recovery_code(
    db: &DatabaseConnection,
    id: i64,
    code: &str,
) -> Result<Option<i64>, ApiError> {
    let Some(hash) = totp::recovery_hash(code) else {
        return Ok(None);
    };
    let txn = db.begin().await?;
    // The account first, as everywhere (the lock order: app_user, then its rows).
    let on = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT totp_enabled_at IS NOT NULL AS on FROM app_user WHERE id = $1 FOR UPDATE",
            [id.into()],
        ))
        .await?
        .map(|r| r.try_get::<bool>("", "on"))
        .transpose()?;
    if on != Some(true) {
        return Ok(None);
    }
    let used = txn
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE recovery_code SET used_at = now()
             WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
            [id.into(), hash.into()],
        ))
        .await?
        .rows_affected();
    if used != 1 {
        return Ok(None);
    }
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "WITH pace AS (UPDATE app_user SET totp_wrong = 0, totp_next_at = NULL WHERE id = $1)
             SELECT count(*) AS unused FROM recovery_code WHERE user_id = $1 AND used_at IS NULL",
            [id.into()],
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no row"))?;
    let unused: i64 = row.try_get("", "unused")?;
    txn.commit().await?;
    Ok(Some(unused))
}

/// TOTP off: no secret, no recovery codes.
pub async fn clear<C: ConnectionTrait>(db: &C, id: i64) -> Result<(), ApiError> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "WITH codes AS (DELETE FROM recovery_code WHERE user_id = $1)
         UPDATE app_user SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL,
             totp_wrong = 0, totp_next_at = NULL
         WHERE id = $1",
        [id.into()],
    ))
    .await?;
    Ok(())
}

/// An admin's or the CLI's reset (`by` `None`): TOTP off and the account's sessions
/// ended, so its next password login sets it up again (an admin's must).
pub async fn reset<C: ConnectionTrait>(
    db: &C,
    id: i64,
    by: Option<i64>,
    via: &str,
) -> Result<(), ApiError> {
    clear(db, id).await?;
    let ended = session::end_others(db, id, None).await?;
    audit::record(
        db,
        by,
        "user.totp.reset",
        format!("app_user/{id}"),
        json!({ "via": via, "ended_sessions": ended }),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_attempts_double_their_gap_up_to_five_minutes() {
        assert_eq!(
            gap_schedule(),
            vec![0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 300]
        );
    }
}
