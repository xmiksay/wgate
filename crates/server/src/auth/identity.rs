//! Identities: `(provider, subject)` bound to an account. Who a provider login is,
//! binding one (by verified email at a first login, from `/me`, or by an admin) and
//! taking one away, never an account's last way in. Lock order as elsewhere: the
//! `app_user` row first, then what hangs off it. A provider change ([`stranded`])
//! locks the provider row first, but only `FOR NO KEY UPDATE`, which the `KEY SHARE`
//! a login's or a bind's insert takes on it does not wait for: so the two orders
//! never close a cycle.

use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};

use super::Role;
use super::provider::{self, Provider};
use crate::error::ApiError;

/// Why a provider login signs nobody in (the audit's `reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Neither an identity nor an email that may bind.
    Unknown,
    /// An identity of an account the provider does not serve (another tenant's, a
    /// global admin's at a tenant's provider).
    NotServed,
    Disabled,
    /// The email's account has another subject at this provider.
    OtherSubject,
}

impl Refused {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown_subject",
            Self::NotServed => "not_served",
            Self::Disabled => "disabled",
            Self::OtherSubject => "other_subject",
        }
    }
}

/// An account as a login sees it.
struct Account {
    id: i64,
    tenant_id: Option<i64>,
    role: Role,
    disabled: bool,
}

const ACCOUNT: &str = "SELECT u.id, u.tenant_id, u.role,
        u.disabled_at IS NOT NULL OR t.disabled_at IS NOT NULL AS disabled
    FROM app_user u LEFT JOIN tenant t ON t.id = u.tenant_id";

async fn account<C: ConnectionTrait>(
    db: &C,
    filter: &str,
    values: Vec<sea_orm::Value>,
) -> Result<Option<Account>, ApiError> {
    let Some(row) = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{ACCOUNT} {filter}"),
            values,
        ))
        .await?
    else {
        return Ok(None);
    };
    let role = row.try_get::<String>("", "role")?;
    Ok(Some(Account {
        id: row.try_get("", "id")?,
        tenant_id: row.try_get("", "tenant_id")?,
        role: Role::parse(&role).ok_or_else(|| anyhow::anyhow!("role {role}"))?,
        disabled: row.try_get("", "disabled")?,
    }))
}

/// A login through `p` as `subject` (with its verified email, if any): the account
/// and whether it was bound by that email just now. Whatever binds an identity, the
/// login checks again that `p` serves its account: a row put there by hand, or one
/// from before a rule changed, signs in nobody it should not.
pub async fn resolve(
    db: &DatabaseConnection,
    p: &Provider,
    subject: &str,
    email: Option<&str>,
) -> Result<Result<(i64, bool), Refused>, ApiError> {
    let bound = account(
        db,
        "JOIN identity i ON i.user_id = u.id WHERE i.provider_id = $1 AND i.subject = $2",
        vec![p.id.into(), subject.into()],
    )
    .await?;
    if let Some(a) = bound {
        return Ok(if !provider::serves(p.tenant_id, a.tenant_id) {
            Err(Refused::NotServed)
        } else if a.disabled {
            Err(Refused::Disabled)
        } else {
            Ok((a.id, false))
        });
    }
    let Some(email) = email else {
        return Ok(Err(Refused::Unknown));
    };
    let Some(id) = account(db, "WHERE lower(u.email) = lower($1)", vec![email.into()])
        .await?
        .map(|a| a.id)
    else {
        return Ok(Err(Refused::Unknown));
    };
    // Decided and bound under the account's lock: a promotion (which drops what a
    // tenant's provider bound) or a disable in between is seen, not raced.
    let txn = crate::api::begin(db).await?;
    lock_account(&txn, id).await?;
    let fresh = account(&txn, "WHERE u.id = $1", vec![id.into()]).await?;
    let Some(a) = fresh.filter(|a| provider::binds_by_email(p, a.tenant_id, a.role)) else {
        return Ok(Err(Refused::Unknown));
    };
    if a.disabled {
        return Ok(Err(Refused::Disabled));
    }
    let bound = bind(&txn, a.id, p.id, subject).await?;
    txn.commit().await?;
    Ok(match bound {
        Ok(_) => Ok((a.id, true)),
        Err(_) => Err(Refused::OtherSubject),
    })
}

/// Why an identity was not bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// The subject is another account's.
    Elsewhere,
    /// The account has an identity at this provider already.
    Here,
}

impl Taken {
    pub fn error(self) -> ApiError {
        ApiError::Conflict(
            match self {
                Self::Elsewhere => "this identity is linked to another account",
                Self::Here => "the account has an identity at this provider already",
            }
            .into(),
        )
    }
}

/// Binds `(provider, subject)` to account `user`: the new identity's id.
pub async fn bind<C: ConnectionTrait>(
    db: &C,
    user: i64,
    provider: i64,
    subject: &str,
) -> Result<Result<i64, Taken>, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO identity (user_id, provider_id, subject) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING RETURNING id",
            [user.into(), provider.into(), subject.into()],
        ))
        .await?;
    if let Some(row) = row {
        return Ok(Ok(row.try_get("", "id")?));
    }
    let holder = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT user_id FROM identity WHERE provider_id = $1 AND subject = $2",
            [provider.into(), subject.into()],
        ))
        .await?
        .map(|r| r.try_get::<i64>("", "user_id"))
        .transpose()?;
    Ok(Err(match holder {
        Some(other) if other != user => Taken::Elsewhere,
        _ => Taken::Here,
    }))
}

/// Takes identity `id` from account `user` (whose row this locks first): its provider.
/// `NotFound` if it is not the account's; 422 if it is the account's last way in (no
/// password, no other identity at an enabled provider).
pub async fn unlink<C: ConnectionTrait>(db: &C, user: i64, id: i64) -> Result<i64, ApiError> {
    // Its own statement: the check below then sees what a concurrent unlink, which
    // held the lock first, committed (READ COMMITTED takes a new snapshot per
    // statement, not after a lock wait within one).
    lock_account(db, user).await?;
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT u.password_hash IS NOT NULL AS password,
                    (SELECT provider_id FROM identity WHERE id = $2 AND user_id = u.id)
                        AS provider,
                    EXISTS (SELECT FROM identity i JOIN oidc_provider p ON p.id = i.provider_id
                            WHERE i.user_id = u.id AND i.id <> $2 AND p.disabled_at IS NULL)
                        AS other
             FROM app_user u WHERE u.id = $1",
            [user.into(), id.into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    let provider: i64 = row
        .try_get::<Option<i64>>("", "provider")?
        .ok_or(ApiError::NotFound)?;
    if !row.try_get::<bool>("", "password")? && !row.try_get::<bool>("", "other")? {
        return Err(ApiError::invalid(
            "the account's last way to log in: set a password or link another identity first",
        ));
    }
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM identity WHERE id = $1",
        [id.into()],
    ))
    .await?;
    Ok(provider)
}

/// Ends account `user`'s sessions made through `provider` but `keep`; how many.
pub async fn end_sessions<C: ConnectionTrait>(
    db: &C,
    user: i64,
    provider: i64,
    keep: Option<i64>,
) -> Result<u64, ApiError> {
    Ok(db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM session WHERE user_id = $1 AND provider_id = $2
                 AND id IS DISTINCT FROM $3",
            [user.into(), provider.into(), keep.into()],
        ))
        .await?
        .rows_affected())
}

/// Account `id`'s row, locked first (the lock order), so that it does not change
/// (nor lose its last way in) meanwhile.
pub async fn lock_account<C: ConnectionTrait>(db: &C, id: i64) -> Result<(), ApiError> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM app_user WHERE id = $1 FOR UPDATE",
        [id.into()],
    ))
    .await?;
    Ok(())
}

/// An account made an admin loses its identities at tenant providers (bound by the
/// tenant's admins or its provider, never by its owner alone): how many.
pub async fn unlink_tenant_providers<C: ConnectionTrait>(
    db: &C,
    user: i64,
) -> Result<u64, ApiError> {
    Ok(db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM identity i USING oidc_provider p
             WHERE p.id = i.provider_id AND p.tenant_id IS NOT NULL AND i.user_id = $1",
            [user.into()],
        ))
        .await?
        .rows_affected())
}

/// The accounts that would have no way in left without their identity at `provider`
/// (no password, no identity at another enabled provider): (how many, whether an
/// admin account is among them).
pub async fn stranded<C: ConnectionTrait>(db: &C, provider: i64) -> Result<(i64, bool), ApiError> {
    // The accounts first, in their own statement (the lock order: the provider row,
    // then accounts by id, then their identities): none gains or loses a way in
    // while this counts and the caller acts on it.
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM app_user
         WHERE id IN (SELECT user_id FROM identity WHERE provider_id = $1)
         ORDER BY id FOR UPDATE",
        [provider.into()],
    ))
    .await?;
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT count(*) AS n, coalesce(bool_or(u.role <> 'user'), false) AS admin
             FROM identity i JOIN app_user u ON u.id = i.user_id
             WHERE i.provider_id = $1 AND u.password_hash IS NULL
               AND NOT EXISTS (SELECT FROM identity j JOIN oidc_provider q ON q.id = j.provider_id
                               WHERE j.user_id = u.id AND j.provider_id <> $1
                                 AND q.disabled_at IS NULL)",
            [provider.into()],
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no row"))?;
    Ok((row.try_get("", "n")?, row.try_get("", "admin")?))
}

/// Whether account `user` has no way in (no password, no identity at an enabled
/// provider).
pub async fn no_way_in<C: ConnectionTrait>(db: &C, user: i64) -> Result<bool, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT u.password_hash IS NULL
                    AND NOT EXISTS (SELECT FROM identity i JOIN oidc_provider p ON p.id = i.provider_id
                                    WHERE i.user_id = u.id AND p.disabled_at IS NULL) AS none
             FROM app_user u WHERE u.id = $1",
            [user.into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(row.try_get("", "none")?)
}
