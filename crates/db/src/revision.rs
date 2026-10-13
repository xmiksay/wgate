//! The state revision: bumped by every write transaction, which also NOTIFYs the
//! agent. Postgres delivers a NOTIFY only on commit, so a rolled-back write never
//! wakes the agent.

use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};

/// The channel the agent LISTENs on; the payload is the new revision.
pub const CHANNEL: &str = "wgate_changed";

/// Call as part of every write transaction.
pub async fn bump<C: ConnectionTrait>(txn: &C) -> Result<i64, DbErr> {
    let row = txn
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "UPDATE state_revision SET revision = revision + 1 RETURNING revision",
        ))
        .await?
        .ok_or_else(|| DbErr::RecordNotFound("state_revision".into()))?;
    let revision: i64 = row.try_get("", "revision")?;
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT pg_notify($1, $2)",
        [CHANNEL.into(), revision.to_string().into()],
    ))
    .await?;
    Ok(revision)
}

pub async fn current<C: ConnectionTrait>(db: &C) -> Result<i64, DbErr> {
    let row = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT revision FROM state_revision",
        ))
        .await?
        .ok_or_else(|| DbErr::RecordNotFound("state_revision".into()))?;
    row.try_get("", "revision")
}

/// A dedicated connection LISTENing on [`CHANNEL`]. It must reach Postgres directly:
/// pgbouncer in transaction mode drops LISTEN between transactions.
pub async fn listener(database_url: &str) -> Result<sqlx::postgres::PgListener, sqlx::Error> {
    let mut listener = sqlx::postgres::PgListener::connect(database_url).await?;
    listener.listen(CHANNEL).await?;
    Ok(listener)
}
