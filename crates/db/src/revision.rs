//! The state revision. Triggers bump it and NOTIFY the agent once per transaction
//! that changes the desired state, at its commit (see `m0001_state.sql`), so writers
//! need not remember to; nothing else may change it.

use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};

/// The channel the agent LISTENs on; the payload is the new revision.
pub const CHANNEL: &str = "wgate_changed";

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
