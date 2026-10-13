//! The audit trail: every write records who did what to which row, in the same
//! transaction as the write (no change without its entry, no entry without its change).

use sea_orm::{ConnectionTrait, DbBackend, Statement};

use crate::error::ApiError;

/// `target` is `<table>/<id>`; `detail` must never hold a secret (no private keys).
pub async fn record<C: ConnectionTrait>(
    db: &C,
    actor: Option<i64>,
    action: &str,
    target: String,
    detail: serde_json::Value,
) -> Result<(), ApiError> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO audit (actor_user_id, action, target, detail) VALUES ($1, $2, $3, $4)",
        [actor.into(), action.into(), target.into(), detail.into()],
    ))
    .await?;
    Ok(())
}
