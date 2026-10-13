//! The agent's own writes (the only ones its role may make).

use sea_orm::{ConnectionTrait, DbBackend, DbErr, Statement};

/// Records a network's hub public key; a no-op when it is already known.
pub async fn set_hub_key<C: ConnectionTrait>(
    db: &C,
    network_id: i64,
    public_key: &str,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO hub_key (network_id, public_key) VALUES ($1, $2)
         ON CONFLICT (network_id) DO UPDATE SET public_key = EXCLUDED.public_key
         WHERE hub_key.public_key <> EXCLUDED.public_key",
        [network_id.into(), public_key.into()],
    ))
    .await?;
    Ok(())
}

/// What the agent last applied, and what went wrong (`None` = nothing).
pub async fn record_status<C: ConnectionTrait>(
    db: &C,
    applied_revision: i64,
    error: Option<&str>,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO agent_status (applied_revision, applied_at, error) VALUES ($1, now(), $2)
         ON CONFLICT (id) DO UPDATE
             SET applied_revision = EXCLUDED.applied_revision,
                 applied_at = EXCLUDED.applied_at,
                 error = EXCLUDED.error",
        [applied_revision.into(), error.map(str::to_owned).into()],
    ))
    .await?;
    Ok(())
}
