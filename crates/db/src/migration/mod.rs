//! Schema migrations, applied in order by `wgate migrate` before the units restart.
//! Plain SQL files and a bookkeeping table: wgate needs no more than that.

use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbErr, TransactionTrait};

/// In order; a name is recorded once its migration is applied.
const MIGRATIONS: &[(&str, &str)] = &[("m0001_init", include_str!("m0001_init.sql"))];
/// Idempotent; applied on every run, after the migrations.
const GRANTS: &str = include_str!("grants.sql");

/// Applies the pending migrations in one transaction, so a failure leaves the schema
/// as it was. Returns the names applied now.
pub async fn migrate(db: &DatabaseConnection) -> Result<Vec<&'static str>, DbErr> {
    let txn = db.begin().await?;
    // Two concurrent `wgate migrate` runs must not both apply the same migration, nor
    // race to create the bookkeeping table; the lock covers both.
    txn.execute_unprepared("SELECT pg_advisory_xact_lock(hashtext('wgate_migrate'))")
        .await?;
    txn.execute_unprepared(
        "CREATE TABLE IF NOT EXISTS wgate_migration (
            name       text PRIMARY KEY,
            applied_at timestamptz NOT NULL DEFAULT now()
        )",
    )
    .await?;
    // A schema newer than this binary (e.g. after a rollback) must stop the rollout,
    // not run with code that does not know it.
    let known: Vec<&str> = MIGRATIONS.iter().map(|(name, _)| *name).collect();
    for row in txn
        .query_all_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT name FROM wgate_migration",
        ))
        .await?
    {
        let name: String = row.try_get("", "name")?;
        if !known.contains(&name.as_str()) {
            return Err(DbErr::Migration(format!(
                "database has migration {name}, which this wgate does not know (newer schema?)"
            )));
        }
    }
    let mut applied = Vec::new();
    for (name, sql) in MIGRATIONS {
        let done = txn
            .query_one_raw(sea_orm::Statement::from_sql_and_values(
                sea_orm::DbBackend::Postgres,
                "SELECT 1 FROM wgate_migration WHERE name = $1",
                [(*name).into()],
            ))
            .await?
            .is_some();
        if !done {
            txn.execute_unprepared(sql).await?;
            txn.execute_raw(sea_orm::Statement::from_sql_and_values(
                sea_orm::DbBackend::Postgres,
                "INSERT INTO wgate_migration (name) VALUES ($1)",
                [(*name).into()],
            ))
            .await?;
            applied.push(*name);
        }
    }
    txn.execute_unprepared(GRANTS).await?;
    txn.commit().await?;
    Ok(applied)
}

/// Connects to `database_url` and applies the pending migrations.
pub async fn migrate_url(database_url: &str) -> Result<Vec<&'static str>, DbErr> {
    migrate(&Database::connect(database_url).await?).await
}
