//! Schema migrations, applied in order by `wgate migrate` before the units restart.
//! Plain SQL files and a bookkeeping table: wgate needs no more than that.

use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbErr, TransactionTrait};

/// In order; a name is recorded once its migration is applied.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "m0001_init",
        concat!(
            include_str!("m0001_init.sql"),
            include_str!("m0001_state.sql")
        ),
    ),
    ("m0002_accounts", include_str!("m0002_accounts.sql")),
    ("m0003_totp", include_str!("m0003_totp.sql")),
    ("m0004_providers", include_str!("m0004_providers.sql")),
];
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
            checksum   text NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now()
        )",
    )
    .await?;
    // A schema newer than this binary (e.g. after a rollback) must stop the rollout,
    // not run with code that does not know it.
    // An applied migration must be byte-for-byte the one this binary carries: one
    // edited after it ran would leave the database on a different schema than the
    // code expects, with every run reporting "up to date".
    let mut done = std::collections::HashSet::new();
    for row in txn
        .query_all_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT name, checksum FROM wgate_migration",
        ))
        .await?
    {
        let name: String = row.try_get("", "name")?;
        let checksum: String = row.try_get("", "checksum")?;
        let Some((_, sql)) = MIGRATIONS.iter().find(|(known, _)| *known == name) else {
            return Err(DbErr::Migration(format!(
                "database has migration {name}, which this wgate does not know (newer schema?)"
            )));
        };
        if checksum != md5(&txn, sql).await? {
            return Err(DbErr::Migration(format!(
                "migration {name} differs from the one applied to this database"
            )));
        }
        done.insert(name);
    }
    let mut applied = Vec::new();
    for (name, sql) in MIGRATIONS {
        if !done.contains(*name) {
            txn.execute_unprepared(sql).await?;
            let checksum = md5(&txn, sql).await?;
            txn.execute_raw(sea_orm::Statement::from_sql_and_values(
                sea_orm::DbBackend::Postgres,
                "INSERT INTO wgate_migration (name, checksum) VALUES ($1, $2)",
                [(*name).into(), checksum.into()],
            ))
            .await?;
            applied.push(*name);
        }
    }
    txn.execute_unprepared(GRANTS).await?;
    txn.commit().await?;
    Ok(applied)
}

async fn md5<C: ConnectionTrait>(db: &C, text: &str) -> Result<String, DbErr> {
    db.query_one_raw(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Postgres,
        "SELECT md5($1) AS sum",
        [text.into()],
    ))
    .await?
    .ok_or_else(|| DbErr::RecordNotFound("md5".into()))?
    .try_get("", "sum")
}

/// Connects to `database_url` and applies the pending migrations.
pub async fn migrate_url(database_url: &str) -> Result<Vec<&'static str>, DbErr> {
    migrate(&Database::connect(database_url).await?).await
}
