//! A throwaway, migrated Postgres for the integration tests.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use wgate_db::Migrator;

/// A throwaway Postgres 17 (the production version), already migrated. Hold the
/// container: dropping it stops the database.
pub struct Pg {
    pub _container: ContainerAsync<Postgres>,
    pub url: String,
    pub db: DatabaseConnection,
}

pub async fn pg(before_migrate: &str) -> Pg {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("start postgres (is Docker running?)");
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let db = Database::connect(&url).await.expect("connect");
    if !before_migrate.is_empty() {
        db.execute_unprepared(before_migrate).await.expect("setup");
    }
    Migrator::up(&db, None).await.expect("migrate");
    Pg {
        _container: container,
        url,
        db,
    }
}

pub async fn ok(db: &DatabaseConnection, sql: &str) {
    db.execute_unprepared(sql)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

pub async fn refused(db: &DatabaseConnection, sql: &str) {
    assert!(db.execute_unprepared(sql).await.is_err(), "accepted: {sql}");
}
