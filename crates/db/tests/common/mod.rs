//! A throwaway, migrated Postgres for the integration tests.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

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
    wgate_db::migrate(&db).await.expect("migrate");
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

/// Two tenants, one network of tenant 1, one user with a device.
pub const BASE: &str = "
    INSERT INTO tenant (id, slug, name) VALUES (1, 'nexial', 'Nexial'), (2, 'krcmar', 'Krcmar');
    INSERT INTO tenant_block (id, tenant_id, cidr) VALUES (1, 1, '10.50.0.0/24'), (2, 2, '10.50.1.0/24');
    INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port)
        VALUES (1, 1, 1, 'nexial', 'Nexial', '10.50.0.0/25', 51801);
    INSERT INTO app_user (id, tenant_id, email, role) VALUES (1, 1, 'a@nexial.cz', 'user');
    INSERT INTO device (id, user_id, name) VALUES (1, 1, 'laptop');
";
pub const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

/// `url` as the agent role (created with password `agent`).
pub fn as_agent(url: &str) -> String {
    url.replace("postgres:postgres@", "wgate_agent:agent@")
}
