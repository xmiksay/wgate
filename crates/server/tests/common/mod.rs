//! A migrated Postgres, the router, and signed-in clients for the API tests.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

pub mod idp;
mod session;

use axum::Router;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use wgate_server::{AppState, Config};

pub struct Env {
    pub _container: ContainerAsync<Postgres>,
    pub url: String,
    pub db: DatabaseConnection,
    pub app: Router,
}

/// The test config: the example's addresses, plain http, `issuer` for the admins.
pub fn config(url: &str, issuer: &str) -> Config {
    let mut c: Config = toml::from_str(include_str!("../../server.example.toml")).unwrap();
    c.database_url = url.to_owned();
    c.public_url = "http://portal.test".parse().unwrap();
    c.endpoint_host = "127.0.0.1".into();
    c.admin_oidc.issuer = issuer.to_owned();
    c
}

pub async fn env_with_issuer(issuer: &str) -> Env {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("start postgres (is Docker running?)");
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let db = Database::connect(&url).await.expect("connect");
    wgate_db::migrate(&db).await.expect("migrate");
    let app = wgate_server::router(AppState::new(db.clone(), config(&url, issuer)).unwrap());
    Env {
        _container: container,
        url,
        db,
        app,
    }
}

pub async fn env() -> Env {
    env_with_issuer("http://127.0.0.1:9/").await
}

pub async fn sql(db: &DatabaseConnection, s: &str) {
    db.execute_unprepared(s)
        .await
        .unwrap_or_else(|e| panic!("{s}: {e}"));
}

pub use session::Client;

/// A signed-in client: a user with `role` (tenant `tenant`).
pub async fn sign_in(e: &Env, email: &str, role: &str, tenant: Option<i64>) -> Client {
    session::sign_in_to(&e.db, &e.app, email, role, tenant).await
}
