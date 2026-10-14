//! A migrated Postgres, the router, and signed-in clients for the API tests.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

pub mod capture;
pub mod idp;
pub mod login;
pub mod oidc;
mod session;
pub mod totp;

use axum::Router;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use wgate_server::{AppState, Clock, Config};

pub struct Env {
    pub _container: ContainerAsync<Postgres>,
    pub url: String,
    pub db: DatabaseConnection,
    pub app: Router,
    /// The server's TOTP clock, set by hand: mid-step, moved on only by the tests.
    pub clock: Clock,
}

/// The test config: the example's addresses, plain http.
pub fn config(url: &str) -> Config {
    let mut c: Config = toml::from_str(include_str!("../../server.example.toml")).unwrap();
    c.database_url = url.to_owned();
    c.public_url = "http://portal.test".parse().unwrap();
    c.endpoint_host = "127.0.0.1".into();
    // The example's is a placeholder the server refuses.
    c.secret_key = Some(wgate_server::SecretKey::generate().unwrap());
    // The mock providers listen on the loopback.
    c.oidc_allow_private = vec!["127.0.0.0/8".parse().unwrap()];
    c
}

/// As [`env`], the config changed by `edit` first.
pub async fn env_with(edit: impl FnOnce(&mut Config)) -> Env {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("start postgres (is Docker running?)");
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let db = Database::connect(&url).await.expect("connect");
    wgate_db::migrate(&db).await.expect("migrate");
    let mut config = config(&url);
    edit(&mut config);
    let mut state = AppState::new(db.clone(), config).unwrap();
    let clock = Clock::manual(1_800_000_015);
    state.clock = clock.clone();
    let app = wgate_server::router(state);
    Env {
        _container: container,
        url,
        db,
        app,
        clock,
    }
}

pub async fn env() -> Env {
    env_with(|_| {}).await
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
