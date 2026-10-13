//! A migrated Postgres, the router, and signed-in clients for the API tests.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

pub mod idp;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use serde_json::Value;
use sha2::{Digest, Sha256};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tower::ServiceExt;
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

/// A signed-in client: a user with `role` (tenant `tenant`) and a session made the
/// way a login makes one.
#[derive(Clone)]
pub struct Client {
    pub app: Router,
    pub token: String,
    pub csrf: String,
    pub user_id: i64,
}

pub async fn sign_in(e: &Env, email: &str, role: &str, tenant: Option<i64>) -> Client {
    let row =
        e.db.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO app_user (tenant_id, email, role) VALUES ($1, $2, $3) RETURNING id",
            [tenant.into(), email.into(), role.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    let user_id: i64 = row.try_get("", "id").unwrap();
    let token = format!("token-{user_id}");
    let csrf = format!("csrf-{user_id}");
    e.db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO session (token_hash, user_id, csrf, expires_at)
         VALUES ($1, $2, $3, now() + interval '1 day')",
        [
            Sha256::digest(token.as_bytes()).to_vec().into(),
            user_id.into(),
            csrf.clone().into(),
        ],
    ))
    .await
    .unwrap();
    Client {
        app: e.app.clone(),
        token,
        csrf,
        user_id,
    }
}

impl Client {
    pub async fn call(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.call_with(method, uri, body, true).await
    }

    pub async fn call_with(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
        csrf: bool,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("/api/v1{uri}"))
            .header(header::COOKIE, format!("wgate_session={}", self.token));
        if csrf {
            req = req.header("x-csrf-token", &self.csrf);
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    pub async fn get(&self, uri: &str) -> (StatusCode, Value) {
        self.call(Method::GET, uri, None).await
    }

    pub async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::POST, uri, Some(body)).await
    }

    pub async fn patch(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::PATCH, uri, Some(body)).await
    }

    pub async fn delete(&self, uri: &str) -> (StatusCode, Value) {
        self.call(Method::DELETE, uri, None).await
    }

    /// The created row's id; panics with the response unless it is a 201.
    pub async fn create(&self, uri: &str, body: Value) -> Value {
        let (status, v) = self.post(uri, body).await;
        assert_eq!(status, StatusCode::CREATED, "{uri}: {v}");
        v
    }
}
