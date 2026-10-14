//! Signed-in API clients against a router, with sessions made the way a login makes
//! them. No `Env`: the full-stack netns tests include this file too.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

/// A signed-in client: a user with `role` (tenant `tenant`) and a session made the
/// way a login makes one.
#[derive(Clone)]
pub struct Client {
    pub app: Router,
    pub token: String,
    pub csrf: String,
    pub user_id: i64,
}

pub async fn sign_in_to(
    db: &DatabaseConnection,
    app: &Router,
    email: &str,
    role: &str,
    tenant: Option<i64>,
) -> Client {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
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
    db.execute_raw(Statement::from_sql_and_values(
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
        app: app.clone(),
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
            .header(header::COOKIE, format!("wgate_session={}", self.token))
            // As `serve` adds it: the client's address.
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
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

    /// A POST labelled JSON whose body is empty, as some clients send for "no body".
    pub async fn post_empty_json(&self, uri: &str) -> StatusCode {
        let req = Request::post(format!("/api/v1{uri}"))
            .header(header::COOKIE, format!("wgate_session={}", self.token))
            .header("x-csrf-token", &self.csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))))
            .body(Body::empty())
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap().status()
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

    /// The created row; panics with the response unless it is a 201.
    pub async fn create(&self, uri: &str, body: Value) -> Value {
        self.expect(StatusCode::CREATED, Method::POST, uri, Some(body))
            .await
    }

    /// The response of a call that must answer `want`.
    pub async fn expect(
        &self,
        want: StatusCode,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> Value {
        let (status, v) = self.call(method, uri, body).await;
        assert_eq!(status, want, "{uri}: {v}");
        v
    }
}
