//! Password logins as a browser makes them, from a chosen client address.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use sea_orm::{ConnectionTrait, DatabaseConnection};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::Client;

/// The default client.
pub const PEER: &str = "192.0.2.10:40000";

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Reply {
    /// `wgate_session=<token>`, if the reply set one.
    pub fn session(&self) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|c| c.to_str().unwrap())
            .find(|c| c.starts_with("wgate_session="))
            .map(|c| c.split(';').next().unwrap().to_owned())
    }
}

/// A request from `peer` (with extra `headers`), as `serve` hands it to the router.
pub async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    peer: &str,
    headers: &[(&str, &str)],
) -> Reply {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = match body {
        Some(b) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    Reply {
        status,
        headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

pub async fn login_from(
    app: &Router,
    email: &str,
    password: &str,
    peer: &str,
    headers: &[(&str, &str)],
) -> Reply {
    let body = json!({ "email": email, "password": password });
    send(app, "POST", "/auth/password", Some(body), peer, headers).await
}

pub async fn login(app: &Router, email: &str, password: &str) -> Reply {
    login_from(app, email, password, PEER, &[]).await
}

/// An account with `role` (tenant `tenant`) and `password`, not signed in.
pub async fn account(
    db: &DatabaseConnection,
    email: &str,
    role: &str,
    tenant: Option<i64>,
    password: &str,
) -> i64 {
    use sea_orm::{DbBackend, Statement};
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO app_user (tenant_id, email, role) VALUES ($1, $2, $3) RETURNING id",
            [tenant.into(), email.into(), role.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    wgate_server::set_password(db, email, wgate_server::Password::new(password.into()))
        .await
        .unwrap();
    row.try_get("", "id").unwrap()
}

/// The API client of a session cookie from a login.
pub async fn client(app: &Router, cookie: &str) -> Client {
    let r = send(
        app,
        "GET",
        "/api/v1/session",
        None,
        PEER,
        &[("cookie", cookie)],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    Client {
        app: app.clone(),
        token: cookie.strip_prefix("wgate_session=").unwrap().to_owned(),
        csrf: r.body["csrf"].as_str().unwrap().to_owned(),
        user_id: r.body["user_id"].as_i64().unwrap(),
    }
}

/// The one row of `query` as a JSON object.
pub async fn one(db: &DatabaseConnection, query: &str) -> Value {
    let row = db
        .query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            format!("WITH x AS ({query}) SELECT to_jsonb(x) AS v FROM x"),
        ))
        .await
        .unwrap()
        .unwrap();
    row.try_get("", "v").unwrap()
}

/// A new tenant's id.
pub async fn tenant(db: &DatabaseConnection, slug: &str) -> i64 {
    one(
        db,
        &format!("INSERT INTO tenant (slug, name) VALUES ('{slug}', 'x') RETURNING id"),
    )
    .await["id"]
        .as_i64()
        .unwrap()
}
