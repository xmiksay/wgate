//! The portal: REST API (`/api/v1`), the login (`/auth`: password and TOTP,
//! invite and reset links, the global admins' OIDC) and the embedded UI.
//! Unprivileged: it only writes the database; the agent applies what changed.

mod api;
mod audit;
mod auth;
pub mod config;
mod error;
mod seal;
mod state;
mod ui;
mod wgkey;

use std::net::SocketAddr;

use anyhow::Context;
use axum::Router;
use axum::routing::{get, post};
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement, TransactionTrait,
};
use serde_json::json;

pub use api::openapi;
pub use auth::password::Password;
pub use config::Config;
pub use seal::SecretKey;
pub use state::{AppState, Clock};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/auth/options", post(auth::local::options))
        .route("/auth/password", post(auth::local::login))
        .route("/auth/totp", post(auth::challenge::login))
        .route(
            "/auth/account/{token}",
            get(auth::links::info).post(auth::links::redeem),
        )
        .route("/auth/login", get(auth::oidc::login))
        .route("/auth/oidc/{id}", get(auth::oidc::start))
        .route("/auth/callback", get(auth::oidc::callback))
        .route("/auth/logout", post(auth::oidc::logout))
        .nest("/api/v1", api::router())
        .fallback(ui::serve)
        .with_state(state)
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let listen = config.listen;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listen on {listen}"))?;
    serve_on(listener, config).await
}

/// [`serve`] on a listener already bound (`listen` is not looked at).
pub async fn serve_on(listener: tokio::net::TcpListener, config: Config) -> anyhow::Result<()> {
    let db = Database::connect(&config.database_url)
        .await
        .context("connect to the database")?;
    let app = router(AppState::new(db, config)?);
    tracing::info!(listen = %listener.local_addr()?, "serving");
    // The peer address: the client, or the proxy that vouches for it.
    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app).await.context("serve")
}

/// `wgate admin grant <email>`: makes `email` a global admin (or enables one again),
/// who can then log in with that verified email or a password
/// ([`set_password`]). A tenant's account keeps its role: emails are unique.
pub async fn grant_admin(db: &DatabaseConnection, email: &str) -> anyhow::Result<i64> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO app_user (tenant_id, email, role) VALUES (NULL, $1, 'global_admin')
             ON CONFLICT (lower(email)) DO UPDATE SET disabled_at = NULL
                 WHERE app_user.role = 'global_admin'
             RETURNING id",
            [email.into()],
        ))
        .await?
        .with_context(|| format!("{email} is an account of a tenant"))?;
    let id: i64 = row.try_get("", "id")?;
    audit::record(
        db,
        None,
        "admin.grant",
        format!("app_user/{id}"),
        json!({ "email": email }),
    )
    .await
    .map_err(cli_error)?;
    Ok(id)
}

/// `wgate user password <email>`: sets the account's password (any role), clears
/// its lockout and ends its sessions.
pub async fn set_password(
    db: &DatabaseConnection,
    email: &str,
    password: Password,
) -> anyhow::Result<i64> {
    auth::account::set_password(db, email, password)
        .await
        .map_err(cli_error)
}

/// `wgate user totp-reset <email>`: turns the account's TOTP off (with its recovery
/// codes) and ends its sessions.
pub async fn totp_reset(db: &DatabaseConnection, email: &str) -> anyhow::Result<i64> {
    let txn = db.begin().await.context("begin")?;
    let id = api::credentials::totp_reset_cli(&txn, email)
        .await
        .map_err(cli_error)?;
    txn.commit().await.context("commit")?;
    Ok(id)
}

/// `wgate keygen`: a new `secret_key` for `server.toml`.
pub fn keygen() -> anyhow::Result<String> {
    Ok(SecretKey::generate()?.to_base64())
}

/// An internal error keeps its cause on the command line.
fn cli_error(e: error::ApiError) -> anyhow::Error {
    match e {
        error::ApiError::Internal(e) => e,
        e => anyhow::anyhow!("{e}"),
    }
}
