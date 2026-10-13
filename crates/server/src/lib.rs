//! The portal: REST API (`/api/v1`) and the global admins' OIDC login. Unprivileged:
//! it only writes the database; the agent applies what changed.

mod api;
mod audit;
mod auth;
pub mod config;
mod error;
mod state;
mod wgkey;

use anyhow::Context;
use axum::Router;
use axum::routing::{get, post};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use serde_json::json;

pub use api::openapi;
pub use config::Config;
pub use state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/auth/login", get(auth::oidc::login))
        .route("/auth/callback", get(auth::oidc::callback))
        .route("/auth/logout", post(auth::oidc::logout))
        .nest("/api/v1", api::router())
        .with_state(state)
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let db = Database::connect(&config.database_url)
        .await
        .context("connect to the database")?;
    let listen = config.listen;
    let app = router(AppState::new(db, config)?);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listen on {listen}"))?;
    tracing::info!(%listen, "serving");
    axum::serve(listener, app).await.context("serve")
}

/// `wgate admin grant <email>`: makes `email` a global admin (or enables one again),
/// who can then log in with that verified email.
pub async fn grant_admin(db: &DatabaseConnection, email: &str) -> anyhow::Result<i64> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO app_user (tenant_id, email, role) VALUES (NULL, $1, 'global_admin')
             ON CONFLICT (tenant_id, lower(email)) DO UPDATE SET disabled_at = NULL
             RETURNING id",
            [email.into()],
        ))
        .await?
        .context("no row returned")?;
    let id: i64 = row.try_get("", "id")?;
    audit::record(
        db,
        None,
        "admin.grant",
        format!("app_user/{id}"),
        json!({ "email": email }),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(id)
}
