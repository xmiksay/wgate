//! What every request handler shares.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::auth::oidc::Provider;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Arc<Config>,
    /// For the OIDC provider; never follows redirects (an SSRF guard).
    pub http: openidconnect::reqwest::Client,
    pub oidc: Arc<Provider>,
}

impl AppState {
    pub fn new(db: DatabaseConnection, config: Config) -> anyhow::Result<Self> {
        let http = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            // A provider that hangs must not hold the discovery lock forever.
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self {
            db,
            config: Arc::new(config),
            http,
            oidc: Arc::default(),
        })
    }
}
