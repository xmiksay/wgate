//! What every request handler shares.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use sea_orm::DatabaseConnection;

use crate::auth::limit::Limiter;
use crate::auth::oidc::Provider;
use crate::auth::password::Hasher;
use crate::config::Config;
use crate::seal::SecretKey;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Arc<Config>,
    /// For the OIDC provider; never follows redirects (an SSRF guard).
    pub http: openidconnect::reqwest::Client,
    pub oidc: Arc<Provider>,
    pub limiter: Arc<Limiter>,
    pub hasher: Hasher,
    /// Seals secrets at rest ([`crate::seal`]); the only copy (taken out of the config).
    pub key: Arc<SecretKey>,
    /// Which 30 s step a TOTP code is checked against.
    pub clock: Clock,
}

/// Unix seconds: the system's, or (tests) one set by hand, so a TOTP code made for a
/// step is checked in that step whatever the wall clock does meanwhile.
#[derive(Clone, Default)]
pub struct Clock(Option<Arc<AtomicI64>>);

impl Clock {
    pub fn manual(unix: i64) -> Self {
        Self(Some(Arc::new(AtomicI64::new(unix))))
    }

    pub fn now(&self) -> i64 {
        match &self.0 {
            Some(t) => t.load(Ordering::Relaxed),
            None => time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }

    /// A manual clock moves on by `secs`; the system's ignores it.
    pub fn advance(&self, secs: i64) {
        if let Some(t) = &self.0 {
            t.fetch_add(secs, Ordering::Relaxed);
        }
    }
}

impl AppState {
    /// Refuses a config without a usable `secret_key`.
    pub fn new(db: DatabaseConnection, mut config: Config) -> anyhow::Result<Self> {
        config.secret_key()?;
        let key = Arc::new(
            config
                .secret_key
                .take()
                .ok_or_else(|| anyhow::anyhow!("no secret_key"))?,
        );
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
            limiter: Arc::default(),
            hasher: Hasher::per_core()?,
            key,
            clock: Clock::default(),
        })
    }
}
