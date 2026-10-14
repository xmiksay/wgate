//! What every request handler shares.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use sea_orm::DatabaseConnection;

use crate::auth::limit::Limiter;
use crate::auth::outbound::Outbound;
use crate::auth::password::Hasher;
use crate::auth::provider::Discovery;
use crate::config::Config;
use crate::seal::SecretKey;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Arc<Config>,
    /// For the OIDC providers: public addresses only (but `oidc_allow_private`),
    /// no redirects, capped answers.
    pub http: Outbound,
    pub discovery: Arc<Discovery>,
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
    /// Refuses a config [`Config::check`] refuses (no usable `secret_key`, a
    /// leftover `[admin_oidc]`).
    pub fn new(db: DatabaseConnection, mut config: Config) -> anyhow::Result<Self> {
        config.check()?;
        let key = Arc::new(
            config
                .secret_key
                .take()
                .ok_or_else(|| anyhow::anyhow!("no secret_key"))?,
        );
        let http = Outbound::new(config.oidc_allow_private.clone())?;
        Ok(Self {
            db,
            config: Arc::new(config),
            http,
            discovery: Arc::default(),
            limiter: Arc::default(),
            hasher: Hasher::per_core()?,
            key,
            clock: Clock::default(),
        })
    }
}
