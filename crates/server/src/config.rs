//! `/etc/wgate/server.toml`.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::Context;
use ipnet::Ipv4Net;
use serde::Deserialize;
use url::Url;
use wgate_db::Infra;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    /// Direct to Postgres, as the agent (pgbouncer's transaction pooling would do
    /// here, but one URL setup is simpler to get right).
    pub database_url: String,
    /// Where the portal is reached, an origin without a path (the portal serves at the
    /// root); the OIDC callback is `<public_url>/auth/callback`.
    pub public_url: Url,
    /// The WireGuard endpoint's host in client configs (the portal and the hub may be
    /// reached under different names).
    pub endpoint_host: String,
    /// Must match the agent's.
    pub pool: Vec<Ipv4Net>,
    pub routed_space: Vec<Ipv4Net>,
    #[serde(default)]
    pub reserved: Vec<Ipv4Net>,
    pub snat_source: Ipv4Addr,
    pub node_cidrs: Vec<Ipv4Net>,
    pub admin_oidc: Oidc,
}

/// An OpenID Connect provider (discovery at `<issuer>/.well-known/openid-configuration`).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    /// Exactly as the provider names itself (discovery compares it verbatim: a URL
    /// type would add a trailing slash).
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let config: Self =
            toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        config.check()?;
        Ok(config)
    }

    pub fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.public_url.path() == "/"
                && self.public_url.query().is_none()
                && self.public_url.fragment().is_none()
                && self.public_url.username().is_empty()
                && self.public_url.password().is_none(),
            "public_url must be an origin, without a path or credentials (the portal \
             serves at the root)"
        );
        Ok(())
    }

    pub fn infra(&self) -> Infra {
        Infra {
            pool: self.pool.clone(),
            routed_space: self.routed_space.clone(),
            reserved: self.reserved.clone(),
            snat_source: self.snat_source,
            node_cidrs: self.node_cidrs.clone(),
        }
    }

    /// The session cookie is `Secure` unless the portal runs on plain http (tests).
    pub fn secure_cookies(&self) -> bool {
        self.public_url.scheme() == "https"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_config_and_hides_the_secret() {
        let c: Config = toml::from_str(include_str!("../server.example.toml")).unwrap();
        assert_eq!(c.endpoint_host, "vpn.mmik.cz");
        assert!(c.secure_cookies());
        c.check().unwrap();
        let mut prefixed = c.clone();
        prefixed.public_url = "https://example.org/wgate/".parse().unwrap();
        assert!(prefixed.check().is_err());
        prefixed.public_url = "https://user:pw@example.org/".parse().unwrap();
        assert!(prefixed.check().is_err());
        assert!(!format!("{c:?}").contains(&c.admin_oidc.client_secret));
        let example = include_str!("../server.example.toml");
        assert!(toml::from_str::<Config>(&format!("{example}\nbogus = 1")).is_err());
    }
}
