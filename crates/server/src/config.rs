//! `/etc/wgate/server.toml`.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::Context;
use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;
use url::Url;
use wgate_db::Infra;

use crate::seal::SecretKey;

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
    /// Peers whose `X-Forwarded-For` names the client (the ingress); anyone else's
    /// is ignored. Empty: the TCP peer is the client.
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    /// Non-public addresses OIDC providers may be reached at (an internal Keycloak);
    /// plain `http` only into these. Empty: providers are on the internet.
    #[serde(default)]
    pub oidc_allow_private: Vec<IpNet>,
    /// Encrypts secrets at rest (TOTP secrets); required, see [`Config::secret_key`].
    #[serde(default)]
    pub secret_key: Option<SecretKey>,
    /// Gone (plan 1.10): kept only so that a leftover gets [`LEFTOVER_ADMIN_OIDC`]
    /// rather than serde's "unknown field". Never read, never printed.
    #[serde(default)]
    admin_oidc: Option<serde::de::IgnoredAny>,
}

/// Why a `server.toml` with `[admin_oidc]` does not start. Not imported on purpose:
/// a provider in the database is a global admin's decision (its name, who may link).
pub const LEFTOVER_ADMIN_OIDC: &str = "server.toml has [admin_oidc], but providers now live \
    in the database: add it in the UI under Providers (a global provider; the redirect \
    URI stays <public_url>/auth/callback), then remove [admin_oidc] from server.toml";

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
        anyhow::ensure!(self.admin_oidc.is_none(), LEFTOVER_ADMIN_OIDC);
        self.secret_key()?;
        Ok(())
    }

    /// The key for secrets at rest. Optional in the file only so that a missing one
    /// gets this message rather than serde's.
    pub fn secret_key(&self) -> anyhow::Result<&SecretKey> {
        let key = self
            .secret_key
            .as_ref()
            .context("server.toml has no secret_key: make one with `wgate keygen`")?;
        anyhow::ensure!(
            !key.is_placeholder(),
            "secret_key is the example's placeholder: make one with `wgate keygen`"
        );
        Ok(key)
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
        // The example's key is a placeholder: the server refuses it, and no key at all.
        let err = c.check().unwrap_err().to_string();
        assert!(
            err.contains("placeholder") && err.contains("wgate keygen"),
            "{err}"
        );
        let mut c = c;
        c.secret_key = None;
        let err = c.check().unwrap_err().to_string();
        assert!(
            err.contains("no secret_key") && err.contains("wgate keygen"),
            "{err}"
        );
        c.secret_key = Some(SecretKey::generate().unwrap());
        c.check().unwrap();
        let key = c.secret_key.as_ref().unwrap().to_base64();
        assert!(!format!("{c:?}").contains(&key));
        let mut prefixed = c.clone();
        prefixed.public_url = "https://example.org/wgate/".parse().unwrap();
        assert!(prefixed.check().is_err());
        prefixed.public_url = "https://user:pw@example.org/".parse().unwrap();
        assert!(prefixed.check().is_err());
        assert!(c.trusted_proxies.is_empty());
        let example = include_str!("../server.example.toml");
        assert!(toml::from_str::<Config>(&format!("{example}\nbogus = 1")).is_err());
    }

    #[test]
    fn proxies_are_optional_and_a_leftover_admin_oidc_refused() {
        let example = include_str!("../server.example.toml");
        let bare: String = example
            .lines()
            .filter(|l| !l.starts_with("trusted_proxies"))
            .map(|l| format!("{l}\n"))
            .collect();
        let mut c: Config = toml::from_str(&bare).unwrap();
        c.secret_key = Some(SecretKey::generate().unwrap());
        c.check().unwrap();
        let with: Config =
            toml::from_str(&format!("trusted_proxies = [\"172.19.9.11/32\"]\n{bare}")).unwrap();
        assert_eq!(
            with.trusted_proxies,
            vec!["172.19.9.11/32".parse::<IpNet>().unwrap()]
        );
        let leftover = format!(
            "{bare}[admin_oidc]\nissuer = \"https://x\"\nclient_id = \"a\"\nclient_secret = \"hunter2\"\n"
        );
        let mut old: Config = toml::from_str(&leftover).unwrap();
        old.secret_key = Some(SecretKey::generate().unwrap());
        let err = old.check().unwrap_err().to_string();
        assert!(
            err.contains("Providers") && err.contains("remove [admin_oidc]"),
            "{err}"
        );
        assert!(!format!("{old:?}").contains("hunter2"));
    }
}
