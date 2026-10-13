//! `/etc/wgate/agent.toml`.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use ipnet::Ipv4Net;
use serde::Deserialize;
use wgate_db::Infra;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Direct to Postgres, not through pgbouncer (its transaction pooling drops LISTEN).
    pub database_url: String,
    pub pool: Vec<Ipv4Net>,
    pub routed_space: Vec<Ipv4Net>,
    #[serde(default)]
    pub reserved: Vec<Ipv4Net>,
    pub snat_source: Ipv4Addr,
    pub node_cidrs: Vec<Ipv4Net>,
    #[serde(default = "default_keys_dir")]
    pub keys_dir: PathBuf,
    /// The last desired state loaded, served when the hub boots without its database.
    #[serde(default = "default_state_file")]
    pub state_file: PathBuf,
    /// A full reconcile also runs this often, backing up a lost notification.
    #[serde(default = "default_interval")]
    pub reconcile_interval_secs: u64,
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from("/var/lib/wgate/keys")
}

fn default_state_file() -> PathBuf {
    PathBuf::from("/var/lib/wgate/state.json")
}

fn default_interval() -> u64 {
    60
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))
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

    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.reconcile_interval_secs.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_config() {
        let c: Config = toml::from_str(include_str!("../agent.example.toml")).unwrap();
        assert_eq!(c.snat_source, Ipv4Addr::new(172, 19, 9, 10));
        assert_eq!(c.keys_dir, PathBuf::from("/var/lib/wgate/keys"));
        assert_eq!(c.interval(), Duration::from_secs(60));
        // A typo (an unknown key) is never ignored.
        let example = include_str!("../agent.example.toml");
        let err = toml::from_str::<Config>(&format!("{example}\nbogus = 1")).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }
}
