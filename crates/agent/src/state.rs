//! The last desired state loaded, kept on disk: a hub that boots while its database is
//! unreachable rebuilds what it last served. It holds no secret (addresses, rules,
//! peer public keys) and is still written 0600, as the keys are.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::Context;
use wgate_core::DesiredState;

pub fn save(path: &Path, state: &DesiredState) -> anyhow::Result<()> {
    let json = serde_json::to_vec(state).context("encode the state")?;
    crate::private::write(path, &json)
}

/// `None` when there is none yet.
pub fn load(path: &Path) -> anyhow::Result<Option<DesiredState>> {
    match fs::read(path) {
        Ok(json) => serde_json::from_slice(&json)
            .map(Some)
            .with_context(|| format!("parse {}", path.display())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn saves_and_loads_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert!(load(&path).unwrap().is_none());
        let state = DesiredState {
            pool: vec!["10.50.0.0/16".parse().unwrap()],
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: vec![],
            routed_space: vec![],
            reserved: vec![],
            tenants: vec![],
            networks: vec![],
            peers: vec![],
            federations: vec![],
        };
        save(&path, &state).unwrap();
        assert_eq!(load(&path).unwrap().unwrap().pool, state.pool);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::write(&path, "garbage").unwrap();
        assert!(load(&path).is_err());
    }
}
