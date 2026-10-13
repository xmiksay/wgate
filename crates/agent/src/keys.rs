//! Hub private keys: one per interface in the keys directory (0600), generated on
//! first use. They never leave the hub; only the public key goes to the database.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::runner::Runner;

/// The key file of `iface` and its public key.
pub fn ensure(r: &dyn Runner, dir: &Path, iface: &str) -> anyhow::Result<(PathBuf, String)> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(format!("{iface}.key"));
    let private = match fs::read_to_string(&path) {
        Ok(key) => key,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let key = r.run(&["wg", "genkey"], None)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| f.write_all(key.as_bytes()))
                .with_context(|| format!("write {}", path.display()))?;
            key
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let public = r.run(&["wg", "pubkey"], Some(&private))?.trim().to_owned();
    Ok((path, public))
}
