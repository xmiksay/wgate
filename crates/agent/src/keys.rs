//! Hub private keys: one per interface in the keys directory (0600), generated on
//! first use. They never leave the hub; only the public key goes to the database.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context;
use wgate_core::is_wg_key;

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
        Ok(key) if is_wg_key(key.trim()) => key,
        // Empty or truncated (a crash before it was ever used): its public key was
        // never published, so a new one replaces it.
        Ok(_) => {
            tracing::warn!(path = %path.display(), "invalid hub key replaced");
            generate(r, &path)?
        }
        Err(e) if e.kind() == ErrorKind::NotFound => generate(r, &path)?,
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let public = r.run(&["wg", "pubkey"], Some(&private))?.trim().to_owned();
    Ok((path, public))
}

/// Deletes the key of a network that is gone.
pub fn forget(dir: &Path, iface: &str) -> anyhow::Result<()> {
    let path = dir.join(format!("{iface}.key"));
    match fs::remove_file(&path) {
        Err(e) if e.kind() != ErrorKind::NotFound => {
            Err(e).with_context(|| format!("remove {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Written to a temporary file, synced, then renamed: a crash leaves either no key or
/// a whole one.
fn generate(r: &dyn Runner, path: &Path) -> anyhow::Result<String> {
    let key = r.run(&["wg", "genkey"], None)?;
    let tmp = path.with_extension("key.tmp");
    let _ = fs::remove_file(&tmp);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(key.as_bytes()).and_then(|()| f.sync_all()))
        .with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    if let Some(dir) = path.parent() {
        File::open(dir).and_then(|d| d.sync_all()).ok();
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tools;

    impl Runner for Tools {
        fn run(&self, argv: &[&str], _stdin: Option<&str>) -> anyhow::Result<String> {
            Ok(match argv {
                ["wg", "genkey"] => "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n".into(),
                _ => "public\n".into(),
            })
        }
    }

    #[test]
    fn generates_once_replaces_a_broken_key_and_forgets() {
        let dir = tempfile::tempdir().unwrap();
        let (path, public) = ensure(&Tools, dir.path(), "wg-a").unwrap();
        assert_eq!(public, "public");
        let key = fs::read_to_string(&path).unwrap();
        fs::write(&path, "").unwrap();
        ensure(&Tools, dir.path(), "wg-a").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), key, "regenerated");
        forget(dir.path(), "wg-a").unwrap();
        assert!(!path.exists());
        forget(dir.path(), "wg-a").unwrap();
    }
}
