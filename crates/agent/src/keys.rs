//! Hub private keys: one per network in the keys directory (0600), generated on first
//! use and never deleted or replaced. They never leave the hub; only the public key
//! goes to the database.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use wgate_core::is_wg_key;

use crate::runner::Runner;

/// The key file named `name` and its public key, generated if there is none. Only for
/// an interface that has no key yet: generating for one that has would rotate it.
pub fn ensure(r: &dyn Runner, dir: &Path, name: &str) -> anyhow::Result<(PathBuf, String)> {
    match load(r, dir, name)? {
        Some(found) => Ok(found),
        None => {
            let path = dir.join(format!("{name}.key"));
            let private = generate(r, &path)?;
            Ok((path.clone(), public(r, &private)?))
        }
    }
}

/// The key file named `name` and its public key; `None` when there is none.
pub fn load(r: &dyn Runner, dir: &Path, name: &str) -> anyhow::Result<Option<(PathBuf, String)>> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(format!("{name}.key"));
    let private = match fs::read_to_string(&path) {
        Ok(key) if is_wg_key(key.trim()) => key,
        // Keys are written whole (below), so a bad one was damaged after its public
        // key went out: replacing it would cut every client off. Someone decides.
        Ok(_) => bail!(
            "{} is not a WireGuard key; restore it, or delete it to issue a new one",
            path.display()
        ),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let public = public(r, &private)?;
    Ok(Some((path, public)))
}

/// The network (by id) whose key in `dir` is `public`.
pub fn owner_of(r: &dyn Runner, dir: &Path, public: &str) -> Option<i64> {
    let entries = fs::read_dir(dir).ok()?;
    entries.flatten().find_map(|entry| {
        let name = entry.file_name().into_string().ok()?;
        let id = name.strip_prefix('n')?.strip_suffix(".key")?.parse().ok()?;
        let (_, key) = load(r, dir, &format!("n{id}")).ok()??;
        (key == public).then_some(id)
    })
}

fn public(r: &dyn Runner, private: &str) -> anyhow::Result<String> {
    Ok(r.run(&["wg", "pubkey"], Some(private))?.trim().to_owned())
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
    use std::cell::Cell;

    use super::*;

    /// Every genkey returns a new key, so a regeneration shows.
    #[derive(Default)]
    struct Tools(Cell<u8>);

    impl Runner for Tools {
        fn run(&self, argv: &[&str], stdin: Option<&str>) -> anyhow::Result<String> {
            Ok(match argv {
                ["wg", "genkey"] => {
                    self.0.set(self.0.get() + 1);
                    format!("{:0>42}A=\n", self.0.get())
                }
                _ => format!("pub-{}", stdin.unwrap_or_default().trim()),
            })
        }
    }

    #[test]
    fn generates_once_keeps_its_key_and_refuses_a_damaged_one() {
        let dir = tempfile::tempdir().unwrap();
        let tools = Tools::default();
        let (path, public) = ensure(&tools, dir.path(), "n1").unwrap();
        let key = fs::read_to_string(&path).unwrap();
        assert_eq!(public, format!("pub-{}", key.trim()));
        assert_eq!(ensure(&tools, dir.path(), "n1").unwrap().1, public, "kept");
        assert_ne!(
            ensure(&tools, dir.path(), "n2").unwrap().1,
            public,
            "own key"
        );
        fs::write(&path, "garbage").unwrap();
        assert!(ensure(&tools, dir.path(), "n1").is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "garbage",
            "left for a human"
        );
        fs::remove_file(&path).unwrap();
        assert_ne!(
            ensure(&tools, dir.path(), "n1").unwrap().1,
            public,
            "reissued"
        );
    }

    #[test]
    fn loads_without_issuing_and_finds_a_keys_network() {
        let dir = tempfile::tempdir().unwrap();
        let tools = Tools::default();
        assert!(load(&tools, dir.path(), "n4").unwrap().is_none());
        assert!(!dir.path().join("n4.key").exists(), "nothing issued");
        let (_, four) = ensure(&tools, dir.path(), "n4").unwrap();
        let (_, seven) = ensure(&tools, dir.path(), "n7").unwrap();
        assert_eq!(load(&tools, dir.path(), "n4").unwrap().unwrap().1, four);
        assert_eq!(owner_of(&tools, dir.path(), &seven), Some(7));
        assert_eq!(owner_of(&tools, dir.path(), "unknown"), None);
    }
}
