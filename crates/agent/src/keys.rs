//! Hub private keys: one per network (`n<id>.key`) in the keys directory (0600),
//! issued on first use and never deleted or replaced. They never leave the hub; only
//! the public key goes to the database.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use wgate_core::{Id, is_wg_key};

use crate::runner::Runner;

/// The keys directory for one reconcile: each key file is read (and its public key
/// derived) once.
pub struct Keys<'a> {
    r: &'a dyn Runner,
    dir: &'a Path,
    known: RefCell<HashMap<Id, (PathBuf, String)>>,
}

impl<'a> Keys<'a> {
    pub fn new(r: &'a dyn Runner, dir: &'a Path) -> Self {
        Self {
            r,
            dir,
            known: RefCell::default(),
        }
    }

    /// Network `id`'s key file and public key; `None` when it has none.
    pub fn load(&self, id: Id) -> anyhow::Result<Option<(PathBuf, String)>> {
        if let Some(found) = self.known.borrow().get(&id) {
            return Ok(Some(found.clone()));
        }
        let path = self.path(id);
        let private = match fs::read_to_string(&path) {
            Ok(key) if is_wg_key(key.trim()) => key,
            // Keys are written whole (below), so a bad one was damaged after its
            // public key went out: replacing it would cut every client off.
            Ok(_) => bail!(
                "{} is not a WireGuard key; restore it, or delete it to issue a new one",
                path.display()
            ),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        let found = (path, self.public(&private)?);
        self.known.borrow_mut().insert(id, found.clone());
        Ok(Some(found))
    }

    /// Network `id`'s key, issued if there is none. Only for an interface that has no
    /// key yet: issuing for one that has would rotate it.
    pub fn ensure(&self, id: Id) -> anyhow::Result<(PathBuf, String)> {
        if let Some(found) = self.load(id)? {
            return Ok(found);
        }
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(self.dir)
            .with_context(|| format!("create {}", self.dir.display()))?;
        let path = self.path(id);
        let private = generate(self.r, &path)?;
        let found = (path, self.public(&private)?);
        self.known.borrow_mut().insert(id, found.clone());
        Ok(found)
    }

    /// The network whose key is `public`.
    pub fn owner_of(&self, public: &str) -> Option<Id> {
        let entries = fs::read_dir(self.dir).ok()?;
        entries.flatten().find_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let id = name.strip_prefix('n')?.strip_suffix(".key")?.parse().ok()?;
            let (_, key) = self.load(id).ok()??;
            (key == public).then_some(id)
        })
    }

    fn path(&self, id: Id) -> PathBuf {
        self.dir.join(format!("n{id}.key"))
    }

    fn public(&self, private: &str) -> anyhow::Result<String> {
        Ok(self
            .r
            .run(&["wg", "pubkey"], Some(private))?
            .trim()
            .to_owned())
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
    fn issues_once_keeps_its_key_and_refuses_a_damaged_one() {
        let dir = tempfile::tempdir().unwrap();
        let tools = Tools::default();
        // A fresh store each time: what is on disk counts, not the cache.
        let keys = || Keys::new(&tools, dir.path());
        let (path, public) = keys().ensure(1).unwrap();
        let key = fs::read_to_string(&path).unwrap();
        assert_eq!(public, format!("pub-{}", key.trim()));
        assert_eq!(keys().ensure(1).unwrap().1, public, "kept");
        assert_ne!(keys().ensure(2).unwrap().1, public, "own key");
        fs::write(&path, "garbage").unwrap();
        assert!(keys().ensure(1).is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "garbage",
            "left for a human"
        );
        fs::remove_file(&path).unwrap();
        assert_ne!(keys().ensure(1).unwrap().1, public, "reissued");
    }

    #[test]
    fn loads_without_issuing_and_finds_a_keys_network() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        let tools = Tools::default();
        let keys = Keys::new(&tools, &dir);
        assert!(keys.load(4).unwrap().is_none());
        assert!(!dir.exists(), "reading creates nothing");
        let (_, four) = keys.ensure(4).unwrap();
        let (_, seven) = keys.ensure(7).unwrap();
        assert_eq!(keys.load(4).unwrap().unwrap().1, four);
        assert_eq!(Keys::new(&tools, &dir).owner_of(&seven), Some(7));
        assert_eq!(keys.owner_of("unknown"), None);
    }
}
