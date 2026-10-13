//! Hub private keys: one per network (`n<id>.key`) in the keys directory (0600),
//! issued on first use and never deleted or replaced. They never leave the hub; only
//! the public key goes to the database.

use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use wgate_core::{Id, is_wg_key};

use crate::runner::Runner;

/// The keys directory, read through the tools' runner.
pub struct Keys<'a> {
    r: &'a dyn Runner,
    dir: &'a Path,
}

impl<'a> Keys<'a> {
    pub fn new(r: &'a dyn Runner, dir: &'a Path) -> Self {
        Self { r, dir }
    }

    /// Network `id`'s key file and public key; `None` when it has none.
    pub fn load(&self, id: Id) -> anyhow::Result<Option<(PathBuf, String)>> {
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
        Ok(Some((path, self.public(&private)?)))
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
        Ok((path.clone(), self.public(&private)?))
    }

    fn path(&self, id: Id) -> PathBuf {
        self.dir.join(format!("n{id}.key"))
    }

    fn public(&self, private: &str) -> anyhow::Result<String> {
        let public = self.r.run(&["wg", "pubkey"], Some(private))?;
        let public = public.trim();
        // It is published as the hub's key: only a key, never whatever was printed.
        if !is_wg_key(public) {
            bail!("wg pubkey printed no key");
        }
        Ok(public.to_owned())
    }
}

fn generate(r: &dyn Runner, path: &Path) -> anyhow::Result<String> {
    let key = r.run(&["wg", "genkey"], None)?;
    if !is_wg_key(key.trim()) {
        bail!("wg genkey printed no key");
    }
    crate::private::write(path, key.as_bytes())?;
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
                // A key of its own, told from the private one.
                _ => {
                    let mut key = stdin.unwrap_or_default().trim().to_owned();
                    key.replace_range(42..43, "E");
                    key
                }
            })
        }
    }

    #[test]
    fn issues_once_keeps_its_key_and_refuses_a_damaged_one() {
        let dir = tempfile::tempdir().unwrap();
        let tools = Tools::default();
        let keys = || Keys::new(&tools, dir.path());
        let (path, public) = keys().ensure(1).unwrap();
        let key = fs::read_to_string(&path).unwrap();
        assert_eq!(public, key.trim().replace("A=", "E="));
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
    fn loads_without_issuing() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("keys");
        let tools = Tools::default();
        let keys = Keys::new(&tools, &dir);
        assert!(keys.load(4).unwrap().is_none());
        assert!(!dir.exists(), "reading creates nothing");
        let (_, four) = keys.ensure(4).unwrap();
        let (_, seven) = keys.ensure(7).unwrap();
        assert_eq!(keys.load(4).unwrap().unwrap().1, four);
        assert_ne!(seven, four);
    }

    #[test]
    fn a_genkey_that_prints_no_key_issues_nothing() {
        struct Broken;
        impl Runner for Broken {
            fn run(&self, _: &[&str], _: Option<&str>) -> anyhow::Result<String> {
                Ok(String::new())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(Keys::new(&Broken, dir.path()).ensure(1).is_err());
        assert!(!dir.path().join("n1.key").exists());
        // Nor is a pubkey that prints no key taken for one.
        fs::write(dir.path().join("n2.key"), format!("{:0>42}A=", 2)).unwrap();
        assert!(Keys::new(&Broken, dir.path()).load(2).is_err());
    }
}
