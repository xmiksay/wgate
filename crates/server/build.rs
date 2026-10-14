//! Stages the built UI (`web/dist`) for embedding. Without one (no `make web` yet: a
//! plain `cargo build` or `cargo test`), a stub page says how to build it, so the
//! Rust side never needs Node; a release build without it fails instead of shipping
//! a portal with no UI. The Makefile builds the UI before lint and tests, so they
//! embed (and test) the real one.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const STUB: &str = "<!doctype html><meta charset=utf-8><title>wgate</title>\
<p>The UI is not built into this binary: run <code>make web</code>, then rebuild.</p>\n";

fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| io::Error::other("CARGO_MANIFEST_DIR unset"))?,
    );
    let out = PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("OUT_DIR unset"))?,
    )
    .join("ui");
    let dist = manifest.join("../../web/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    if out.exists() {
        fs::remove_dir_all(&out)?;
    }
    if dist.join("index.html").is_file() {
        copy_dir(&dist, &out)
    } else if std::env::var("PROFILE").is_ok_and(|p| p == "release") {
        Err(io::Error::other(format!(
            "no UI at {}: run `make web` before a release build",
            dist.display()
        )))
    } else {
        fs::create_dir_all(&out)?;
        fs::write(out.join("index.html"), STUB)
    }
}
