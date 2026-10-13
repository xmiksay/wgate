//! Files only root may read (hub keys, the saved state), written whole.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;

/// Written 0600 to a temporary file, synced, then renamed: a crash leaves either the
/// previous file (or none) or the whole new one.
pub fn write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = Path::new(&tmp);
    let _ = fs::remove_file(tmp);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    if let Some(dir) = path.parent() {
        File::open(dir).and_then(|d| d.sync_all()).ok();
    }
    Ok(())
}
