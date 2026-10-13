//! Running `ip`, `wg` and `nft`. All kernel changes go through one runner, so the
//! reconcile logic is tested against fake tool output.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, bail};

pub trait Runner {
    /// Runs `argv` (with `stdin` fed in) and returns its stdout; a non-zero exit is an
    /// error carrying stderr.
    fn run(&self, argv: &[&str], stdin: Option<&str>) -> anyhow::Result<String>;
}

/// The real tools, optionally inside a network namespace (`ip netns exec <name>`).
#[derive(Clone, Debug, Default)]
pub struct System {
    prefix: Vec<String>,
}

impl System {
    pub fn in_netns(name: &str) -> Self {
        Self {
            prefix: ["ip", "netns", "exec", name].map(str::to_owned).to_vec(),
        }
    }
}

impl Runner for System {
    fn run(&self, argv: &[&str], stdin: Option<&str>) -> anyhow::Result<String> {
        let full: Vec<&str> = self
            .prefix
            .iter()
            .map(String::as_str)
            .chain(argv.iter().copied())
            .collect();
        let (program, args) = full.split_first().context("empty command")?;
        let mut child = Command::new(program)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn {program}"))?;
        // Fed from a thread while the output is drained: a tool that writes a lot
        // before reading all its input cannot deadlock us, and one that exits early
        // still has its stderr reported.
        let feeder = match (stdin, child.stdin.take()) {
            (Some(input), Some(mut pipe)) => {
                let input = input.to_owned();
                Some(std::thread::spawn(move || pipe.write_all(input.as_bytes())))
            }
            _ => None,
        };
        let out = child.wait_with_output().context("wait")?;
        let fed = feeder.map(|f| f.join());
        if !out.status.success() {
            // argv only, never stdin: it may carry a private key.
            bail!(
                "{} failed ({}): {}",
                argv.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        if let Some(Ok(Err(e))) = fed {
            bail!("{}: writing its input failed: {e}", argv.join(" "));
        }
        String::from_utf8(out.stdout).context("non-UTF-8 output")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_feeds_and_reports_failures() {
        let sh = System::default();
        assert_eq!(sh.run(&["cat"], Some("hello")).unwrap(), "hello");
        // Much more output than a pipe buffer, while input is still being fed.
        let big = "x".repeat(1 << 20);
        assert_eq!(sh.run(&["cat"], Some(&big)).unwrap().len(), big.len());
        let err = sh
            .run(&["sh", "-c", "echo nope >&2; exit 3"], None)
            .unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
    }
}
