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
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(input.as_bytes()).context("write stdin")?;
        }
        let out = child.wait_with_output().context("wait")?;
        if !out.status.success() {
            // argv only, never stdin: it may carry a private key.
            bail!(
                "{} failed ({}): {}",
                argv.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        String::from_utf8(out.stdout).context("non-UTF-8 output")
    }
}
