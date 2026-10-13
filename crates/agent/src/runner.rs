//! Running `ip`, `wg` and `nft`. All kernel changes go through one runner, so the
//! reconcile logic is tested against fake tool output.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, bail};
use wait_timeout::ChildExt;

pub trait Runner {
    /// Runs `argv` (with `stdin` fed in) and returns its stdout; a non-zero exit is an
    /// error carrying stderr.
    fn run(&self, argv: &[&str], stdin: Option<&str>) -> anyhow::Result<String>;
}

/// The real tools, optionally inside a network namespace (`ip netns exec <name>`).
#[derive(Clone, Debug)]
pub struct System {
    prefix: Vec<String>,
    /// A tool still running after this is killed: one hung command must not stall
    /// every later reconcile.
    timeout: Duration,
}

impl Default for System {
    fn default() -> Self {
        Self {
            prefix: vec![],
            timeout: Duration::from_secs(30),
        }
    }
}

impl System {
    pub fn in_netns(name: &str) -> Self {
        Self {
            prefix: ["ip", "netns", "exec", name].map(str::to_owned).to_vec(),
            ..Self::default()
        }
    }

    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
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
                Some(thread::spawn(move || pipe.write_all(input.as_bytes())))
            }
            _ => None,
        };
        // Read on threads that report back, so a helper that kept the pipes open
        // after the tool exited cannot hold the reconcile.
        let drain = |pipe: Option<Box<dyn Read + Send>>| {
            let (tx, rx) = std::sync::mpsc::channel();
            thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut pipe) = pipe {
                    let _ = pipe.read_to_end(&mut buf);
                }
                let _ = tx.send(buf);
            });
            rx
        };
        let started = std::time::Instant::now();
        let stdout = drain(child.stdout.take().map(|p| Box::new(p) as _));
        let stderr = drain(child.stderr.take().map(|p| Box::new(p) as _));
        let waited = child.wait_timeout(self.timeout);
        let Ok(Some(status)) = waited else {
            // Timed out, or the wait itself failed: no tool is left running.
            let _ = child.kill();
            let _ = child.wait();
            match waited {
                Err(e) => return Err(e).context("wait"),
                _ => bail!("{} timed out after {:?}", argv.join(" "), self.timeout),
            }
        };
        let left = || {
            self.timeout
                .saturating_sub(started.elapsed())
                .max(Duration::from_millis(100))
        };
        let out = std::process::Output {
            status,
            stdout: stdout.recv_timeout(left()).unwrap_or_default(),
            stderr: stderr.recv_timeout(left()).unwrap_or_default(),
        };
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
        // A helper that keeps the pipe open past the tool's exit holds nothing up.
        let quick = System::default().with_timeout(Duration::from_millis(500));
        let started = std::time::Instant::now();
        quick
            .run(&["sh", "-c", "(sleep 3) & echo hi"], None)
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        let slow = System::default().with_timeout(Duration::from_millis(200));
        let err = slow.run(&["sleep", "5"], None).unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }
}
