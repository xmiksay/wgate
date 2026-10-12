//! Helpers shared by the root-only netns test crates.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

/// A network namespace deleted on drop, so a failed assertion leaves nothing behind.
pub struct Netns(pub String);

impl Netns {
    pub fn new(tag: &str) -> Self {
        let name = format!("wgate-{tag}-{}", std::process::id());
        run(Command::new("ip").args(["netns", "add", &name]), None);
        Self(name)
    }

    pub fn cmd(&self, argv: &[&str]) -> Command {
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", &self.0]).args(argv);
        cmd
    }

    pub fn exec(&self, argv: &[&str], stdin: Option<&str>) {
        run(&mut self.cmd(argv), stdin);
    }

    pub fn output(&self, argv: &[&str]) -> String {
        let out = self.cmd(argv).output().expect("spawn");
        assert!(
            out.status.success(),
            "{argv:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).expect("utf-8")
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}

pub fn run(cmd: &mut Command, stdin: Option<&str>) {
    let mut child = cmd
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .spawn()
        .expect("spawn");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input.as_bytes())
            .expect("write stdin");
    }
    let status = child.wait().expect("wait");
    assert!(status.success(), "{cmd:?} failed: {status}");
}

impl Netns {
    /// Exit status only; for probes that are expected to fail.
    pub fn succeeds(&self, argv: &[&str]) -> bool {
        self.cmd(argv)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn")
            .success()
    }

    /// A background process, killed on drop, with its stdout piped.
    pub fn spawn(&self, argv: &[&str]) -> Background {
        let child = self
            .cmd(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn");
        Background(child)
    }
}

pub struct Background(pub Child);

impl Background {
    /// Blocks until the process prints a line (e.g. a server's "ready").
    pub fn wait_line(&mut self) -> String {
        let mut line = String::new();
        BufReader::new(self.stdout())
            .read_line(&mut line)
            .expect("read");
        line
    }

    pub fn stdout(&mut self) -> &mut ChildStdout {
        self.0.stdout.as_mut().expect("piped stdout")
    }

    pub fn take_stdout(&mut self) -> ChildStdout {
        self.0.stdout.take().expect("piped stdout")
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
