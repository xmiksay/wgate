//! Helpers shared by the root-only netns test crates.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

pub mod py;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use sea_orm::{Database, DatabaseConnection};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

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
        let mut child = self
            .cmd(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn");
        let out = child.stdout.take().expect("piped stdout");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send((Instant::now(), line)).is_err() {
                    break;
                }
            }
        });
        Background { child, lines }
    }
}

/// A process with its stdout lines (and when each arrived) read on a thread, so a
/// test can wait with a timeout instead of hanging on a process that never prints.
pub struct Background {
    child: Child,
    pub lines: Receiver<(Instant, String)>,
}

impl Background {
    /// The next line, or a panic naming `what` after 10 s.
    pub fn expect_line(&self, what: &str) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|e| panic!("{what}: {e}"))
            .1
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Exit 0 when a TCP echo round trip (`py::PROBE`) works within a second.
pub fn tcp_ok(from: &Netns, host: &str, port: u16) -> bool {
    from.succeeds(&["python3", "-c", py::PROBE, host, &port.to_string()])
}

pub fn ping_ok(from: &Netns, host: &str) -> bool {
    from.succeeds(&["ping", "-c", "1", "-W", "2", host])
}

/// A migrated Postgres 17 in Docker: the container (stops on drop), its URL, a
/// connection.
pub async fn postgres() -> (ContainerAsync<Postgres>, String, DatabaseConnection) {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("start postgres (is Docker running?)");
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let db = Database::connect(&url).await.expect("connect");
    wgate_db::migrate(&db).await.expect("migrate");
    (container, url, db)
}
