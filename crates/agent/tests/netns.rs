//! Root-only tests in throwaway network namespaces. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::process::{Command, Stdio};

/// A network namespace deleted on drop, so a failed assertion leaves nothing behind.
struct Netns(String);

impl Netns {
    fn new(tag: &str) -> Self {
        let name = format!("wgate-{tag}-{}", std::process::id());
        run(Command::new("ip").args(["netns", "add", &name]), None);
        Self(name)
    }

    fn exec(&self, argv: &[&str], stdin: Option<&str>) {
        run(
            Command::new("ip")
                .args(["netns", "exec", &self.0])
                .args(argv),
            stdin,
        );
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}

fn run(cmd: &mut Command, stdin: Option<&str>) {
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

/// The kernel features the design depends on: a `wg-*` interface and an nft set
/// with concatenated interval keys (design.md → Risks).
#[test]
#[ignore = "needs root: make test-netns"]
fn kernel_supports_wg_and_concat_interval_sets() {
    let ns = Netns::new("smoke");
    ns.exec(
        &["ip", "link", "add", "wg-smoke", "type", "wireguard"],
        None,
    );
    ns.exec(
        &["nft", "-f", "-"],
        Some(
            "table inet wgate {
               set allow {
                 type ipv4_addr . ipv4_addr . inet_proto . inet_service; flags interval;
                 elements = { 10.50.1.2 . 172.16.16.1 . tcp . 6443,
                              10.50.1.0/24 . 172.19.9.10-172.19.9.12 . udp . 1000-2000 }
               }
             }",
        ),
    );
}
