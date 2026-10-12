//! Root-only tests in throwaway network namespaces. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use wgate_core::{NftState, render_nft};

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

impl Netns {
    fn output(&self, argv: &[&str]) -> String {
        let out = Command::new("ip")
            .args(["netns", "exec", &self.0])
            .args(argv)
            .output()
            .expect("spawn");
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

/// The rendered ruleset golden (core) must be accepted by the kernel — overlapping
/// interval elements are rejected — and applying another render must replace it.
#[test]
#[ignore = "needs root: make test-netns"]
fn rendered_ruleset_loads_and_replaces() {
    let ns = Netns::new("ruleset");
    ns.exec(
        &["nft", "-f", "-"],
        Some(include_str!("../../core/tests/golden/ruleset.nft")),
    );
    assert!(
        ns.output(&["nft", "list", "table", "inet", "wgate"])
            .contains("10.50.1.2 . ")
    );

    let empty = render_nft(&NftState {
        snat_source: Ipv4Addr::new(172, 19, 9, 10),
        node_cidrs: vec![],
        devices: vec![],
    });
    ns.exec(&["nft", "-f", "-"], Some(&empty.script));
    let listed = ns.output(&["nft", "list", "table", "inet", "wgate"]);
    assert!(
        !listed.contains("10.50.1."),
        "stale elements survived:\n{listed}"
    );
    assert!(!listed.contains("snat"), "stale snat survived:\n{listed}");
}
