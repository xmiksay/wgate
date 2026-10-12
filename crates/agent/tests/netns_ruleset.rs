//! The rendered ruleset against real packets. Hub-side veth links named `wg-*` stand
//! in for WireGuard interfaces (its source check is not under test here); python3
//! provides the TCP/UDP endpoints. Run with `make test-netns`.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::io::BufRead;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{Background, Netns};
use ipnet::Ipv4Net;
use wgate_core::{
    DesiredState, Federation, NetRule, Network, NftState, Peer, PortRange, RuleSet, Service,
    Tenant, compile, render_nft,
};

const ECHO: &str = r#"
import socket, sys, threading
def echo(c):
    while (d := c.recv(64)):
        c.sendall(d)
def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    while True:
        threading.Thread(target=echo, args=(s.accept()[0],), daemon=True).start()
for p in sys.argv[1:]:
    threading.Thread(target=serve, args=(int(p),), daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
"#;

/// Exit 0 when a TCP echo round trip to host:port works within a second.
const PROBE: &str = r#"
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1)
    s.sendall(b"x")
    sys.exit(0 if s.recv(1) == b"x" else 1)
except OSError:
    sys.exit(1)
"#;

/// One open connection; prints "ok" per echo every 100 ms for argv[3] seconds.
const STREAM: &str = r#"
import socket, sys, time
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1)
s.settimeout(0.3)
end = time.monotonic() + float(sys.argv[3])
while time.monotonic() < end:
    try:
        s.sendall(b"x")
        if s.recv(1):
            print("ok", flush=True)
    except OSError:
        pass
    time.sleep(0.1)
"#;

/// Sends one UDP datagram from a chosen source address.
const SPOOF: &str = r#"
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(b"x", (sys.argv[2], int(sys.argv[3])))
"#;

const A: &str = "10.50.0.2"; // tenant 1, network 1
const B: &str = "10.50.1.2"; // tenant 1, network 2
const C: &str = "10.50.2.2"; // tenant 2, network 3
const NODE: &str = "172.19.9.11";

/// hub ─ wg-n1 ─ a, wg-n2 ─ b, wg-n3 ─ c, eth-node ─ node (no route back to the
/// pool: needs SNAT), eth-pod ─ pod (outside the pool).
struct Lab {
    hub: Netns,
    a: Netns,
    b: Netns,
    c: Netns,
    _node: Netns,
    pod: Netns,
    _servers: Vec<Background>,
}

impl Lab {
    fn new() -> Self {
        let hub = Netns::new("hub");
        hub.exec(&["sysctl", "-qw", "net.ipv4.ip_forward=1"], None);
        hub.exec(&["ip", "link", "set", "lo", "up"], None);
        let link = |tag: &str, iface: &str, hub_addr: &str, addr: &str, gw: Option<&str>| {
            let ns = Netns::new(tag);
            hub.exec(
                &[
                    "ip", "link", "add", iface, "type", "veth", "peer", "name", "p0", "netns",
                    &ns.0,
                ],
                None,
            );
            hub.exec(&["ip", "addr", "add", hub_addr, "dev", iface], None);
            hub.exec(&["ip", "link", "set", iface, "up"], None);
            ns.exec(&["ip", "addr", "add", addr, "dev", "p0"], None);
            ns.exec(&["ip", "link", "set", "p0", "up"], None);
            ns.exec(&["ip", "link", "set", "lo", "up"], None);
            if let Some(gw) = gw {
                ns.exec(&["ip", "route", "add", "default", "via", gw], None);
            }
            ns
        };
        let a = link(
            "a",
            "wg-n1",
            "10.50.0.1/24",
            "10.50.0.2/24",
            Some("10.50.0.1"),
        );
        let b = link(
            "b",
            "wg-n2",
            "10.50.1.1/24",
            "10.50.1.2/24",
            Some("10.50.1.1"),
        );
        let c = link(
            "c",
            "wg-n3",
            "10.50.2.1/24",
            "10.50.2.2/24",
            Some("10.50.2.1"),
        );
        let node = link("node", "eth-node", "172.19.9.10/24", "172.19.9.11/24", None);
        let pod = link(
            "pod",
            "eth-pod",
            "10.244.0.1/24",
            "10.244.0.5/24",
            Some("10.244.0.1"),
        );
        let mut servers = Vec::new();
        for (ns, ports) in [
            (&a, &["7000", "7100", "7200"][..]),
            (&b, &["7000", "7100", "7200"][..]),
            (&node, &["8080", "8081"][..]),
        ] {
            let mut argv = vec!["python3", "-c", ECHO];
            argv.extend(ports);
            let mut server = ns.spawn(&argv);
            assert_eq!(server.wait_line().trim(), "ready");
            servers.push(server);
        }
        Self {
            hub,
            a,
            b,
            c,
            _node: node,
            pod,
            _servers: servers,
        }
    }

    fn apply(&self, state: &DesiredState) {
        let compiled = compile(state);
        assert!(compiled.skipped.is_empty(), "{:?}", compiled.skipped);
        let render = render_nft(&NftState {
            snat_source: "172.19.9.10".parse().expect("addr"),
            node_cidrs: vec![net("172.19.9.0/24")],
            tenant_space: compiled.tenant_space,
            peers: compiled.peers,
        });
        self.hub.exec(&["nft", "-f", "-"], Some(&render.script));
    }
}

fn tcp_ok(from: &Netns, host: &str, port: u16) -> bool {
    from.succeeds(&["python3", "-c", PROBE, host, &port.to_string()])
}

fn net(s: &str) -> Ipv4Net {
    s.parse().expect("cidr")
}

fn tcp(port: u16) -> Service {
    Service::Tcp(PortRange::new(port, port).expect("port"))
}

fn rules(rules: &[&str]) -> RuleSet {
    let rules: Vec<_> = rules.iter().map(|r| r.parse().expect("rule")).collect();
    RuleSet::from_rules(&rules)
}

/// Network 1 may reach the node (ping, tcp 8080) and network 2 on 7000; the pod
/// network may reach network 2 on 7100; network 3 (tenant 2) is federated into
/// network 2 on 7200.
fn state() -> DesiredState {
    let external = |r: &str| NetRule::External(r.parse().expect("rule"));
    let network = |id, tenant, cidr: &str, rules| Network {
        id,
        tenant,
        cidr: net(cidr),
        mesh: false,
        rules,
        inbound: RuleSet::new(),
    };
    let mut n2 = network(2, 1, "10.50.1.0/24", vec![]);
    n2.inbound = rules(&["tcp 10.244.0.0/16 7100"]);
    let peer = |id, network, ip: &str| Peer {
        id,
        network,
        ip: ip.parse().expect("addr"),
        routed: vec![],
    };
    DesiredState {
        pool: vec![net("10.50.0.0/16")],
        tenants: vec![
            Tenant {
                id: 1,
                ceiling: rules(&["icmp 172.19.9.0/24", "tcp 172.19.9.0/24 8080"]),
            },
            Tenant {
                id: 2,
                ceiling: RuleSet::new(),
            },
        ],
        networks: vec![
            network(
                1,
                1,
                "10.50.0.0/24",
                vec![
                    external("icmp 172.19.9.11/32"),
                    external("tcp 172.19.9.11/32 8080"),
                    NetRule::To {
                        network: 2,
                        service: tcp(7000),
                    },
                ],
            ),
            n2,
            network(3, 2, "10.50.2.0/24", vec![]),
        ],
        peers: vec![peer(1, 1, A), peer(2, 2, B), peer(3, 3, C)],
        federations: vec![Federation {
            from: 3,
            to: 2,
            service: tcp(7200),
        }],
    }
}

#[test]
#[ignore = "needs root: make test-netns"]
fn external_access_follows_rules_and_snat() {
    let lab = Lab::new();
    lab.apply(&state());
    assert!(
        lab.a.succeeds(&["ping", "-c1", "-W1", NODE]),
        "ping through SNAT"
    );
    assert!(tcp_ok(&lab.a, NODE, 8080));
    assert!(!tcp_ok(&lab.a, NODE, 8081), "port not granted");
    assert!(
        !lab.b.succeeds(&["ping", "-c1", "-W1", NODE]),
        "network 2 has no rule"
    );
    // The pod has a route into the pool, so only the ruleset can stop these.
    assert!(
        !lab.pod.succeeds(&["ping", "-c1", "-W1", A]),
        "nothing opens into a peer"
    );
    assert!(!tcp_ok(&lab.pod, A, 7000), "nothing opens into a peer");
}

#[test]
#[ignore = "needs root: make test-netns"]
fn peer_to_peer_needs_a_rule_or_federation() {
    let lab = Lab::new();
    lab.apply(&state());
    assert!(tcp_ok(&lab.a, B, 7000), "rule 1 → 2");
    assert!(!tcp_ok(&lab.b, A, 7000), "rules are one-way");
    assert!(!tcp_ok(&lab.a, B, 7200), "wrong port");
    assert!(tcp_ok(&lab.c, B, 7200), "federation 3 → 2");
    assert!(!tcp_ok(&lab.c, A, 7200), "no federation into 1");
    assert!(tcp_ok(&lab.pod, B, 7100), "inbound grant");
    assert!(!tcp_ok(&lab.pod, A, 7100), "no grant for 1");
}

#[test]
#[ignore = "needs root: make test-netns"]
fn spoofed_tenant_sources_are_dropped() {
    let lab = Lab::new();
    lab.apply(&state());
    lab.pod
        .exec(&["ip", "addr", "add", "10.50.0.2/32", "dev", "p0"], None);
    lab.pod.exec(&["python3", "-c", SPOOF, A, B, "7000"], None);
    let chain = lab
        .hub
        .output(&["nft", "list", "chain", "inet", "wgate", "prerouting"]);
    let spoof = chain
        .lines()
        .find(|l| l.contains("ip saddr @tenant_space counter"))
        .expect("spoof rule");
    assert!(spoof.contains("packets 1 "), "{spoof}");
}

/// Removing a right cuts a connection that is already open, even though conntrack
/// still has it.
#[test]
#[ignore = "needs root: make test-netns"]
fn revocation_cuts_live_streams() {
    for (from, to, port, revoke) in [
        ("a", B, 7000, revoke_rule as fn(&mut DesiredState)),
        ("pod", B, 7100, revoke_grant),
        ("c", B, 7200, revoke_federation),
    ] {
        let lab = Lab::new();
        let mut state = state();
        lab.apply(&state);
        let src = match from {
            "a" => &lab.a,
            "pod" => &lab.pod,
            _ => &lab.c,
        };
        let mut stream = src.spawn(&["python3", "-c", STREAM, to, &port.to_string(), "3"]);
        let (tx, rx) = mpsc::channel();
        let out = stream.take_stdout();
        std::thread::spawn(move || {
            for _ in out.lines() {
                let _ = tx.send(Instant::now());
            }
        });
        for _ in 0..3 {
            rx.recv_timeout(Duration::from_secs(2))
                .expect("stream is up");
        }
        revoke(&mut state);
        lab.apply(&state);
        let revoked = Instant::now();
        let late: Vec<_> = rx
            .iter()
            .filter(|t| *t > revoked + Duration::from_millis(300))
            .collect();
        assert!(
            late.is_empty(),
            "{from} → {to}:{port} still flowing after revocation"
        );
    }
}

fn revoke_rule(s: &mut DesiredState) {
    s.networks[0]
        .rules
        .retain(|r| !matches!(r, NetRule::To { .. }));
}

fn revoke_grant(s: &mut DesiredState) {
    s.networks[1].inbound = RuleSet::new();
}

fn revoke_federation(s: &mut DesiredState) {
    s.federations.clear();
}
