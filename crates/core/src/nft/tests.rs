use super::*;
use crate::compile::{DesiredState, Federation, NetRule, Network, Peer, Tenant, compile};
use crate::rights::RuleSet;
use crate::rule::{PortRange, Rule};
use crate::testing::{assert_golden, rule_set};

fn net(s: &str) -> Ipv4Net {
    s.parse().unwrap()
}

fn rule(s: &str) -> Rule {
    s.parse().unwrap()
}

fn tcp(port: u16) -> Service {
    Service::Tcp(PortRange::new(port, port).unwrap())
}

fn peer(id: i64, network: i64, ip: &str, routed: &[&str]) -> Peer {
    Peer {
        id,
        network,
        ip: ip.parse().unwrap(),
        routed: routed.iter().map(|r| net(r)).collect(),
    }
}

/// Tenant nexial: network `nexial` (a laptop and a router with a LAN; k8s API, node
/// pings, SSH into `nexial-dev`) and `nexial-dev` (mesh, a pod network may reach it on
/// 8080). Tenant krcmar: network `krcmar`, federated into `nexial-dev` on 443. The
/// netns tests load the rendered file into a kernel.
fn sample_state() -> NftState {
    let mut dev = Network {
        id: 2,
        tenant: 1,
        cidr: net("10.50.1.0/24"),
        mesh: true,
        rules: vec![],
        inbound: rule_set(&["tcp 10.244.0.0/16 8080"]),
    };
    dev.rules
        .push(NetRule::External(rule("tcp 172.16.16.1/32 6443")));
    let state = DesiredState {
        pool: vec![net("10.50.0.0/16")],
        tenants: vec![
            Tenant {
                id: 1,
                ceiling: rule_set(&[
                    "tcp 172.16.16.1/32 6443",
                    "icmp 172.19.9.0/24",
                    "tcp 10.0.0.0/8 80-90",
                ]),
            },
            Tenant {
                id: 3,
                ceiling: rule_set(&["tcp 172.16.16.1/32 6443"]),
            },
        ],
        networks: vec![
            Network {
                id: 1,
                tenant: 1,
                cidr: net("10.50.0.0/24"),
                mesh: false,
                rules: vec![
                    NetRule::External(rule("tcp 172.16.16.1/32 6443")),
                    NetRule::External(rule("icmp 172.19.9.10/32")),
                    NetRule::External(rule("icmp 172.19.9.11/32")),
                    NetRule::External(rule("icmp 172.19.9.12/32")),
                    // Overlapping external rules must still render disjoint.
                    NetRule::External(rule("tcp 10.0.0.0/8 80-90")),
                    NetRule::External(rule("tcp 10.1.0.0/16 85-100")),
                    NetRule::To {
                        network: 2,
                        service: tcp(22),
                    },
                ],
                inbound: RuleSet::new(),
            },
            dev,
            Network {
                id: 3,
                tenant: 3,
                cidr: net("10.50.2.0/24"),
                mesh: false,
                rules: vec![NetRule::External(rule("tcp 172.16.16.1/32 6443"))],
                inbound: RuleSet::new(),
            },
        ],
        peers: vec![
            peer(11, 1, "10.50.0.2", &[]),
            peer(12, 1, "10.50.0.3", &["192.168.10.0/24"]),
            peer(21, 2, "10.50.1.2", &[]),
            peer(22, 2, "10.50.1.3", &[]),
            peer(31, 3, "10.50.2.2", &[]),
        ],
        federations: vec![Federation {
            from: 3,
            to: 2,
            service: tcp(443),
        }],
    };
    let compiled = compile(&state);
    assert!(compiled.skipped.is_empty());
    NftState {
        snat_source: Ipv4Addr::new(172, 19, 9, 10),
        node_cidrs: vec![net("172.19.9.0/24")],
        pool: state.pool,
        peers: compiled.peers,
    }
}

#[test]
fn ruleset_golden() {
    let out = render_nft(&sample_state());
    assert!(out.skipped.is_empty());
    assert_golden("ruleset.nft", &out.script);
}

#[test]
fn router_lans_are_keyed_like_the_router() {
    let script = render_nft(&sample_state()).script;
    assert!(script.contains("192.168.10.0-192.168.10.255 . 172.16.16.1 . tcp . 6443"));
    assert!(script.contains("192.168.10.0-192.168.10.255 . 10.50.1.2 . tcp . 22"));
}

#[test]
fn overlapping_peers_are_left_out() {
    let mut state = sample_state();
    let mut twin = state.peers[0].clone();
    twin.id = 99;
    state.peers.push(twin);
    let out = render_nft(&state);
    let first = state.peers[0].id;
    assert_eq!(out.skipped, [first, 99]);
    assert!(!out.script.contains(&format!("{} . ", state.peers[0].ip)));
}

#[test]
fn node_cidrs_are_merged_without_tenant_space() {
    let mut state = sample_state();
    state.node_cidrs = [
        "172.19.9.0/24",
        "172.19.0.0/16",
        "172.19.9.0/24",
        "10.48.0.0/14",
    ]
    .iter()
    .map(|n| net(n))
    .collect();
    let script = render_nft(&state).script;
    assert!(
        script.contains("ip daddr { 10.48.0.0/15, 10.51.0.0/16, 172.19.0.0/16 } snat"),
        "{script}"
    );
}

#[test]
fn empty_state_has_no_elements_or_snat() {
    let script = render_nft(&NftState {
        snat_source: Ipv4Addr::new(172, 19, 9, 10),
        node_cidrs: vec![],
        pool: vec![],
        peers: vec![],
    })
    .script;
    assert!(!script.contains("elements"));
    assert!(!script.contains("snat"));
    assert!(script.contains("counter drop"));
}
