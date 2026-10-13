use std::net::Ipv4Addr;

use super::*;
use crate::compile::{DesiredState, Federation, NetRule, Network, Tenant, compile};
use crate::rights::RuleSet;
use crate::rule::Rule;
use crate::testing::{assert_golden, block, net, peer, rule_set, tcp};

fn rule(s: &str) -> Rule {
    s.parse().unwrap()
}

/// Tenant nexial: network `nexial` (a laptop and a router with a LAN; k8s API, node
/// pings, SSH into `nexial-dev`) and `nexial-dev` (mesh, a pod network may reach it on
/// 8080). Tenant krcmar: network `krcmar`, federated into `nexial-dev` on 443. The
/// netns tests load the rendered file into a kernel.
fn desired() -> DesiredState {
    let mut dev = Network {
        id: 2,
        tenant: 1,
        slug: "nexial-dev".parse().unwrap(),
        port: 51802,
        cidr: net("10.50.1.0/24"),
        mesh: true,
        rules: vec![],
        inbound: rule_set(&["tcp 10.244.0.0/16 8080"]),
    };
    dev.rules
        .push(NetRule::External(rule("tcp 172.16.16.1/32 6443")));
    DesiredState {
        pool: vec![net("10.50.0.0/16")],
        snat_source: Ipv4Addr::new(172, 19, 9, 10),
        node_cidrs: vec![net("172.19.9.0/24")],
        routed_space: vec![net("192.168.0.0/16")],
        reserved: vec![],
        tenants: vec![
            Tenant {
                id: 1,
                blocks: vec![block(1, "10.50.0.0/23")],
                ceiling: rule_set(&[
                    "tcp 172.16.16.1/32 6443",
                    "icmp 172.19.9.0/24",
                    "tcp 10.0.0.0/8 80-90",
                ]),
            },
            Tenant {
                id: 3,
                blocks: vec![block(2, "10.50.2.0/24")],
                ceiling: rule_set(&["tcp 172.16.16.1/32 6443"]),
            },
        ],
        networks: vec![
            Network {
                id: 1,
                tenant: 1,
                slug: "nexial".parse().unwrap(),
                port: 51801,
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
                slug: "krcmar".parse().unwrap(),
                port: 51803,
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
    }
}

fn sample() -> Compiled {
    let compiled = compile(&desired());
    assert!(compiled.skipped.is_empty() && compiled.invalid_networks.is_empty());
    compiled
}

#[test]
fn ruleset_golden() {
    assert_golden("ruleset.nft", &render_all(&sample()));
}

#[test]
fn router_lans_are_keyed_like_the_router() {
    let script = render_all(&sample());
    assert!(script.contains("192.168.10.0-192.168.10.255 . 172.16.16.1 . tcp . 6443"));
    assert!(script.contains("192.168.10.0-192.168.10.255 . 10.50.1.2 . tcp . 22"));
}

#[test]
fn node_cidrs_are_merged_without_tenant_space() {
    let mut state = desired();
    state.node_cidrs = [
        "172.19.9.0/24",
        "172.19.0.0/16",
        "172.19.9.0/24",
        "10.48.0.0/14",
    ]
    .iter()
    .map(|n| net(n))
    .collect();
    let script = render_all(&compile(&state));
    assert!(
        script.contains("ip daddr { 10.48.0.0/15, 10.51.0.0/16, 172.19.0.0/16 } snat"),
        "{script}"
    );
}

#[test]
fn empty_state_has_no_elements_or_snat() {
    let script = render_all(&compile(&DesiredState {
        pool: vec![],
        node_cidrs: vec![],
        tenants: vec![],
        networks: vec![],
        peers: vec![],
        federations: vec![],
        ..desired()
    }));
    assert!(!script.contains("add element"));
    assert!(!script.contains("snat"));
    assert!(script.contains("counter drop"));
}

#[test]
fn a_network_fragment_holds_only_its_own_peers() {
    let c = sample();
    let dev = c
        .networks
        .iter()
        .find(|n| n.iface == "wg-nexial-dev")
        .unwrap();
    let fragment = render_network(&c, dev);
    assert!(fragment.contains("add element inet wgate n2_peers {\n\t10.50.1.2,\n\t10.50.1.3\n}"));
    assert!(!fragment.contains("10.50.0.2 ."), "another network's peer");
    assert!(
        fragment.contains("add element inet wgate from_net { \"wg-nexial-dev\" : jump n2_from }")
    );
    // The base never touches a network's map entries, so re-applying it keeps them.
    assert!(!render_base(&c).contains("add element inet wgate from_net"));
    // SNAT is a transaction of its own, after the base.
    assert!(!render_base(&c).contains("snat"));
    assert!(render_snat(&c).contains("snat ip to"));
}

#[test]
fn a_purge_is_the_removal_without_map_entries() {
    let purge = render_network_purge(7);
    assert!(!purge.contains("element"));
    assert!(purge.contains("delete chain inet wgate n7_from"));
    assert!(purge.contains("delete set inet wgate n7_inbound_icmp"));
    // Both add what they delete first, so either applies whatever is already gone.
    let removal = render_network_removal(7, "wg-x");
    for script in [&purge, &removal] {
        let add = script.find("add chain inet wgate n7_from").unwrap();
        assert!(add < script.find("delete chain inet wgate n7_from").unwrap());
    }
    let deletes = purge
        .lines()
        .filter(|l| l.starts_with("delete"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(removal.trim_end().ends_with(&deletes));
}

#[test]
fn a_cutoff_drops_everything() {
    let cutoff = render_network_cutoff(7);
    for chain in ["n7_ingress", "n7_from", "n7_to"] {
        assert!(cutoff.contains(&format!(
            "flush chain inet wgate {chain}\nadd rule inet wgate {chain} counter drop"
        )));
    }
}

#[test]
fn removal_deletes_map_entries_before_chains() {
    let script = render_network_removal(7, "wg-x");
    let entry = script.find("delete element inet wgate from_net").unwrap();
    let chain = script.find("delete chain inet wgate n7_from").unwrap();
    assert!(entry < chain);
    assert!(script.contains("delete set inet wgate n7_inbound_icmp"));
}

#[test]
fn chain_names_name_their_network() {
    assert_eq!(network_of_chain("n12_from"), Some(12));
    assert_eq!(network_of_chain("n3_ingress"), Some(3));
    assert_eq!(network_of_chain("forward"), None);
}
