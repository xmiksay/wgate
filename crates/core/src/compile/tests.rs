use super::*;
use crate::rule::{PortRange, Proto};
use crate::testing::rule_set;

fn net(s: &str) -> Ipv4Net {
    s.parse().unwrap()
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn tcp(port: u16) -> Service {
    Service::Tcp(PortRange::new(port, port).unwrap())
}

fn network(id: Id, tenant: Id, cidr: &str, mesh: bool, rules: Vec<NetRule>) -> Network {
    Network {
        id,
        tenant,
        cidr: net(cidr),
        mesh,
        rules,
        inbound: RuleSet::new(),
    }
}

fn peer(id: Id, network: Id, addr: &str, routed: &[&str]) -> Peer {
    Peer {
        id,
        network,
        ip: ip(addr),
        routed: routed.iter().map(|r| net(r)).collect(),
    }
}

fn external(rule: &str) -> NetRule {
    NetRule::External(rule.parse().unwrap())
}

const A: Id = 1;
const B: Id = 2;
const C: Id = 3;

/// Tenant 10: networks A (router a1 with a LAN) and B (mesh); tenant 20: network C,
/// federated into B on 443.
fn state() -> DesiredState {
    let mut a = network(
        A,
        10,
        "10.50.0.0/28",
        false,
        vec![
            external("tcp 172.16.16.1/32 6443"),
            external("tcp 172.16.16.1/32 22"),
            external("tcp 10.50.0.0/16 443"),
            NetRule::To {
                network: B,
                service: tcp(22),
            },
        ],
    );
    a.inbound = rule_set(&["tcp 10.244.0.0/16 8080"]);
    DesiredState {
        pool: vec![net("10.50.0.0/16")],
        tenants: vec![
            Tenant {
                id: 10,
                ceiling: rule_set(&["tcp 172.16.16.1/32 6443", "tcp 10.0.0.0/8 443"]),
            },
            Tenant {
                id: 20,
                ceiling: RuleSet::new(),
            },
        ],
        networks: vec![
            a,
            network(B, 10, "10.50.0.16/28", true, vec![]),
            network(
                C,
                20,
                "10.50.1.0/28",
                false,
                vec![NetRule::To {
                    network: A,
                    service: tcp(80),
                }],
            ),
        ],
        peers: vec![
            peer(11, A, "10.50.0.2", &["192.168.1.0/24"]),
            peer(21, B, "10.50.0.18", &[]),
            peer(22, B, "10.50.0.19", &[]),
            peer(31, C, "10.50.1.2", &[]),
        ],
        federations: vec![Federation {
            from: C,
            to: B,
            service: tcp(443),
        }],
    }
}

fn get(c: &Compiled, id: Id) -> &CompiledPeer {
    c.peers.iter().find(|p| p.id == id).unwrap()
}

#[test]
fn outbound_follows_rules_ceiling_and_tenant_space() {
    let c = compile(&state());
    assert!(c.skipped.is_empty(), "{:?}", c.skipped);
    let a1 = get(&c, 11);
    let k8s = ip("172.16.16.1");
    assert!(a1.outbound.allows(Proto::Tcp, k8s, 6443));
    assert!(
        !a1.outbound.allows(Proto::Tcp, k8s, 22),
        "outside the ceiling"
    );
    // An external rule never reaches tenant space, even with a ceiling covering it.
    assert!(!a1.outbound.allows(Proto::Tcp, ip("10.50.0.18"), 443));
    assert!(a1.outbound.allows(Proto::Tcp, ip("10.50.0.18"), 22));
    assert!(a1.outbound.allows(Proto::Tcp, ip("10.50.0.19"), 22));
    assert!(
        !a1.outbound.allows(Proto::Tcp, ip("10.50.1.2"), 22),
        "another tenant"
    );
    assert_eq!(a1.addrs, [net("10.50.0.2/32"), net("192.168.1.0/24")]);
}

#[test]
fn inbound_mirrors_rules_mesh_federation_and_grants() {
    let c = compile(&state());
    let b1 = get(&c, 21);
    // From A's router and its LAN, per A's rule.
    assert!(b1.inbound.allows(Proto::Tcp, ip("10.50.0.2"), 22));
    assert!(b1.inbound.allows(Proto::Tcp, ip("192.168.1.77"), 22));
    assert!(!b1.inbound.allows(Proto::Tcp, ip("10.50.0.2"), 80));
    // Mesh: the other member on everything, not itself.
    assert!(b1.inbound.allows(Proto::Udp, ip("10.50.0.19"), 5353));
    assert!(b1.outbound.allows(Proto::Icmp, ip("10.50.0.19"), 0));
    assert!(!b1.outbound.allows(Proto::Icmp, ip("10.50.0.18"), 0));
    // Federation C → B.
    assert!(b1.inbound.allows(Proto::Tcp, ip("10.50.1.2"), 443));
    let c1 = get(&c, 31);
    assert!(c1.outbound.allows(Proto::Tcp, ip("10.50.0.18"), 443));
    // C's own rule into another tenant's network is ignored.
    assert!(!c1.outbound.allows(Proto::Tcp, ip("10.50.0.2"), 80));
    assert!(!get(&c, 11).inbound.allows(Proto::Tcp, ip("10.50.1.2"), 80));
    // Inbound grant from outside the pool.
    assert!(
        get(&c, 11)
            .inbound
            .allows(Proto::Tcp, ip("10.244.3.4"), 8080)
    );
}

#[test]
fn networks_outside_the_pool_or_overlapping_fail_closed() {
    let mut s = state();
    s.networks
        .push(network(4, 10, "192.168.50.0/24", true, vec![]));
    s.networks
        .push(network(5, 10, "10.50.0.0/29", true, vec![]));
    s.peers.push(peer(41, 4, "192.168.50.2", &[]));
    s.peers.push(peer(51, 5, "10.50.0.5", &[]));
    let c = compile(&s);
    let mut skipped = c.skipped.clone();
    skipped.sort_by_key(|(id, _)| *id);
    // Network 5 overlaps the older A: only 5's peers fail closed.
    assert_eq!(
        skipped,
        [(41, Problem::InvalidNetwork), (51, Problem::InvalidNetwork)]
    );
}

#[test]
fn lans_of_skipped_routers_stay_tenant_space() {
    let mut s = state();
    s.tenants[0].ceiling = rule_set(&["tcp 192.168.0.0/16 80"]);
    s.networks[0].rules.push(external("tcp 192.168.0.0/16 80"));
    s.peers.push(peer(12, A, "10.50.0.3", &[]));
    s.peers.push(peer(
        32,
        C,
        "10.50.1.3",
        &["192.168.3.0/24", "192.168.3.0/25"],
    ));
    let c = compile(&s);
    assert_eq!(c.skipped, [(32, Problem::Overlap)]);
    let a2 = get(&c, 12);
    assert!(!a2.outbound.allows(Proto::Tcp, ip("192.168.3.5"), 80));
    assert!(!a2.outbound.allows(Proto::Tcp, ip("192.168.1.5"), 80));
    assert!(a2.outbound.allows(Proto::Tcp, ip("192.168.2.5"), 80));
    assert!(c.tenant_space.contains(&net("192.168.3.0/24")));
}

#[test]
fn inbound_grants_only_take_outside_sources_and_hub_addresses() {
    let mut s = state();
    s.networks[0].inbound = rule_set(&["tcp 10.50.0.0/16 22", "tcp 10.50.0.1/32 9100"]);
    let c = compile(&s);
    let a1 = get(&c, 11);
    assert!(
        !a1.inbound.allows(Proto::Tcp, ip("10.50.1.2"), 22),
        "another tenant's peer"
    );
    assert!(
        a1.inbound.allows(Proto::Tcp, ip("10.50.0.1"), 22),
        "the hub address"
    );
    assert!(a1.inbound.allows(Proto::Tcp, ip("10.50.0.1"), 9100));
}

#[test]
fn mesh_off_means_no_access_between_members() {
    let mut s = state();
    s.peers.push(peer(12, A, "10.50.0.3", &[]));
    let c = compile(&s);
    assert!(!get(&c, 12).outbound.allows(Proto::Tcp, ip("10.50.0.2"), 22));
    assert!(!get(&c, 11).inbound.allows(Proto::Tcp, ip("10.50.0.3"), 22));
}

#[test]
fn invalid_peers_are_skipped_and_others_compile_without_them() {
    let mut s = state();
    s.peers.extend([
        peer(40, A, "10.50.0.1", &[]),
        peer(41, 99, "10.50.9.2", &[]),
        peer(42, A, "10.50.0.4", &["10.50.7.0/24"]),
        peer(43, C, "10.50.1.3", &["192.168.1.128/25"]),
        peer(44, B, "10.50.0.20", &["10.60.0.0/24", "10.60.0.0/16"]),
        // Nested in a CIDR that is itself nested at the same start (/32 then /24).
        peer(45, B, "10.50.0.21", &["10.70.0.0/32"]),
        peer(46, B, "10.50.0.22", &["10.70.0.0/24"]),
        peer(47, B, "10.50.0.23", &["10.70.0.128/25"]),
    ]);
    let c = compile(&s);
    let mut skipped = c.skipped.clone();
    skipped.sort_by_key(|(id, _)| *id);
    // The older peer keeps a contested address; only the newcomer fails closed.
    assert_eq!(
        skipped,
        [
            (40, Problem::InvalidIp),
            (41, Problem::UnknownNetwork),
            (42, Problem::RoutedInPool),
            (43, Problem::Overlap),
            (44, Problem::Overlap),
            (46, Problem::Overlap),
        ]
    );
    // a1 still works, and 47 (inside the rejected /24, clear of 45's /32) is in.
    assert!(
        get(&c, 21)
            .inbound
            .allows(Proto::Tcp, ip("192.168.1.9"), 22)
    );
    get(&c, 47);
}
