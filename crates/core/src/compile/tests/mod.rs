use super::*;
use crate::rule::Proto;
use crate::testing::{block, ip, net, peer, rule_set, tcp};

pub(super) fn network(id: Id, tenant: Id, cidr: &str, mesh: bool, rules: Vec<NetRule>) -> Network {
    Network {
        id,
        tenant,
        slug: format!("n{id}").parse().unwrap(),
        port: (51800 + id).try_into().unwrap(),
        cidr: net(cidr),
        mesh,
        rules,
        inbound: RuleSet::new(),
    }
}

pub(super) fn external(rule: &str) -> NetRule {
    NetRule::External(rule.parse().unwrap())
}

pub(super) const A: Id = 1;
pub(super) const B: Id = 2;
pub(super) const C: Id = 3;

/// Tenant 10: networks A (router a1 with a LAN) and B (mesh); tenant 20: network C,
/// federated into B on 443.
pub(super) fn state() -> DesiredState {
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
        snat_source: ip("172.19.9.10"),
        node_cidrs: vec![net("172.19.9.0/24")],
        routed_space: vec![net("10.0.0.0/8"), net("192.168.0.0/16")],
        reserved: vec![],
        tenants: vec![
            Tenant {
                id: 10,
                blocks: vec![block(1, "10.50.0.0/24")],
                ceiling: rule_set(&["tcp 172.16.16.1/32 6443", "tcp 10.0.0.0/8 443"]),
            },
            Tenant {
                id: 20,
                blocks: vec![block(2, "10.50.1.0/24")],
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

pub(super) fn get(c: &Compiled, id: Id) -> &CompiledPeer {
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
fn compiled_peers_know_their_interface() {
    assert_eq!(get(&compile(&state()), 21).iface, "wg-n2");
}

#[test]
fn only_the_losing_route_is_dropped() {
    let mut s = state();
    s.tenants[0].ceiling = rule_set(&["tcp 192.168.0.0/16 80"]);
    s.networks[0].rules.push(external("tcp 192.168.0.0/16 80"));
    s.peers.push(peer(12, A, "10.50.0.3", &[]));
    // Route 3200 claims a1's LAN (route 1100, older); route 3201 is free.
    s.peers.push(peer(
        32,
        C,
        "10.50.1.3",
        &["192.168.1.0/24", "192.168.3.0/24"],
    ));
    let c = compile(&s);
    assert!(c.skipped.is_empty());
    assert_eq!(c.dropped_routes, [(3200, Problem::Overlap)]);
    assert_eq!(
        get(&c, 32).addrs,
        [net("10.50.1.3/32"), net("192.168.3.0/24")]
    );
    assert_eq!(
        get(&c, 11).addrs,
        [net("10.50.0.2/32"), net("192.168.1.0/24")]
    );
    // Both LANs are tenant space: reachable only through network rules.
    let a2 = get(&c, 12);
    assert!(!a2.outbound.allows(Proto::Tcp, ip("192.168.1.5"), 80));
    assert!(!a2.outbound.allows(Proto::Tcp, ip("192.168.3.5"), 80));
    assert!(a2.outbound.allows(Proto::Tcp, ip("192.168.2.5"), 80));
}

#[test]
fn a_newer_router_keeps_its_lan_when_an_older_one_claims_it() {
    let mut s = state();
    s.peers.push(peer(50, B, "10.50.0.20", &[]));
    s.peers[4].routed.push(Claim {
        id: 9000,
        cidr: net("192.168.9.0/24"),
    });
    // Older peer (11), newer route claim (9100) for the same LAN.
    s.peers[0].routed.push(Claim {
        id: 9100,
        cidr: net("192.168.9.0/24"),
    });
    let c = compile(&s);
    assert_eq!(c.dropped_routes, [(9100, Problem::Overlap)]);
    assert!(get(&c, 50).addrs.contains(&net("192.168.9.0/24")));
}

#[test]
fn rejected_routes_are_not_tenant_space() {
    let mut s = state();
    s.tenants[0].ceiling = rule_set(&["tcp 192.168.0.0/16 80"]);
    s.networks[0].rules.push(external("tcp 192.168.0.0/16 80"));
    s.peers.push(peer(12, A, "10.50.0.3", &[]));
    // Its own two routes overlap: the newer one goes, the older stays.
    s.peers.push(peer(
        32,
        C,
        "10.50.1.3",
        &["192.168.3.0/24", "192.168.3.0/25"],
    ));
    s.peers
        .push(peer(33, C, "10.50.1.4", &["192.168.200.5/24"]));
    let c = compile(&s);
    assert_eq!(
        c.dropped_routes,
        [(3201, Problem::Overlap), (3300, Problem::RoutedNotAllowed)]
    );
    let a2 = get(&c, 12);
    assert!(a2.outbound.allows(Proto::Tcp, ip("192.168.200.5"), 80));
    assert!(!c.tenant_space.contains(&net("192.168.200.0/24")));
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
    // Only its own network's hub address, not another network's.
    assert!(!a1.inbound.allows(Proto::Tcp, ip("10.50.0.17"), 22));
    assert!(!a1.inbound.allows(Proto::Tcp, ip("10.50.1.1"), 22));
}

#[test]
fn mesh_off_means_no_access_between_members() {
    let mut s = state();
    s.peers.push(peer(12, A, "10.50.0.3", &[]));
    let c = compile(&s);
    assert!(!get(&c, 12).outbound.allows(Proto::Tcp, ip("10.50.0.2"), 22));
    assert!(!get(&c, 11).inbound.allows(Proto::Tcp, ip("10.50.0.3"), 22));
}

mod valid;
