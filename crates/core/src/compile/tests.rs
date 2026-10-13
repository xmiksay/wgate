use super::*;
use crate::rule::Proto;
use crate::testing::{ip, net, peer, rule_set, tcp};

fn network(id: Id, tenant: Id, cidr: &str, mesh: bool, rules: Vec<NetRule>) -> Network {
    Network {
        id,
        tenant,
        slug: format!("n{id}").parse().unwrap(),
        cidr: net(cidr),
        mesh,
        rules,
        inbound: RuleSet::new(),
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
        routed_space: vec![net("10.0.0.0/8"), net("192.168.0.0/16")],
        reserved: vec![],
        tenants: vec![
            Tenant {
                id: 10,
                blocks: vec![net("10.50.0.0/24")],
                ceiling: rule_set(&["tcp 172.16.16.1/32 6443", "tcp 10.0.0.0/8 443"]),
            },
            Tenant {
                id: 20,
                blocks: vec![net("10.50.1.0/24")],
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
fn routed_lans_outside_routed_space_are_refused() {
    let mut s = state();
    s.peers.push(peer(13, A, "10.50.0.4", &["128.0.0.0/1"]));
    s.peers.push(peer(14, A, "10.50.0.5", &["172.19.9.0/24"]));
    let c = compile(&s);
    let mut skipped = c.skipped.clone();
    skipped.sort_by_key(|(id, _)| *id);
    assert_eq!(
        skipped,
        [
            (13, Problem::RoutedNotAllowed),
            (14, Problem::RoutedNotAllowed)
        ]
    );
    // Never tenant space, so the hub keeps accepting those sources on eth0.
    assert_eq!(c.tenant_space, [net("10.50.0.0/16"), net("192.168.1.0/24")]);
}

#[test]
fn bad_networks_do_not_knock_out_good_ones() {
    let mut s = state();
    // Lower ids than A, but outside the pool / with an unknown tenant.
    s.networks.push(network(0, 10, "10.0.0.0/8", false, vec![]));
    s.networks
        .push(network(-1, 99, "10.50.0.0/24", true, vec![]));
    s.peers.push(peer(91, -1, "10.50.0.9", &[]));
    let c = compile(&s);
    assert_eq!(c.skipped, [(91, Problem::InvalidNetwork)]);
    get(&c, 11);
    // The tenant-less network's mesh grants nothing.
    assert!(!get(&c, 11).inbound.allows(Proto::Tcp, ip("10.50.0.9"), 1));
}

#[test]
fn networks_outside_their_tenant_blocks_or_too_small_fail_closed() {
    let mut s = state();
    // In the pool, but in tenant 20's block.
    s.networks
        .push(network(6, 10, "10.50.1.64/28", true, vec![]));
    // In tenant 10's block, but no room for a peer.
    s.networks
        .push(network(7, 10, "10.50.0.255/32", true, vec![]));
    s.peers.push(peer(61, 6, "10.50.1.66", &[]));
    let c = compile(&s);
    assert_eq!(c.skipped, [(61, Problem::InvalidNetwork)]);
}

#[test]
fn routed_lans_with_host_bits_are_refused() {
    let mut s = state();
    s.peers.push(peer(13, A, "10.50.0.4", &["192.168.7.5/24"]));
    assert_eq!(compile(&s).skipped, [(13, Problem::RoutedNotAllowed)]);
}

#[test]
fn compiled_peers_know_their_interface() {
    assert_eq!(get(&compile(&state()), 21).iface, "wg-n2");
}

#[test]
fn lans_of_skipped_routers_are_not_tenant_space() {
    let mut s = state();
    s.tenants[0].ceiling = rule_set(&["tcp 192.168.0.0/16 80"]);
    s.networks[0].rules.push(external("tcp 192.168.0.0/16 80"));
    s.peers.push(peer(12, A, "10.50.0.3", &[]));
    // Its own LANs overlap each other: skipped, and its LAN stays external space.
    s.peers.push(peer(
        32,
        C,
        "10.50.1.3",
        &["192.168.3.0/24", "192.168.3.0/25"],
    ));
    let c = compile(&s);
    assert_eq!(c.skipped, [(32, Problem::Overlap)]);
    let a2 = get(&c, 12);
    assert!(a2.outbound.allows(Proto::Tcp, ip("192.168.3.5"), 80));
    // A valid router's LAN is tenant space: reachable only through network rules.
    assert!(!a2.outbound.allows(Proto::Tcp, ip("192.168.1.5"), 80));
    assert!(!c.tenant_space.contains(&net("192.168.3.0/24")));
}

#[test]
fn routed_lans_never_cover_reserved_infrastructure() {
    let mut s = state();
    s.routed_space.push(net("172.16.0.0/12"));
    s.reserved = vec![net("172.19.9.0/24")];
    s.peers.push(peer(13, A, "10.50.0.4", &["172.19.0.0/16"]));
    s.peers.push(peer(14, A, "10.50.0.5", &["172.20.0.0/16"]));
    let c = compile(&s);
    assert_eq!(c.skipped, [(13, Problem::RoutedNotAllowed)]);
    get(&c, 14);
}

#[test]
fn network_slugs_and_blocks_follow_older_wins() {
    let mut s = state();
    // Same slug as B (id 2), newer: it would share B's interface.
    let mut dup = network(8, 10, "10.50.0.32/28", false, vec![]);
    dup.slug = "n2".parse().unwrap();
    s.networks.push(dup);
    // Host bits in the range.
    s.networks
        .push(network(9, 10, "10.50.0.53/28", false, vec![]));
    s.peers.push(peer(81, 8, "10.50.0.34", &[]));
    s.peers.push(peer(91, 9, "10.50.0.50", &[]));
    // A newer tenant whose block overlaps tenant 10's loses its block.
    s.tenants.push(Tenant {
        id: 30,
        blocks: vec![net("10.50.0.128/25")],
        ceiling: RuleSet::new(),
    });
    s.networks
        .push(network(10, 30, "10.50.0.128/28", false, vec![]));
    s.peers.push(peer(101, 10, "10.50.0.130", &[]));
    let c = compile(&s);
    let mut skipped = c.skipped.clone();
    skipped.sort_by_key(|(id, _)| *id);
    assert_eq!(
        skipped,
        [
            (81, Problem::InvalidNetwork),
            (91, Problem::InvalidNetwork),
            (101, Problem::InvalidNetwork),
        ]
    );
    assert_eq!(get(&c, 21).iface, "wg-n2");
}

#[test]
fn adjacent_blocks_and_routed_entries_are_merged() {
    let mut s = state();
    s.tenants[0].blocks = vec![
        net("10.50.0.0/24"),
        net("10.50.3.0/24"),
        net("10.50.2.0/24"),
    ];
    s.networks
        .push(network(11, 10, "10.50.2.0/23", false, vec![]));
    s.peers.push(peer(111, 11, "10.50.2.9", &[]));
    s.routed_space = vec![
        net("192.168.4.0/24"),
        net("192.168.1.0/24"),
        net("192.168.5.0/24"),
    ];
    s.peers
        .push(peer(112, 11, "10.50.2.10", &["192.168.4.0/23"]));
    let c = compile(&s);
    assert!(c.skipped.is_empty(), "{:?}", c.skipped);
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
            (42, Problem::RoutedNotAllowed),
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
