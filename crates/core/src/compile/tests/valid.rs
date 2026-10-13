//! Validation: networks, blocks, peers and routes that fail closed.

use super::*;
use crate::net::RESERVED_PORT;

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
    // The routes go, the peers stay.
    assert!(c.skipped.is_empty());
    assert_eq!(
        c.dropped_routes,
        [
            (1300, Problem::RoutedNotAllowed),
            (1400, Problem::RoutedNotAllowed)
        ]
    );
    assert_eq!(get(&c, 13).addrs, [net("10.50.0.4/32")]);
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
    assert_eq!(
        compile(&s).dropped_routes,
        [(1300, Problem::RoutedNotAllowed)]
    );
}

#[test]
fn routed_lans_never_cover_reserved_infrastructure() {
    let mut s = state();
    s.routed_space.push(net("172.16.0.0/12"));
    s.reserved = vec![net("172.19.9.0/24")];
    s.peers.push(peer(13, A, "10.50.0.4", &["172.19.0.0/16"]));
    s.peers.push(peer(14, A, "10.50.0.5", &["172.20.0.0/16"]));
    let c = compile(&s);
    assert_eq!(c.dropped_routes, [(1300, Problem::RoutedNotAllowed)]);
    assert!(get(&c, 14).addrs.contains(&net("172.20.0.0/16")));
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
        blocks: vec![block(3, "10.50.0.128/25")],
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
fn a_clashing_block_costs_only_itself() {
    let mut s = state();
    // Tenant 20's second, newer block overlaps tenant 10's: only that block goes.
    s.tenants[1].blocks.push(block(50, "10.50.0.0/25"));
    let c = compile(&s);
    assert!(c.skipped.is_empty(), "{:?}", c.skipped);
    get(&c, 31);
}

#[test]
fn a_range_loser_does_not_hold_its_slug() {
    let mut s = state();
    // Overlaps A (older) and so is invalid; its slug must stay free.
    let mut loser = network(12, 10, "10.50.0.0/29", false, vec![]);
    loser.slug = "x".parse().unwrap();
    let mut winner = network(13, 10, "10.50.0.32/28", false, vec![]);
    winner.slug = "x".parse().unwrap();
    s.networks.extend([loser, winner]);
    s.peers.push(peer(131, 13, "10.50.0.34", &[]));
    let c = compile(&s);
    assert_eq!(get(&c, 131).iface, "wg-x");
}

#[test]
fn adjacent_blocks_and_routed_entries_are_merged() {
    let mut s = state();
    s.tenants[0].blocks = vec![
        block(1, "10.50.0.0/24"),
        block(21, "10.50.3.0/24"),
        block(22, "10.50.2.0/24"),
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
fn invalid_peers_and_routes_are_left_out() {
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
        // The same address as a1, newer.
        peer(48, A, "10.50.0.2", &[]),
    ]);
    let c = compile(&s);
    assert_eq!(
        c.skipped,
        [
            (40, Problem::InvalidIp),
            (41, Problem::UnknownNetwork),
            (48, Problem::Overlap),
        ]
    );
    assert_eq!(
        c.dropped_routes,
        [
            (4200, Problem::RoutedNotAllowed),
            (4300, Problem::Overlap),
            (4401, Problem::Overlap),
            (4600, Problem::Overlap),
        ]
    );
    // a1 keeps its LAN; 47 (inside the rejected /24, clear of 45's /32) is in.
    assert!(
        get(&c, 21)
            .inbound
            .allows(Proto::Tcp, ip("192.168.1.9"), 22)
    );
    assert!(get(&c, 47).addrs.contains(&net("10.70.0.128/25")));
}

#[test]
fn a_device_of_another_tenant_cannot_join() {
    let mut s = state();
    let mut foreign = peer(60, C, "10.50.1.6", &[]);
    foreign.owner_tenant = Some(10);
    let mut own = peer(61, C, "10.50.1.7", &[]);
    own.owner_tenant = Some(20);
    s.peers.extend([foreign, own]);
    let c = compile(&s);
    assert_eq!(c.skipped, [(60, Problem::ForeignDevice)]);
    get(&c, 61);
}

#[test]
fn listen_ports_must_be_in_range_and_unique() {
    let mut s = state();
    let mut clash = network(14, 10, "10.50.0.64/28", false, vec![]);
    clash.port = 51802; // B's
    let mut reserved = network(15, 10, "10.50.0.80/28", false, vec![]);
    reserved.port = RESERVED_PORT;
    let mut outside = network(16, 10, "10.50.0.96/28", false, vec![]);
    outside.port = 51900;
    s.networks.extend([clash, reserved, outside]);
    assert_eq!(compile(&s).invalid_networks, [14, 15, 16]);
}

#[test]
fn losing_blocks_are_reported() {
    let mut s = state();
    s.tenants[1].blocks.push(block(50, "10.50.0.0/25"));
    s.tenants[1].blocks.push(block(51, "10.60.0.0/24"));
    s.tenants[1].blocks.push(block(52, "10.50.9.5/24"));
    assert_eq!(compile(&s).invalid_blocks, [50, 51, 52]);
}
