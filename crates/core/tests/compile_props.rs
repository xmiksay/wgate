//! Property tests: `compile` keeps both sides of every grant consistent and never
//! exceeds ceilings or tenant boundaries.
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use proptest::prelude::*;
use wgate_core::{
    CompiledPeer, DesiredState, Federation, NetRule, Network, Peer, PortRange, Proto, Rule,
    RuleSet, Service, Tenant, compile,
};

const NETWORKS: i64 = 4;

fn tenant_of(network: i64) -> i64 {
    // Networks 0 and 1 belong to tenant 0, 2 and 3 to tenant 1.
    network / 2
}

fn cidr(network: i64) -> Ipv4Net {
    Ipv4Net::new(Ipv4Addr::new(10, 50, network as u8, 0), 28).expect("prefix")
}

fn service() -> impl Strategy<Value = Service> {
    let ports = (1u16..20, 1u16..20)
        .prop_map(|(a, b)| PortRange::new(a.min(b), a.max(b)).expect("ordered"));
    prop_oneof![
        ports.clone().prop_map(Service::Tcp),
        ports.prop_map(Service::Udp),
        Just(Service::Icmp),
    ]
}

/// External destinations in a small universe outside the pool.
fn external() -> impl Strategy<Value = Rule> {
    (0u32..64, 26u8..=32, service()).prop_map(|(host, len, service)| {
        let net = Ipv4Net::new(Ipv4Addr::from(0xac10_1000 + host), len)
            .expect("prefix")
            .trunc();
        Rule::from_parts(net, service)
    })
}

fn net_rule() -> impl Strategy<Value = NetRule> {
    prop_oneof![
        external().prop_map(NetRule::External),
        // Any network, also another tenant's: compile must ignore those.
        (0..NETWORKS, service()).prop_map(|(network, service)| NetRule::To { network, service }),
    ]
}

fn state() -> impl Strategy<Value = DesiredState> {
    let networks = prop::collection::vec(
        (any::<bool>(), prop::collection::vec(net_rule(), 0..4)),
        NETWORKS as usize,
    );
    let ceilings = prop::collection::vec(prop::collection::vec(external(), 0..4), 2);
    let peers = prop::collection::vec((0..NETWORKS, 2u8..8), 0..8);
    let federations = prop::collection::vec((0..NETWORKS, 0..NETWORKS, service()), 0..3);
    (networks, ceilings, peers, federations).prop_map(|(networks, ceilings, peers, federations)| {
        let mut seen = Vec::new();
        DesiredState {
            pool: vec!["10.50.0.0/16".parse().expect("cidr")],
            tenants: ceilings
                .iter()
                .enumerate()
                .map(|(id, rules)| Tenant {
                    id: id as i64,
                    ceiling: RuleSet::from_rules(rules),
                })
                .collect(),
            networks: networks
                .into_iter()
                .enumerate()
                .map(|(id, (mesh, rules))| Network {
                    id: id as i64,
                    tenant: tenant_of(id as i64),
                    cidr: cidr(id as i64),
                    mesh,
                    rules,
                    inbound: RuleSet::new(),
                })
                .collect(),
            peers: peers
                .into_iter()
                .filter(|p| {
                    let fresh = !seen.contains(p);
                    seen.push(*p);
                    fresh
                })
                .enumerate()
                .map(|(id, (network, host))| Peer {
                    id: id as i64,
                    network,
                    ip: Ipv4Addr::new(10, 50, network as u8, host),
                    routed: vec![],
                })
                .collect(),
            federations: federations
                .into_iter()
                .map(|(from, to, service)| Federation { from, to, service })
                .collect(),
        }
    })
}

fn network_of(p: &CompiledPeer) -> i64 {
    i64::from(p.ip.octets()[2])
}

/// Sample points: every proto at a few ports.
fn points() -> impl Iterator<Item = (Proto, u16)> {
    [Proto::Tcp, Proto::Udp, Proto::Icmp]
        .into_iter()
        .flat_map(|p| [1u16, 5, 10, 19].into_iter().map(move |port| (p, port)))
}

proptest! {
    #[test]
    fn both_sides_agree(s in state()) {
        let c = compile(&s);
        for p in &c.peers {
            for q in &c.peers {
                if p.id == q.id {
                    continue;
                }
                for (proto, port) in points() {
                    prop_assert_eq!(
                        p.outbound.allows(proto, q.ip, port),
                        q.inbound.allows(proto, p.ip, port),
                        "{} → {} {:?} {}", p.ip, q.ip, proto, port
                    );
                }
            }
        }
    }

    #[test]
    fn tenants_are_isolated_without_federation(s in state()) {
        let c = compile(&s);
        for p in &c.peers {
            for q in &c.peers {
                let (n, m) = (network_of(p), network_of(q));
                let federated = s.federations.iter().any(|f| f.from == n && f.to == m);
                if tenant_of(n) == tenant_of(m) || federated {
                    continue;
                }
                for (proto, port) in points() {
                    prop_assert!(!p.outbound.allows(proto, q.ip, port));
                }
            }
        }
    }

    #[test]
    fn external_access_stays_within_the_ceiling(s in state()) {
        let c = compile(&s);
        let pool = RuleSet::everything(&s.pool);
        for p in &c.peers {
            let ceiling = &s.tenants[tenant_of(network_of(p)) as usize].ceiling;
            prop_assert!(p.outbound.difference(&pool).difference(ceiling).is_empty());
        }
    }

    #[test]
    fn no_peer_reaches_itself(s in state()) {
        for p in compile(&s).peers {
            for (proto, port) in points() {
                prop_assert!(!p.outbound.allows(proto, p.ip, port));
                prop_assert!(!p.inbound.allows(proto, p.ip, port));
            }
        }
    }
}
