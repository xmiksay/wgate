//! Property tests: `compile` keeps both sides of every grant consistent and never
//! exceeds ceilings or tenant boundaries.
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use proptest::prelude::*;
use wgate_core::{
    Claim, CompiledPeer, DesiredState, Federation, NetRule, Network, Peer, PortRange, Proto, Rule,
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
    // Routed LAN: 192.168.0-3.0/24 (allowed, may collide) or 8.8.8.0/24 (not).
    // (network, host, LAN, shared-key seed, device of the other tenant's user)
    let peers = prop::collection::vec(
        (
            0..NETWORKS,
            2u8..8,
            prop::option::of(0u8..5),
            prop::option::weighted(0.2, 0u8..3),
            prop::bool::weighted(0.15),
        ),
        0..8,
    );
    let federations = prop::collection::vec((0..NETWORKS, 0..NETWORKS, service()), 0..3);
    (networks, ceilings, peers, federations).prop_map(|(networks, ceilings, peers, federations)| {
        let mut seen = Vec::new();
        DesiredState {
            pool: vec!["10.50.0.0/16".parse().expect("cidr")],
            snat_source: Ipv4Addr::new(172, 19, 9, 10),
            node_cidrs: vec!["172.19.9.0/24".parse().expect("cidr")],
            routed_space: vec!["192.168.0.0/16".parse().expect("cidr")],
            reserved: vec![],
            tenants: ceilings
                .iter()
                .enumerate()
                .map(|(id, rules)| Tenant {
                    id: id as i64,
                    blocks: vec![Claim {
                        id: id as i64,
                        cidr: Ipv4Net::new(Ipv4Addr::new(10, 50, 2 * id as u8, 0), 23)
                            .expect("prefix"),
                    }],
                    ceiling: RuleSet::from_rules(rules),
                })
                .collect(),
            networks: networks
                .into_iter()
                .enumerate()
                .map(|(id, (mesh, rules))| Network {
                    id: id as i64,
                    tenant: tenant_of(id as i64),
                    slug: format!("n{id}").parse().expect("slug"),
                    port: 51800 + id as u16,
                    cidr: cidr(id as i64),
                    mesh,
                    rules,
                    inbound: RuleSet::new(),
                })
                .collect(),
            peers: peers
                .into_iter()
                .filter(|(network, host, _, _, _)| {
                    let fresh = !seen.contains(&(*network, *host));
                    seen.push((*network, *host));
                    fresh
                })
                .enumerate()
                .map(|(id, (network, host, lan, shared, foreign))| Peer {
                    id: id as i64,
                    network,
                    ip: Ipv4Addr::new(10, 50, network as u8, host),
                    public_key: match shared {
                        Some(k) => format!("{k:0>42}E="),
                        None => format!("{id:0>42}A="),
                    },
                    owner_tenant: Some(if foreign {
                        1 - tenant_of(network)
                    } else {
                        tenant_of(network)
                    }),
                    routed: lan
                        .map(|l| match l {
                            4 => Ipv4Net::new(Ipv4Addr::new(8, 8, 8, 0), 24),
                            l => Ipv4Net::new(Ipv4Addr::new(192, 168, l, 0), 24),
                        })
                        .into_iter()
                        .map(|n| Claim {
                            id: id as i64,
                            cidr: n.expect("prefix"),
                        })
                        .collect(),
                })
                .collect(),
            federations: federations
                .into_iter()
                .map(|(from, to, service)| Federation { from, to, service })
                .collect(),
        }
    })
}

/// The peer's own address and one host of each routed LAN.
fn hosts(p: &CompiledPeer) -> Vec<Ipv4Addr> {
    p.addrs
        .iter()
        .map(|a| {
            if a.prefix_len() == 32 {
                a.addr()
            } else {
                Ipv4Addr::from(u32::from(a.network()) + 1)
            }
        })
        .collect()
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
                for (src, dst) in hosts(p).into_iter().flat_map(|s| hosts(q).into_iter().map(move |d| (s, d))) {
                    for (proto, port) in points() {
                        prop_assert_eq!(
                            p.outbound.allows(proto, dst, port),
                            q.inbound.allows(proto, src, port),
                            "{} → {} {:?} {}", src, dst, proto, port
                        );
                    }
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
                for dst in hosts(q) {
                    for (proto, port) in points() {
                        prop_assert!(!p.outbound.allows(proto, dst, port));
                    }
                }
            }
        }
    }

    #[test]
    fn external_access_stays_within_the_ceiling(s in state()) {
        let c = compile(&s);
        let tenant_space = RuleSet::everything(&c.tenant_space);
        for p in &c.peers {
            let ceiling = &s.tenants[tenant_of(network_of(p)) as usize].ceiling;
            prop_assert!(p.outbound.difference(&tenant_space).difference(ceiling).is_empty());
        }
    }

    #[test]
    fn tenant_space_stays_within_pool_and_routed_space(s in state()) {
        let allowed: Vec<Ipv4Net> = s.pool.iter().chain(&s.routed_space).copied().collect();
        for net in compile(&s).tenant_space {
            prop_assert!(allowed.iter().any(|a| a.contains(&net)), "{}", net);
        }
    }

    #[test]
    fn compiled_peers_have_unique_keys_and_their_own_tenants_devices(s in state()) {
        let c = compile(&s);
        let mut keys = std::collections::HashSet::new();
        for p in &c.peers {
            prop_assert!(keys.insert(p.public_key.clone()), "key {} twice", p.public_key);
            let peer = s.peers.iter().find(|q| q.id == p.id).expect("compiled from the state");
            prop_assert_eq!(peer.owner_tenant, Some(tenant_of(network_of(p))));
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
