//! Property tests: `RuleSet` operations agree with pointwise set semantics.
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use proptest::prelude::*;
use wgate_core::{PortRange, Proto, Rule, RuleSet, covers, effective};

// A small universe (10.0.0.0/22, ports 1–99) so random rules actually overlap, plus
// the domain edges (/0, 255.255.255.255, port 65535) where overflow would show.
const BASE: u32 = 0x0a00_0000;

fn proto() -> impl Strategy<Value = Proto> {
    prop_oneof![Just(Proto::Tcp), Just(Proto::Udp), Just(Proto::Icmp)]
}

fn dst() -> impl Strategy<Value = Ipv4Net> {
    prop_oneof![
        8 => (0u32..1024, 22u8..=32).prop_map(|(host, len)| {
            Ipv4Net::new(Ipv4Addr::from(BASE + host), len)
                .expect("prefix <= 32")
                .trunc()
        }),
        1 => Just(Ipv4Net::default()),
        1 => Just(Ipv4Net::from(Ipv4Addr::BROADCAST)),
    ]
}

fn ports() -> impl Strategy<Value = PortRange> {
    prop_oneof![
        8 => (1u16..100, 1u16..100).prop_map(|(a, b)| (a.min(b), a.max(b))),
        1 => Just((1, u16::MAX)),
        1 => (60000u16..=u16::MAX).prop_map(|a| (a, u16::MAX)),
    ]
    .prop_map(|(a, b)| PortRange::new(a, b).expect("ordered, non-zero"))
}

fn rule() -> impl Strategy<Value = Rule> {
    (proto(), dst(), ports()).prop_map(|(proto, dst, ports)| {
        let ports = (proto != Proto::Icmp).then_some(ports);
        Rule::new(proto, dst, ports).expect("valid by construction")
    })
}

fn rule_set() -> impl Strategy<Value = RuleSet> {
    prop::collection::vec(rule(), 0..6).prop_map(|rules| RuleSet::from_rules(&rules))
}

/// Points slightly outside the universe and at the edges, to catch leaks.
fn point() -> impl Strategy<Value = (Proto, Ipv4Addr, u16)> {
    let addr = prop_oneof![
        8 => (0u32..1100).prop_map(|h| Ipv4Addr::from(BASE + h)),
        1 => any::<u32>().prop_map(Ipv4Addr::from),
        1 => Just(Ipv4Addr::BROADCAST),
    ];
    let port = prop_oneof![8 => 0u16..110, 1 => Just(u16::MAX), 1 => any::<u16>()];
    (proto(), addr, port)
}

fn points() -> impl Strategy<Value = Vec<(Proto, Ipv4Addr, u16)>> {
    prop::collection::vec(point(), 64)
}

proptest! {
    #[test]
    fn ops_match_pointwise_semantics(a in rule_set(), b in rule_set(), pts in points()) {
        let (i, u, d) = (a.intersect(&b), a.union(&b), a.difference(&b));
        for (p, addr, port) in pts {
            let (x, y) = (a.allows(p, addr, port), b.allows(p, addr, port));
            prop_assert_eq!(i.allows(p, addr, port), x && y);
            prop_assert_eq!(u.allows(p, addr, port), x || y);
            prop_assert_eq!(d.allows(p, addr, port), x && !y);
        }
    }

    #[test]
    fn intersect_is_commutative_and_within_both(a in rule_set(), b in rule_set()) {
        let i = a.intersect(&b);
        prop_assert_eq!(&i, &b.intersect(&a));
        prop_assert!(i.difference(&a).is_empty());
        prop_assert!(i.difference(&b).is_empty());
    }

    #[test]
    fn effective_never_exceeds_company(
        company in rule_set(),
        groups in prop::collection::vec(rule_set(), 0..3),
        user in rule_set(),
    ) {
        prop_assert!(effective(&company, &groups, &user).difference(&company).is_empty());
    }

    #[test]
    fn elements_are_disjoint_and_exact(s in rule_set(), pts in points()) {
        let elements = s.elements();
        for (p, addr, port) in pts {
            let hits = elements
                .iter()
                .filter(|e| {
                    e.service.proto() == p
                        && e.addrs.contains(addr)
                        && e.service.ports().is_none_or(|r| (r.from()..=r.to()).contains(&port))
                })
                .count();
            prop_assert!(hits <= 1, "overlapping elements at {p} {addr} {port}");
            prop_assert_eq!(hits == 1, s.allows(p, addr, port));
        }
    }

    #[test]
    fn covers_matches_containment(ceiling in rule_set(), r in rule(), pts in points()) {
        let single = RuleSet::from_rules([&r]);
        match covers(&ceiling, &r) {
            Ok(()) => {
                for (p, addr, port) in pts {
                    if single.allows(p, addr, port) {
                        prop_assert!(ceiling.allows(p, addr, port));
                    }
                }
            }
            Err(uncovered) => {
                prop_assert!(!uncovered.0.is_empty());
                prop_assert!(!single.difference(&ceiling).is_empty());
            }
        }
    }

    #[test]
    fn addresses_are_exactly_the_element_addresses(s in rule_set(), pts in points()) {
        let dsts = s.addresses(&[]);
        let elements = s.elements();
        for (_, addr, _) in pts {
            prop_assert_eq!(
                dsts.iter().any(|n| n.contains(&addr)),
                elements.iter().any(|e| e.addrs.contains(addr)),
                "{}", addr
            );
        }
        for net in &dsts {
            for edge in [net.network(), net.broadcast()] {
                prop_assert!(elements.iter().any(|e| e.addrs.contains(edge)));
            }
        }
    }
}
