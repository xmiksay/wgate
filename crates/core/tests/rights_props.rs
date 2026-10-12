//! Property tests: `RuleSet` operations agree with pointwise set semantics.
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use proptest::prelude::*;
use wgate_core::{PortRange, Proto, Rule, RuleSet, covers, effective};

// A small universe (10.0.0.0/22, ports 0–99) so random rules actually overlap.
const BASE: u32 = 0x0a00_0000;

fn proto() -> impl Strategy<Value = Proto> {
    prop_oneof![Just(Proto::Tcp), Just(Proto::Udp), Just(Proto::Icmp)]
}

fn rule() -> impl Strategy<Value = Rule> {
    (proto(), 0u32..1024, 22u8..=32, 0u16..100, 0u16..100).prop_map(|(proto, host, len, a, b)| {
        let dst = Ipv4Net::new(Ipv4Addr::from(BASE + host), len)
            .expect("prefix <= 32")
            .trunc();
        let ports =
            (proto != Proto::Icmp).then(|| PortRange::new(a.min(b), a.max(b)).expect("ordered"));
        Rule::new(proto, dst, ports).expect("valid by construction")
    })
}

fn rule_set() -> impl Strategy<Value = RuleSet> {
    prop::collection::vec(rule(), 0..6).prop_map(|rules| RuleSet::from_rules(&rules))
}

/// Points slightly outside the universe too, to catch edge leaks.
fn point() -> impl Strategy<Value = (Proto, Ipv4Addr, u16)> {
    (proto(), 0u32..1100, 0u16..110).prop_map(|(p, h, port)| (p, Ipv4Addr::from(BASE + h), port))
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
                    e.proto == p
                        && e.dst.contains(addr)
                        && e.ports.is_none_or(|r| (r.from()..=r.to()).contains(&port))
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
    fn destinations_cover_every_allowed_address(s in rule_set(), pts in points()) {
        let dsts = s.destinations();
        for (p, addr, port) in pts {
            if s.allows(p, addr, port) {
                prop_assert!(dsts.iter().any(|n| n.contains(&addr)));
            }
        }
        for net in &dsts {
            prop_assert!(s.elements().iter().any(|e| e.dst.contains(net.network())));
        }
    }
}
