//! Rule sets and the tiered rights model (design.md → Rights).

use std::fmt;
use std::net::Ipv4Addr;

use ipnet::{Ipv4Net, Ipv4Subnets};

use crate::interval::{IntervalMap, Op};
use crate::rule::{PortRange, Proto, Rule, Service, fmt_rule};

type Line = IntervalMap<()>;
/// Destination address → set of ports.
type Plane = IntervalMap<Line>;

/// A set of allowed `(proto, addr, port)` points in canonical form, so `==` compares
/// what is allowed rather than how it was written. `addr` is the destination for
/// outbound rights and the source for inbound grants; `port` is always the
/// destination port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSet {
    tcp: Plane,
    udp: Plane,
    icmp: Line,
}

/// Inclusive address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddrRange {
    pub lo: Ipv4Addr,
    pub hi: Ipv4Addr,
}

impl AddrRange {
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        (self.lo..=self.hi).contains(&addr)
    }
}

impl fmt::Display for AddrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// One box of a [`RuleSet`]. The elements of a set are pairwise disjoint, which is
/// what nft interval sets require: they reject overlapping elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Element {
    pub addrs: AddrRange,
    pub service: Service,
}

impl fmt::Display for Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_rule(f, self.service, self.addrs)
    }
}

impl RuleSet {
    pub const fn new() -> Self {
        Self {
            tcp: Plane::empty(),
            udp: Plane::empty(),
            icmp: Line::empty(),
        }
    }

    pub fn from_rules<'a>(rules: impl IntoIterator<Item = &'a Rule>) -> Self {
        rules
            .into_iter()
            .fold(Self::new(), |acc, r| acc.union(&Self::from_rule(r)))
    }

    fn from_rule(rule: &Rule) -> Self {
        let (lo, hi) = span(rule.net());
        let plane =
            |p: PortRange| Plane::single(lo, hi, Line::single(p.from().into(), p.to().into(), ()));
        let mut set = Self::new();
        match rule.service() {
            Service::Tcp(p) => set.tcp = plane(p),
            Service::Udp(p) => set.udp = plane(p),
            Service::Icmp => set.icmp = Line::single(lo, hi, ()),
        }
        set
    }

    fn op(&self, other: &Self, op: Op) -> Self {
        Self {
            tcp: self.tcp.op(&other.tcp, op),
            udp: self.udp.op(&other.udp, op),
            icmp: self.icmp.op(&other.icmp, op),
        }
    }

    pub fn union(&self, other: &Self) -> Self {
        self.op(other, Op::Union)
    }

    pub fn intersect(&self, other: &Self) -> Self {
        self.op(other, Op::Intersect)
    }

    pub fn difference(&self, other: &Self) -> Self {
        self.op(other, Op::Difference)
    }

    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty() && self.icmp.is_empty()
    }

    /// `port` is ignored for icmp.
    pub fn allows(&self, proto: Proto, addr: Ipv4Addr, port: u16) -> bool {
        let addr = u32::from(addr);
        match proto {
            Proto::Icmp => self.icmp.get(addr).is_some(),
            Proto::Tcp => Self::plane_allows(&self.tcp, addr, port),
            Proto::Udp => Self::plane_allows(&self.udp, addr, port),
        }
    }

    fn plane_allows(plane: &Plane, addr: u32, port: u16) -> bool {
        plane
            .get(addr)
            .is_some_and(|ports| ports.get(port.into()).is_some())
    }

    /// Disjoint boxes covering exactly this set: tcp, udp, then icmp, each by address.
    pub fn elements(&self) -> Vec<Element> {
        let range = |lo: u32, hi: u32| AddrRange {
            lo: lo.into(),
            hi: hi.into(),
        };
        let mut out = Vec::new();
        let planes = [
            (&self.tcp, Service::Tcp as fn(PortRange) -> Service),
            (&self.udp, Service::Udp),
        ];
        for (plane, service) in planes {
            for a in plane.spans() {
                for p in a.val.spans() {
                    let ports = PortRange::from_span(p.lo, p.hi);
                    out.push(Element {
                        addrs: range(a.lo, a.hi),
                        service: service(ports),
                    });
                }
            }
        }
        out.extend(self.icmp.spans().iter().map(|s| Element {
            addrs: range(s.lo, s.hi),
            service: Service::Icmp,
        }));
        out
    }

    /// Minimal CIDRs covering every address of any protocol, minus `except`.
    pub fn addresses(&self, except: &[Ipv4Net]) -> Vec<Ipv4Net> {
        // Plane spans are sorted and disjoint, so pushing them in order is enough.
        let addrs = |plane: &Plane| {
            let mut line = Line::default();
            for s in plane.spans() {
                line.push(s.lo, s.hi, ());
            }
            line
        };
        let all = addrs(&self.tcp)
            .op(&addrs(&self.udp), Op::Union)
            .op(&self.icmp, Op::Union);
        minus(all, except)
    }
}

/// `nets` minus `except`, as minimal CIDRs.
pub fn subtract_nets(nets: &[Ipv4Net], except: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let all = nets.iter().fold(Line::default(), |acc, &n| {
        let (lo, hi) = span(n);
        acc.op(&Line::single(lo, hi, ()), Op::Union)
    });
    minus(all, except)
}

fn minus(line: Line, except: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let line = except.iter().fold(line, |acc, &n| {
        let (lo, hi) = span(n);
        acc.op(&Line::single(lo, hi, ()), Op::Difference)
    });
    line.spans()
        .iter()
        .flat_map(|s| Ipv4Subnets::new(s.lo.into(), s.hi.into(), 0))
        .collect()
}

fn span(net: Ipv4Net) -> (u32, u32) {
    (net.network().into(), net.broadcast().into())
}

/// `effective(user) = company ∩ (user rules if any, else the union of the user's
/// groups' rules if they are in any group, else company)`.
///
/// `groups` holds one entry per group the user is a member of, including groups
/// without rules: membership alone switches the user from the company default to
/// their groups' rules, so a member of rule-less groups gets nothing.
pub fn effective(company: &RuleSet, groups: &[RuleSet], user: &RuleSet) -> RuleSet {
    if !user.is_empty() {
        company.intersect(user)
    } else if !groups.is_empty() {
        let union = groups.iter().fold(RuleSet::new(), |acc, g| acc.union(g));
        company.intersect(&union)
    } else {
        company.clone()
    }
}

/// The part of a rule its ceiling does not allow.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not covered: {}", list(.0))]
pub struct Uncovered(pub Vec<Element>);

fn list(elements: &[Element]) -> String {
    elements
        .iter()
        .map(Element::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `ceiling` allows everything `rule` does.
pub fn covers(ceiling: &RuleSet, rule: &Rule) -> Result<(), Uncovered> {
    let rest = RuleSet::from_rule(rule).difference(ceiling);
    if rest.is_empty() {
        Ok(())
    } else {
        Err(Uncovered(rest.elements()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::rule_set as set;

    fn shown(s: &RuleSet) -> Vec<String> {
        s.elements().iter().map(Element::to_string).collect()
    }

    #[test]
    fn overlapping_rules_become_disjoint_elements() {
        let s = set(&["tcp 10.0.0.0/8 80-90", "tcp 10.1.0.0/16 85-100"]);
        assert_eq!(
            shown(&s),
            [
                "tcp 10.0.0.0-10.0.255.255 80-90",
                "tcp 10.1.0.0-10.1.255.255 80-100",
                "tcp 10.2.0.0-10.255.255.255 80-90",
            ]
        );
    }

    #[test]
    fn protocols_are_independent() {
        let s = set(&["tcp 10.0.0.0/8 53", "udp 10.0.0.0/8 53", "icmp 10.0.0.1"]);
        assert!(s.allows(Proto::Tcp, "10.9.9.9".parse().unwrap(), 53));
        assert!(!s.allows(Proto::Tcp, "10.9.9.9".parse().unwrap(), 54));
        assert!(s.allows(Proto::Icmp, "10.0.0.1".parse().unwrap(), 0));
        assert!(!s.allows(Proto::Icmp, "10.0.0.2".parse().unwrap(), 0));
        assert!(s.intersect(&set(&["udp 0.0.0.0/0 1-65535"])) == set(&["udp 10.0.0.0/8 53"]));
    }

    #[test]
    fn equal_sets_compare_equal_regardless_of_spelling() {
        assert_eq!(
            set(&["tcp 10.0.0.0/25 80", "tcp 10.0.0.128/25 80"]),
            set(&["tcp 10.0.0.0/24 80"])
        );
    }

    #[test]
    fn effective_follows_the_tiers() {
        let company = set(&["tcp 172.16.16.1/32 6443", "icmp 172.19.9.0/24"]);
        let group = set(&["icmp 172.19.9.10/32", "tcp 0.0.0.0/0 22"]);
        let user = set(&["tcp 172.16.16.1/32 6443-6444"]);

        assert_eq!(effective(&company, &[], &RuleSet::new()), company);
        assert_eq!(
            effective(&company, std::slice::from_ref(&group), &RuleSet::new()),
            set(&["icmp 172.19.9.10/32"])
        );
        assert_eq!(
            effective(&company, &[group], &user),
            set(&["tcp 172.16.16.1/32 6443"])
        );
        // In groups that grant nothing → nothing, not the company default.
        assert!(effective(&company, &[RuleSet::new()], &RuleSet::new()).is_empty());
    }

    #[test]
    fn covers_reports_the_uncovered_part() {
        let company = set(&["tcp 10.0.0.0/24 80-90"]);
        assert_eq!(
            covers(&company, &"tcp 10.0.0.0/25 85".parse().unwrap()),
            Ok(())
        );
        let err = covers(&company, &"tcp 10.0.0.0/23 85-95".parse().unwrap()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "not covered: tcp 10.0.0.0-10.0.0.255 91-95, \
             tcp 10.0.1.0-10.0.1.255 85-95"
        );
    }

    #[test]
    fn addresses_leave_out_the_endpoint() {
        let s = set(&["tcp 10.0.0.0/30 443"]);
        let shown: Vec<String> = s
            .addresses(&["10.0.0.1/32".parse().unwrap()])
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(shown, ["10.0.0.0/32", "10.0.0.2/31"]);
    }

    #[test]
    fn addresses_aggregate_across_protocols() {
        let s = set(&[
            "tcp 172.16.16.1/32 6443",
            "icmp 172.19.9.10/32",
            "icmp 172.19.9.11/32",
            "udp 172.19.9.12/32 53",
        ]);
        let shown: Vec<String> = s.addresses(&[]).iter().map(|n| n.to_string()).collect();
        assert_eq!(
            shown,
            ["172.16.16.1/32", "172.19.9.10/31", "172.19.9.12/32"]
        );
    }
}
