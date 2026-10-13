//! Who may hold what on wgate's interfaces this pass: the one account that growth
//! and rights are drawn from. An address is held by one peer at most; while that cannot
//! be shown, nobody else takes it.

use anyhow::Context;
use ipnet::Ipv4Net;
use wgate_core::{Compiled, CompiledNetwork, Id};

use super::gone::Gone;
use super::steps::{Link, current_peers, current_routes, removals, route_deletions, set_ranges};
use super::{Plan, note};
use crate::runner::Runner;

/// The account. Two kinds of holdings: what failed to be released (nobody's this
/// pass: no peer, route or right takes it), and what interfaces the pass leaves
/// alone may hold (no other network takes it; rights to it stay).
#[derive(Debug, Default)]
pub(super) struct Ledger {
    unreleased: Vec<Ipv4Net>,
    /// By the network whose interface may hold it (its own additions are not blocked
    /// by it), or `None` for an interface of no compiled network.
    elsewhere: Vec<(Option<Id>, Vec<Ipv4Net>)>,
    /// What networks whose peers cannot be read may hold: their own rules give it to
    /// nobody, so a revocation holds while the read fails.
    unread: Vec<Ipv4Net>,
    /// Some holdings cannot even be told: nothing is known to be free.
    unknown: bool,
    /// What the previous pass left held: still counted (and carried on) while some
    /// network is unread, as that network may still hold it.
    before: Vec<Ipv4Net>,
    before_used: bool,
}

impl Ledger {
    /// From what gone interfaces that would not go still hold.
    pub fn new(gone: &Gone, previously_held: &[Ipv4Net]) -> Self {
        Self {
            unreleased: gone.held.clone(),
            unknown: gone.blind,
            before: previously_held.to_vec(),
            ..Self::default()
        }
    }

    /// An invalid network's interface, kept as it is: what it holds there.
    pub fn kept(&mut self, r: &dyn Runner, link: &Link) {
        match (current_peers(r, &link.name), current_routes(r, &link.name)) {
            (Ok(peers), Ok(routes)) => {
                let held = peers.into_iter().flat_map(|p| p.allowed).chain(routes);
                self.elsewhere.push((None, held.collect()));
            }
            _ => self.unknown = true,
        }
    }

    /// A network whose peers (`peers`) or routes cannot be read: what it may hold
    /// there is what is compiled for it and what its rules last gave (`n<id>_peers`).
    fn unreadable(&mut self, r: &dyn Runner, c: &Compiled, n: &CompiledNetwork, peers: bool) {
        let mut may_hold: Vec<Ipv4Net> = c.peers_of(n.id).flat_map(|p| p.addrs.clone()).collect();
        match set_ranges(r, &format!("n{}_peers", n.id)) {
            Ok(last) => may_hold.extend(last),
            Err(_) => self.unknown = true,
        }
        if peers {
            self.unread.extend_from_slice(&may_hold);
        }
        self.elsewhere.push((Some(n.id), may_hold));
        self.before_used = true;
    }

    /// Whether anything may grow: only while every holding is known.
    pub fn grows(&self) -> bool {
        !self.unknown
    }

    /// What no right is given to.
    pub fn cut(&self) -> &[Ipv4Net] {
        &self.unreleased
    }

    /// What no right is given to in the rules of networks whose peers are unread.
    pub fn cut_unread(&self) -> Vec<Ipv4Net> {
        dedup(
            [
                self.unreleased.as_slice(),
                &self.unread,
                self.carried_before(),
            ]
            .concat(),
        )
    }

    /// What no peer or route of network `id` takes this pass.
    pub fn taken_for(&self, id: Id) -> Vec<Ipv4Net> {
        let elsewhere = self
            .elsewhere
            .iter()
            .filter(|(by, _)| *by != Some(id))
            .flat_map(|(_, addrs)| addrs.iter().copied());
        dedup(
            self.unreleased
                .iter()
                .copied()
                .chain(elsewhere)
                .chain(self.carried_before().iter().copied())
                .collect(),
        )
    }

    /// What the next pass still counts: what failed to be released now, and what an
    /// earlier pass left held while some network stays unread. Not what is merely
    /// compiled or last given (read again each pass), so nothing piles up.
    pub fn carried(&self) -> Vec<Ipv4Net> {
        dedup([self.unreleased.as_slice(), self.carried_before()].concat())
    }

    fn carried_before(&self) -> &[Ipv4Net] {
        if self.before_used { &self.before } else { &[] }
    }
}

fn dedup(mut nets: Vec<Ipv4Net>) -> Vec<Ipv4Net> {
    nets.sort_unstable();
    nets.dedup();
    nets
}

/// What anyone loses, in every network, before any network's rules change or grow:
/// an address or LAN moving between peers or networks is never held twice. What fails
/// to be released stays in the ledger. Returns the networks whose peers could not be
/// read (they get no changes on their interface this pass).
pub(super) fn revoke_all(
    r: &dyn Runner,
    c: &Compiled,
    active: &[(&CompiledNetwork, bool, Plan)],
    ledger: &mut Ledger,
    errors: &mut Vec<String>,
) -> Vec<Id> {
    let mut unread = vec![];
    for (n, _, plan) in active {
        match &plan.peers {
            Ok(peers) => {
                let (result, still) = removals(r, &n.iface, peers);
                ledger.unreleased.extend(still);
                note(
                    result.with_context(|| format!("{}: peers", n.iface)),
                    errors,
                );
            }
            Err(e) => {
                errors.push(format!("{}: peers: {e:#}", n.iface));
                ledger.unreadable(r, c, n, true);
                unread.push(n.id);
            }
        }
        match &plan.routes {
            Ok((_, del)) => {
                let (result, still) = route_deletions(r, &n.iface, del);
                ledger.unreleased.extend(still);
                note(
                    result.with_context(|| format!("{}: routes", n.iface)),
                    errors,
                );
            }
            // No route of its is added this pass (`network` adds only what it read).
            Err(e) => {
                errors.push(format!("{}: routes: {e:#}", n.iface));
                if plan.peers.is_ok() {
                    ledger.unreadable(r, c, n, false);
                }
            }
        }
    }
    unread
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(s: &[&str]) -> Vec<Ipv4Net> {
        s.iter().map(|n| n.parse().unwrap()).collect()
    }

    #[test]
    fn what_fails_to_go_is_cut_from_rights_and_taken() {
        let gone = Gone {
            held: nets(&["10.50.9.2/32"]),
            ..Gone::default()
        };
        let mut ledger = Ledger::new(&gone, &nets(&["10.50.8.0/24"]));
        assert!(ledger.grows());
        assert_eq!(ledger.cut(), nets(&["10.50.9.2/32"]));
        // What the previous pass left held counts only while a network is unread.
        assert_eq!(ledger.taken_for(1), nets(&["10.50.9.2/32"]));
        assert_eq!(ledger.carried(), nets(&["10.50.9.2/32"]));
        ledger
            .elsewhere
            .push((Some(2), nets(&["10.50.2.0/24", "10.50.9.2/32"])));
        ledger.before_used = true;
        // A network's own possible holdings never block it; nothing is counted twice.
        assert_eq!(ledger.taken_for(2), nets(&["10.50.8.0/24", "10.50.9.2/32"]));
        assert_eq!(
            ledger.taken_for(1),
            nets(&["10.50.2.0/24", "10.50.8.0/24", "10.50.9.2/32"])
        );
        // The next pass carries what failed and the earlier carry-over, not what is
        // read again anyway.
        assert_eq!(ledger.carried(), nets(&["10.50.8.0/24", "10.50.9.2/32"]));
        let blind = Ledger::new(
            &Gone {
                blind: true,
                ..Gone::default()
            },
            &[],
        );
        assert!(!blind.grows());
    }
}
