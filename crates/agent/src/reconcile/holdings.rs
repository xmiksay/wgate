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
    elsewhere: Vec<Ipv4Net>,
    /// What networks whose peers cannot be read may hold: their own rules give it to
    /// nobody, so a revocation holds while the read fails.
    unread: Vec<Ipv4Net>,
    /// Some holdings cannot even be told: nothing is known to be free.
    unknown: bool,
    /// What the previous pass left held, still counted while a network is unread.
    before: Vec<Ipv4Net>,
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
                self.elsewhere
                    .extend(peers.into_iter().flat_map(|p| p.allowed));
                self.elsewhere.extend(routes);
            }
            _ => self.unknown = true,
        }
    }

    /// A network whose peers (`peers`) or routes cannot be read: what it may hold
    /// there is what is compiled for it, what its rules last gave (`n<id>_peers`), and
    /// what an earlier pass left held and so out of its rules.
    fn unreadable(&mut self, r: &dyn Runner, c: &Compiled, n: &CompiledNetwork, peers: bool) {
        let mut may_hold: Vec<Ipv4Net> = c.peers_of(n.id).flat_map(|p| p.addrs.clone()).collect();
        match set_ranges(r, &format!("n{}_peers", n.id)) {
            Ok(last) => may_hold.extend(last),
            Err(_) => self.unknown = true,
        }
        may_hold.extend(std::mem::take(&mut self.before));
        if peers {
            self.unread.extend_from_slice(&may_hold);
        }
        self.elsewhere.extend(may_hold);
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
        [self.unreleased.as_slice(), &self.unread].concat()
    }

    /// What no peer or route of any network takes this pass; carried to the next.
    pub fn taken(&self) -> Vec<Ipv4Net> {
        [self.unreleased.as_slice(), &self.elsewhere].concat()
    }
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
        let ledger = Ledger::new(&gone, &nets(&["10.50.8.0/24"]));
        assert!(ledger.grows());
        assert_eq!(ledger.cut(), nets(&["10.50.9.2/32"]));
        // What the previous pass left held counts only while a network is unread.
        assert_eq!(ledger.taken(), nets(&["10.50.9.2/32"]));
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
