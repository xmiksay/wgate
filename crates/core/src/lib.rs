//! Pure logic: addressing, rights, compile of the desired state, nft and client-config
//! rendering. No I/O.

mod client;
mod compile;
mod interval;
mod net;
mod nft;
mod rights;
mod rule;

pub use client::{ClientConfig, render_client_config};
pub use compile::{
    Claim, Compiled, CompiledPeer, DesiredState, Federation, Id, NetRule, Network, Peer, Problem,
    Tenant, compile,
};
pub use net::{
    InvalidSlug, MAX_NETWORK_PREFIX, PORT_RANGE, RESERVED_PORT, Slug, first_overlap, hub_address,
    is_inside, is_peer_ip, is_wg_key, next_free_net, next_peer_ip, next_port, overlaps,
};
pub use nft::render_nft;
pub use rights::{AddrRange, Element, RuleSet, Uncovered, covers, merge_nets, subtract_nets};
pub use rule::{PortRange, Proto, Rule, RuleError, Service};

#[cfg(test)]
mod testing {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use ipnet::Ipv4Net;

    use crate::{Claim, Id, Peer, PortRange, Rule, RuleSet, Service};

    pub(crate) fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    pub(crate) fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    pub(crate) fn tcp(port: u16) -> Service {
        Service::Tcp(PortRange::new(port, port).unwrap())
    }

    pub(crate) fn peer(id: Id, network: Id, addr: &str, routed: &[&str]) -> Peer {
        Peer {
            id,
            network,
            ip: ip(addr),
            public_key: key(id),
            // A global admin's device: may join any network.
            owner_tenant: None,
            routed: routed
                .iter()
                .enumerate()
                .map(|(i, r)| Claim {
                    id: id * 100 + i as Id,
                    cidr: net(r),
                })
                .collect(),
        }
    }

    /// A valid WireGuard key, distinct per `id`.
    pub(crate) fn key(id: Id) -> String {
        format!("{:0>42}A=", id.unsigned_abs())
    }

    /// A block claimed with `id`.
    pub(crate) fn block(id: Id, cidr: &str) -> Claim {
        Claim {
            id,
            cidr: net(cidr),
        }
    }

    pub(crate) fn rule_set(rules: &[&str]) -> RuleSet {
        let rules: Vec<Rule> = rules.iter().map(|r| r.parse().unwrap()).collect();
        RuleSet::from_rules(&rules)
    }

    /// Compares against `tests/golden/<name>`; `UPDATE_GOLDEN=1` rewrites the file.
    pub(crate) fn assert_golden(name: &str, actual: &str) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden")
            .join(name);
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, actual).unwrap();
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (run with UPDATE_GOLDEN=1)", path.display()));
        assert_eq!(
            actual, expected,
            "golden {name} differs (UPDATE_GOLDEN=1 to accept)"
        );
    }
}
