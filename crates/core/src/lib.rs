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
    Compiled, CompiledPeer, DesiredState, Federation, Id, NetRule, Network, Peer, Problem, Tenant,
    compile,
};
pub use net::{
    InvalidSlug, MAX_NETWORK_PREFIX, PORT_RANGE, RESERVED_PORT, Slug, first_overlap, hub_address,
    is_inside, is_peer_ip, next_free_net, next_peer_ip, next_port, overlaps,
};
pub use nft::{NftRender, NftState, render_nft};
pub use rights::{AddrRange, Element, RuleSet, Uncovered, covers, subtract_nets};
pub use rule::{PortRange, Proto, Rule, RuleError, Service};

#[cfg(test)]
mod testing {
    use std::path::PathBuf;

    use crate::{Rule, RuleSet};

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
