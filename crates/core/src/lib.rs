//! Pure logic: model, rights (intersection), allocators, nft and client-config rendering. No I/O.

mod client;
mod interval;
mod net;
mod nft;
mod rights;
mod rule;

pub use client::{ClientConfig, render_client_config};
pub use net::{
    InvalidNetIndex, InvalidSlug, NET_INDEX_RANGE, NetIndex, Slug, TENANT_CIDR, next_net_index,
};
pub use nft::{NftDevice, NftRender, NftState, render_nft};
pub use rights::{AddrRange, Element, RuleSet, Uncovered, covers, effective};
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
