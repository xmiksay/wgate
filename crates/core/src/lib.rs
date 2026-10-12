//! Pure logic: model, rights (intersection), allocators, nft and client-config rendering. No I/O.

mod client;
mod interval;
mod net;
mod nft;
mod rights;
mod rule;

pub use client::{ClientConfig, render_client_config};
pub use net::{
    InvalidSlug, NET_INDEX_RANGE, Slug, TENANT_CIDR, company_subnet, hub_ip, listen_port,
    next_device_ip, next_net_index,
};
pub use nft::{NftDevice, NftState, render_nft};
pub use rights::{AddrRange, Element, RuleSet, Uncovered, covers, effective};
pub use rule::{PortRange, Proto, Rule, RuleError};

#[cfg(test)]
mod golden {
    use std::path::PathBuf;

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
