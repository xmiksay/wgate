//! What is gone: interfaces wgate made (by their mark) for a network no longer
//! compiled on them, and registrations (`from_net`) of such networks.

use wgate_core::{Compiled, Id, render_network_cutoff, render_network_removal};

use super::steps::{Link, SCRATCH, disarm, nft, run};
use crate::runner::Runner;

/// Deletes the interfaces wgate made whose network is not compiled under that name,
/// and unmarked scratch leftovers of a creation that crashed. Returns the ones that
/// would not go (disarmed instead; their names are not reused until they do), and the
/// `(name, network)` of every marked one, to be unregistered too.
pub(super) fn remove_gone_links(
    r: &dyn Runner,
    c: &Compiled,
    links: &mut Vec<Link>,
    errors: &mut Vec<String>,
) -> (Vec<String>, Vec<(String, Id)>) {
    let mut stuck = vec![];
    let mut gone_pairs = vec![];
    for link in links.clone() {
        let gone = match link.owner {
            Some(id) => !c
                .networks
                .iter()
                .any(|n| n.id == id && n.iface == link.name),
            None => link.name.starts_with(SCRATCH),
        };
        if !gone {
            continue;
        }
        if let Some(id) = link.owner {
            gone_pairs.push((link.name.clone(), id));
        }
        match run(r, &["ip", "link", "del", &link.name]) {
            Ok(()) => {
                tracing::info!(link = %link.name, network = ?link.owner, "interface removed");
                links.retain(|l| *l != link);
            }
            Err(e) => {
                errors.push(format!("{} (gone): {e:#}", link.name));
                // Still there: it must at least stop carrying the gone network.
                if let Err(e) = disarm(r, &link.name) {
                    errors.push(format!("{} (gone): disarm: {e:#}", link.name));
                }
                stuck.push(link.name);
            }
        }
    }
    (stuck, gone_pairs)
}

/// Takes `(iface, id)` out of the table: its map entries, chains and sets. Without
/// the entries the base drops the interface's traffic. One that still fails has its
/// chains cut off to `drop`, so its old rights never outlive it.
pub(super) fn unregister(r: &dyn Runner, iface: &str, id: Id, errors: &mut Vec<String>) {
    match nft(r, &render_network_removal(id, iface)) {
        Ok(()) => tracing::info!(%iface, network = id, "unregistered"),
        Err(e) => {
            errors.push(format!("{iface} (unregistering network {id}): {e:#}"));
            if let Err(e) = nft(r, &render_network_cutoff(id)) {
                errors.push(format!(
                    "{iface} (unregistering network {id}): cutoff: {e:#}"
                ));
            }
        }
    }
}
