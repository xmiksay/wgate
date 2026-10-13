//! What is gone: interfaces wgate made (by their mark) for a network no longer
//! compiled on them, and registrations (`from_net`) of such networks.

use ipnet::Ipv4Net;
use wgate_core::{
    Compiled, Id, render_network_cutoff, render_network_removal, render_network_unmap,
};

use super::steps::{Link, SCRATCH, disarm, nft, run};
use crate::runner::Runner;

/// What [`remove_gone_links`] left.
#[derive(Default)]
pub(super) struct Gone {
    /// `(name, network)` of the marked interfaces deleted: to be unregistered too.
    pub deleted: Vec<(String, Id)>,
    /// Those that would not go (disarmed instead): their names are not reused, and
    /// their ports may be freed, until they do.
    pub stuck: Vec<String>,
    /// What the stuck ones still hold.
    pub held: Vec<Ipv4Net>,
    /// Whether what a stuck one holds could not even be read.
    pub blind: bool,
}

/// Deletes the interfaces wgate made whose network is not compiled under that name,
/// and scratch links (`wgtmp-*`, wgate's own namespace) a crashed creation left.
pub(super) fn remove_gone_links(
    r: &dyn Runner,
    c: &Compiled,
    links: &mut Vec<Link>,
    errors: &mut Vec<String>,
) -> Gone {
    let mut gone = Gone::default();
    for link in links.clone() {
        let is_gone = match link.owner {
            // Invalid this pass (a bad block, range or setting) is not gone: it keeps
            // its interface, unregistered, so a fix brings it straight back.
            Some(id) if c.invalid_networks.contains(&id) => false,
            Some(id) => !c
                .networks
                .iter()
                .any(|n| n.id == id && n.iface == link.name),
            None => link.name.starts_with(SCRATCH),
        };
        if !is_gone {
            continue;
        }
        match run(r, &["ip", "link", "del", &link.name]) {
            Ok(()) => {
                tracing::info!(link = %link.name, network = ?link.owner, "interface removed");
                if let Some(id) = link.owner {
                    gone.deleted.push((link.name.clone(), id));
                }
                links.retain(|l| *l != link);
            }
            Err(e) => {
                errors.push(format!("{} (gone): {e:#}", link.name));
                // Still there: it must at least stop carrying the gone network.
                let (result, held, blind) = disarm(r, &link.name);
                gone.held.extend(held);
                gone.blind |= blind;
                if let Err(e) = result {
                    errors.push(format!("{} (gone): disarm: {e:#}", link.name));
                }
                gone.stuck.push(link.name);
            }
        }
    }
    gone
}

/// Takes `(iface, id)` out of the table: its map entries, chains and sets. Without
/// the entries the base drops the interface's traffic. One that still fails has its
/// chains cut off to `drop`, so its old rights never outlive it.
pub(super) fn unregister(
    r: &dyn Runner,
    c: &Compiled,
    iface: &str,
    id: Id,
    errors: &mut Vec<String>,
) {
    // A stale name of a network that lives on another interface: its chains are that
    // network's, still in use; only the name's entries go.
    if c.networks.iter().any(|n| n.id == id && n.iface != iface) {
        let result = nft(r, &render_network_unmap(id, iface));
        if let Err(e) = result {
            errors.push(format!("{iface} (unmapping network {id}): {e:#}"));
        }
        return;
    }
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
