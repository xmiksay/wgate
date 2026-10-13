//! What is gone: interfaces wgate made (by their mark) for a network no longer
//! compiled on them, and registrations (`from_net`) of such networks.

use ipnet::Ipv4Net;
use wgate_core::{Compiled, Id, render_network_cutoff, render_network_purge};

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

/// Takes `iface`'s entries out of the dispatch maps, each on its own (only those
/// there: one that is not is no reason to keep the others), then network `id`'s chains
/// and sets unless the network lives on elsewhere. Without the entries the base drops
/// the interface's traffic; chains that will not go are cut off to `drop`, so old
/// rights never outlive their network.
pub(super) fn unregister(
    r: &dyn Runner,
    c: &Compiled,
    entries: &[(&str, String)],
    iface: &str,
    id: Id,
    errors: &mut Vec<String>,
) {
    for (map, _) in entries.iter().filter(|(_, i)| i == iface) {
        let script = format!("delete element inet wgate {map} {{ \"{iface}\" }}\n");
        if let Err(e) = nft(r, &script) {
            errors.push(format!(
                "{iface} (unregistering network {id}): {map}: {e:#}"
            ));
        }
    }
    if c.networks.iter().any(|n| n.id == id) {
        return;
    }
    match nft(r, &render_network_purge(id)) {
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
