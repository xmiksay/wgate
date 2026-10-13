//! Networks that are gone: registered ones, and leftovers whose registration was lost.

use std::path::Path;

use wgate_core::{Compiled, Id, render_network_removal};

use super::steps::{nft, run, strip_peers};
use crate::keys;
use crate::runner::Runner;

/// Takes away the registered networks that are not compiled under the same interface
/// *and* id, so a new network that reuses a slug starts on a fresh interface. The
/// interface goes before the map entry: deleting it cuts the traffic at once, and the
/// entry stays as the marker that retries a removal that failed halfway. Returns the
/// interfaces whose removal failed: they are not reused until it succeeds.
pub(super) fn remove_gone(
    r: &dyn Runner,
    c: &Compiled,
    keys_dir: &Path,
    registered: &[(String, Id)],
    links: &mut Vec<String>,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let mut blocked = vec![];
    for (iface, id) in registered {
        if c.networks.iter().any(|n| n.iface == *iface && n.id == *id) {
            continue;
        }
        // The name may have been taken again after wgate's interface went: only one
        // with the network's key (or none yet) is deleted.
        let present = links.contains(iface);
        let ours = present && {
            let shown = interface_key(r, iface);
            shown.is_none()
                || keys::load(r, keys_dir, &format!("n{id}"))
                    .ok()
                    .flatten()
                    .is_some_and(|(_, public)| shown.as_deref() == Some(public.as_str()))
        };
        if present && !ours {
            errors.push(format!(
                "{iface}: carries a key that is not network {id}'s; left alone"
            ));
        }
        let removed = if ours {
            run(r, &["ip", "link", "del", iface]).map(|()| links.retain(|l| l != iface))
        } else {
            Ok(())
        }
        .and_then(|()| nft(r, &render_network_removal(*id, iface)));
        match removed {
            Ok(()) => tracing::info!(%iface, network = id, "network removed"),
            Err(e) => {
                errors.push(format!("{iface} (removing network {id}): {e:#}"));
                // Still there: it must at least stop carrying the gone network.
                if ours
                    && links.contains(iface)
                    && let Err(e) = strip_peers(r, iface)
                {
                    errors.push(format!("{iface} (removing network {id}): peers: {e:#}"));
                }
                blocked.push(iface.clone());
            }
        }
    }
    blocked
}

/// Interfaces that lost their registration (a flushed table) and carry the key of a
/// network no longer compiled on them are wgate's leftovers: deleted, so their name
/// and port come free.
pub(super) fn remove_unregistered(
    r: &dyn Runner,
    c: &Compiled,
    keys_dir: &Path,
    registered: Option<&[(String, Id)]>,
    links: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    for link in links.clone() {
        let is_registered = registered.is_some_and(|reg| reg.iter().any(|(i, _)| *i == link));
        if !link.starts_with("wg-") || is_registered {
            continue;
        }
        let Some(id) = interface_key(r, &link).and_then(|key| keys::owner_of(r, keys_dir, &key))
        else {
            continue;
        };
        if c.networks.iter().any(|n| n.id == id && n.iface == link) {
            continue;
        }
        match run(r, &["ip", "link", "del", &link]) {
            Ok(()) => {
                tracing::info!(%link, network = id, "unregistered interface of a gone network removed");
                links.retain(|l| *l != link);
            }
            Err(e) => errors.push(format!("{link} (network {id}, unregistered): {e:#}")),
        }
    }
}

/// The public key an interface has; `None` when it has none (or cannot be read).
pub(super) fn interface_key(r: &dyn Runner, iface: &str) -> Option<String> {
    let key = r.run(&["wg", "show", iface, "public-key"], None).ok()?;
    let key = key.trim();
    (!key.is_empty() && key != "(none)").then(|| key.to_owned())
}
