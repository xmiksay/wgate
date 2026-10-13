//! Networks that are gone: registered ones, and leftovers whose registration was lost.
//! Also what decides whether an interface carries a network's key.

use anyhow::Context;
use wgate_core::{Compiled, Id, render_network_removal};

use super::steps::{disarm, nft, run};
use crate::keys::Keys;
use crate::runner::Runner;

/// Whose key an interface has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Carried {
    /// The network's own.
    Its,
    /// None yet (just created, before its key was set).
    Nothing,
    /// Someone else's.
    Other,
    /// A key, but the network's key file is missing: whose cannot be told.
    Unverified,
}

/// Whose key `iface` has, against network `id`'s. A failed read is an error, never
/// "no key": either reading would decide something irreversible.
pub(super) fn carried(r: &dyn Runner, keys: &Keys, iface: &str, id: Id) -> anyhow::Result<Carried> {
    let Some(shown) = interface_key(r, iface)? else {
        return Ok(Carried::Nothing);
    };
    Ok(match keys.load(id).context("hub key")? {
        Some((_, public)) if public == shown => Carried::Its,
        Some(_) => Carried::Other,
        None => Carried::Unverified,
    })
}

/// An interface whose network is gone but whose removal did not finish: not reused
/// until it does.
pub(super) struct Blocked {
    pub iface: String,
    /// Confirmed wgate's (so it may be touched, e.g. to free a port).
    pub ours: bool,
}

/// Takes away the registered networks that are not compiled under the same interface
/// *and* id, so a new network that reuses a slug starts on a fresh interface. The
/// interface goes before the map entry: deleting it cuts the traffic at once, and the
/// entry stays as the marker that retries a removal that failed halfway. Without the
/// list of links only the entry goes (that alone cuts the traffic; the interface is
/// found by its key later).
pub(super) fn remove_gone(
    r: &dyn Runner,
    c: &Compiled,
    keys: &Keys,
    registered: &[(String, Id)],
    mut links: Option<&mut Vec<String>>,
    errors: &mut Vec<String>,
) -> Vec<Blocked> {
    let mut blocked = vec![];
    for (iface, id) in registered {
        if c.networks.iter().any(|n| n.iface == *iface && n.id == *id) {
            continue;
        }
        let present = links.as_ref().is_none_or(|l| l.contains(iface));
        // The name may have been taken again after wgate's interface went: one with
        // another key is left alone. Without the key file the registration decides.
        let ours = match links.as_ref().map(|l| l.contains(iface)) {
            Some(false) => false,
            _ => match carried(r, keys, iface, *id) {
                Ok(Carried::Its | Carried::Nothing | Carried::Unverified) => true,
                Ok(Carried::Other) => {
                    errors.push(format!(
                        "{iface}: carries a key that is not network {id}'s; left alone"
                    ));
                    false
                }
                // Without the list of links a failed read is most likely no link.
                Err(_) if links.is_none() => false,
                Err(e) => {
                    errors.push(format!("{iface} (removing network {id}): {e:#}"));
                    blocked.push(Blocked {
                        iface: iface.clone(),
                        ours: false,
                    });
                    continue;
                }
            },
        };
        let removed = match links.as_deref_mut() {
            Some(links) if ours => {
                run(r, &["ip", "link", "del", iface]).map(|()| links.retain(|l| l != iface))
            }
            _ => Ok(()),
        }
        .and_then(|()| nft(r, &render_network_removal(*id, iface)));
        match removed {
            Ok(()) if links.is_none() && present && ours => {
                // Unregistered; its interface goes once the links can be listed.
                blocked.push(Blocked {
                    iface: iface.clone(),
                    ours,
                });
            }
            Ok(()) => tracing::info!(%iface, network = id, "network removed"),
            Err(e) => {
                errors.push(format!("{iface} (removing network {id}): {e:#}"));
                // Still there: it must at least stop carrying the gone network.
                let still = links.as_ref().is_some_and(|l| l.contains(iface));
                if ours
                    && still
                    && let Err(e) = disarm(r, iface)
                {
                    errors.push(format!("{iface} (removing network {id}): disarm: {e:#}"));
                }
                blocked.push(Blocked {
                    iface: iface.clone(),
                    ours,
                });
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
    keys: &Keys,
    registered: Option<&[(String, Id)]>,
    links: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    for link in links.clone() {
        let is_registered = registered.is_some_and(|reg| reg.iter().any(|(i, _)| *i == link));
        if !link.starts_with("wg-") || is_registered {
            continue;
        }
        let shown = interface_key(r, &link).ok().flatten();
        let Some(id) = shown.and_then(|key| keys.owner_of(&key)) else {
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

/// The public key an interface has; `None` when it has none.
pub(super) fn interface_key(r: &dyn Runner, iface: &str) -> anyhow::Result<Option<String>> {
    let key = r.run(&["wg", "show", iface, "public-key"], None)?;
    let key = key.trim();
    Ok((!key.is_empty() && key != "(none)").then(|| key.to_owned()))
}
