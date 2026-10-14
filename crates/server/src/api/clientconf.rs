//! A peer's client config, from the compiled desired state (so `AllowedIPs` is
//! exactly what its rights reach), and its QR code.

use std::net::{IpAddr, Ipv4Addr};

use sea_orm::EntityTrait;
use serde::Serialize;
use utoipa::ToSchema;
use wgate_core::{ClientConfig, compile, render_client_config};
use wgate_db::entity::{hub_key, network};

use super::dns_hosts;
use crate::error::ApiError;
use crate::state::AppState;
use crate::wgkey::qr_svg;

#[derive(Serialize, ToSchema)]
pub struct Rendered {
    /// The `wg-quick` config.
    pub config: String,
    /// The same as a QR code (SVG) for the WireGuard app; missing when the config is
    /// too long for one.
    pub qr_svg: Option<String>,
    /// What it was rendered from: a key rotation commits only while both still hold.
    #[serde(skip)]
    pub revision: i64,
    #[serde(skip)]
    pub hub_key: String,
}

/// `None` (with a warning saying why) while the peer has no config yet: it is not
/// part of the desired state, or the hub has not published the network's key.
pub async fn render(
    s: &AppState,
    peer_id: i64,
    private_key: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<Option<Rendered>, ApiError> {
    let loaded = wgate_db::desired_state(&s.db, &s.config.infra()).await?;
    let compiled = compile(&loaded.state);
    let Some(peer) = compiled.peers.iter().find(|p| p.id == peer_id) else {
        let why = compiled
            .skipped
            .iter()
            .find(|(id, _)| *id == peer_id)
            .map_or_else(|| "it is not active".to_owned(), |(_, p)| format!("{p:?}"));
        warnings.push(format!(
            "no config: the peer is not part of the desired state ({why})"
        ));
        return Ok(None);
    };
    let Some(net) = compiled.network(peer.network) else {
        warnings.push("no config: the peer's network is not part of the desired state".into());
        return Ok(None);
    };
    let Some(key) = hub_key::Entity::find_by_id(net.id).one(&s.db).await? else {
        warnings.push(
            "no config yet: the hub has not published the network's key; download it again \
             once the network is up"
                .into(),
        );
        return Ok(None);
    };
    let dns: Vec<Ipv4Addr> = network::Entity::find_by_id(net.id)
        .one(&s.db)
        .await?
        .map(|n| dns_hosts(&n.dns))
        .unwrap_or_default();
    let endpoint = format!("{}:{}", s.config.endpoint_host, net.port);
    let endpoint_ips: Vec<Ipv4Addr> = match tokio::net::lookup_host(&endpoint).await {
        Ok(addrs) => addrs
            .filter_map(|a| match a.ip() {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
            .collect(),
        Err(e) => {
            warnings.push(format!(
                "{} did not resolve ({e}): check that the rights do not cover the endpoint",
                s.config.endpoint_host
            ));
            vec![]
        }
    };
    let config = render_client_config(&ClientConfig {
        address: peer.ip,
        hub_address: net.hub,
        private_key,
        hub_public_key: &key.public_key,
        endpoint: &endpoint,
        endpoint_ips: &endpoint_ips,
        dns: &dns,
        outbound: &peer.outbound,
        inbound: &peer.inbound,
    });
    let qr_svg = qr_svg(&config);
    if qr_svg.is_none() {
        warnings.push("the config is too long for a QR code: import the file".into());
    }
    Ok(Some(Rendered {
        config,
        qr_svg,
        revision: loaded.revision,
        hub_key: key.public_key,
    }))
}
