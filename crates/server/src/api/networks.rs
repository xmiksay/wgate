//! Networks (a tenant admin's, inside their tenant's blocks) and inbound grants (the
//! global admin's: sources outside tenant space that may open to a network).

use std::net::{IpAddr, Ipv4Addr};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use ipnet::Ipv4Net;
use sea_orm::prelude::IpNetwork;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use wgate_core::{PORT_RANGE, RESERVED_PORT, Slug, overlaps};
use wgate_db::entity::{hub_key, inbound, network};

use super::{ServiceBody, begin, from_db, tenant_of_network, to_db};
use crate::audit;
use crate::auth::Actor;
use crate::error::ApiError;
use crate::state::AppState;

/// A source this broad routes most of the internet into every target peer's tunnel.
const BROAD_PREFIX: u8 = 16;

#[derive(Serialize, ToSchema)]
pub struct Network {
    pub id: i64,
    pub tenant_id: i64,
    pub block_id: i64,
    /// The interface is `wg-<slug>`.
    pub slug: String,
    pub name: String,
    #[schema(value_type = String)]
    pub cidr: Ipv4Net,
    pub port: u16,
    /// Members may reach each other without a rule.
    pub mesh: bool,
    #[schema(value_type = Vec<String>)]
    pub dns: Vec<Ipv4Addr>,
    pub disabled: bool,
    /// Published by the agent once the network is up.
    pub hub_public_key: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct NetworkCreate {
    pub tenant_id: i64,
    pub block_id: i64,
    pub slug: String,
    pub name: String,
    #[schema(value_type = String)]
    pub cidr: Ipv4Net,
    pub port: u16,
    #[serde(default)]
    pub mesh: bool,
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Deserialize, ToSchema)]
pub struct NetworkUpdate {
    pub name: Option<String>,
    pub mesh: Option<bool>,
    #[schema(value_type = Option<Vec<String>>)]
    pub dns: Option<Vec<Ipv4Addr>>,
    /// Disabling takes the interface down at once (reversible).
    pub disabled: Option<bool>,
}

#[derive(Deserialize, IntoParams)]
pub struct NetworkFilter {
    pub tenant_id: Option<i64>,
}

fn dns_db(dns: &[Ipv4Addr]) -> Vec<IpNetwork> {
    dns.iter()
        .map(|a| IpNetwork::from(IpAddr::V4(*a)))
        .collect()
}

async fn network_out(s: &AppState, n: network::Model) -> Result<Network, ApiError> {
    let key = hub_key::Entity::find_by_id(n.id).one(&s.db).await?;
    Ok(Network {
        id: n.id,
        tenant_id: n.tenant_id,
        block_id: n.block_id,
        slug: n.slug,
        name: n.name,
        cidr: from_db(n.cidr)?,
        port: u16::try_from(n.port).map_err(anyhow::Error::from)?,
        mesh: n.mesh,
        dns: n
            .dns
            .iter()
            .filter_map(|d| match d.ip() {
                IpAddr::V4(a) => Some(a),
                IpAddr::V6(_) => None,
            })
            .collect(),
        disabled: n.disabled_at.is_some(),
        hub_public_key: key.map(|k| k.public_key),
    })
}

#[utoipa::path(get, path = "/networks", params(NetworkFilter), responses((status = 200, body = [Network])))]
pub async fn list(
    State(s): State<AppState>,
    actor: Actor,
    Query(f): Query<NetworkFilter>,
) -> Result<Json<Vec<Network>>, ApiError> {
    let mut q = network::Entity::find().order_by_asc(network::Column::Id);
    if let Some(own) = actor.scope() {
        q = q.filter(network::Column::TenantId.eq(own));
    }
    if let Some(t) = f.tenant_id {
        q = q.filter(network::Column::TenantId.eq(t));
    }
    let mut out = vec![];
    for n in q.all(&s.db).await? {
        out.push(network_out(&s, n).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(get, path = "/networks/{id}", responses((status = 200, body = Network)))]
pub async fn get(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Network>, ApiError> {
    let n = network::Entity::find_by_id(id)
        .one(&s.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    actor.tenant(n.tenant_id)?;
    Ok(Json(network_out(&s, n).await?))
}

/// Inside one of its tenant's blocks; slug, range and port are the network's for good.
#[utoipa::path(post, path = "/networks", request_body = NetworkCreate, responses((status = 201, body = Network)))]
pub async fn create(
    State(s): State<AppState>,
    actor: Actor,
    Json(body): Json<NetworkCreate>,
) -> Result<(StatusCode, Json<Network>), ApiError> {
    actor.tenant(body.tenant_id)?;
    let slug: Slug = body
        .slug
        .parse()
        .map_err(|e: wgate_core::InvalidSlug| ApiError::invalid(e.to_string()))?;
    if body.cidr.trunc() != body.cidr {
        return Err(ApiError::invalid(format!("{} has host bits", body.cidr)));
    }
    if !PORT_RANGE.contains(&body.port) || body.port == RESERVED_PORT {
        return Err(ApiError::invalid(format!(
            "port {} is outside {}–{} (or reserved)",
            body.port,
            PORT_RANGE.start(),
            PORT_RANGE.end()
        )));
    }
    let txn = begin(&s.db).await?;
    let n = network::ActiveModel {
        tenant_id: Set(body.tenant_id),
        block_id: Set(body.block_id),
        slug: Set(slug.to_string()),
        name: Set(body.name),
        cidr: Set(to_db(body.cidr)),
        port: Set(i32::from(body.port)),
        mesh: Set(body.mesh),
        dns: Set(dns_db(&body.dns)),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    audit::record(&txn, Some(actor.user_id), "network.create", format!("network/{}", n.id), json!({ "tenant_id": n.tenant_id, "slug": n.slug, "cidr": body.cidr.to_string(), "port": body.port })).await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(network_out(&s, n).await?)))
}

#[utoipa::path(patch, path = "/networks/{id}", request_body = NetworkUpdate, responses((status = 200, body = Network)))]
pub async fn update(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<NetworkUpdate>,
) -> Result<Json<Network>, ApiError> {
    let txn = begin(&s.db).await?;
    let n = network::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ApiError::NotFound)?;
    actor.tenant(n.tenant_id)?;
    let mut m = n.into_active_model();
    if let Some(name) = &body.name {
        m.name = Set(name.clone());
    }
    if let Some(mesh) = body.mesh {
        m.mesh = Set(mesh);
    }
    if let Some(dns) = &body.dns {
        m.dns = Set(dns_db(dns));
    }
    if let Some(disabled) = body.disabled {
        m.disabled_at = Set(disabled.then(|| chrono::Utc::now().fixed_offset()));
    }
    let n = m.update(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "network.update",
        format!("network/{id}"),
        json!({ "name": body.name, "mesh": body.mesh, "dns": body.dns, "disabled": body.disabled }),
    )
    .await?;
    txn.commit().await?;
    Ok(Json(network_out(&s, n).await?))
}

/// Takes the network's peers, routes, rules, federations and grants along.
#[utoipa::path(delete, path = "/networks/{id}", responses((status = 204)))]
pub async fn remove(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let txn = begin(&s.db).await?;
    actor.tenant(tenant_of_network(&txn, id).await?)?;
    network::Entity::delete_by_id(id).exec(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "network.delete",
        format!("network/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct Inbound {
    pub id: i64,
    pub network_id: i64,
    #[schema(value_type = String)]
    pub source: Ipv4Net,
    #[serde(flatten)]
    pub service: ServiceBody,
    pub comment: String,
}

#[derive(Deserialize, ToSchema)]
pub struct InboundCreate {
    #[schema(value_type = String)]
    pub source: Ipv4Net,
    #[serde(flatten)]
    pub service: ServiceBody,
    #[serde(default)]
    pub comment: String,
}

#[derive(Serialize, ToSchema)]
pub struct InboundCreated {
    pub inbound: Inbound,
    /// E.g. a source so broad that every target peer becomes a full tunnel.
    pub warnings: Vec<String>,
}

fn inbound_out(i: inbound::Model) -> Result<Inbound, ApiError> {
    Ok(Inbound {
        id: i.id,
        network_id: i.network_id,
        source: from_db(i.source)?,
        service: ServiceBody::from_columns(&i.proto, i.port_from, i.port_to),
        comment: i.comment,
    })
}

#[utoipa::path(get, path = "/networks/{id}/inbound", responses((status = 200, body = [Inbound])))]
pub async fn inbound(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Vec<Inbound>>, ApiError> {
    actor.tenant(tenant_of_network(&s.db, id).await?)?;
    let rows = inbound::Entity::find()
        .filter(inbound::Column::NetworkId.eq(id))
        .order_by_asc(inbound::Column::Id)
        .all(&s.db)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(inbound_out)
            .collect::<Result<_, _>>()?,
    ))
}

/// Sources outside tenant space only (inside it, federations decide).
#[utoipa::path(post, path = "/networks/{id}/inbound", request_body = InboundCreate, responses((status = 201, body = InboundCreated)))]
pub async fn add_inbound(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<InboundCreate>,
) -> Result<(StatusCode, Json<InboundCreated>), ApiError> {
    actor.global()?;
    let source = body.source.trunc();
    if s.config.pool.iter().any(|p| overlaps(*p, source)) {
        return Err(ApiError::invalid(format!(
            "{source} overlaps the pool: inside tenant space, federations grant access"
        )));
    }
    let (proto, port_from, port_to) = body.service.columns()?;
    let txn = begin(&s.db).await?;
    tenant_of_network(&txn, id).await?;
    let i = inbound::ActiveModel {
        network_id: Set(id),
        source: Set(to_db(source)),
        proto: Set(proto),
        port_from: Set(port_from),
        port_to: Set(port_to),
        comment: Set(body.comment),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "inbound.create",
        format!("inbound/{}", i.id),
        json!({ "network_id": id, "source": source.to_string(), "service": body.service }),
    )
    .await?;
    txn.commit().await?;
    let warnings = if source.prefix_len() < BROAD_PREFIX {
        vec![format!(
            "{source} is broad: every peer of the network routes it into its tunnel"
        )]
    } else {
        vec![]
    };
    Ok((
        StatusCode::CREATED,
        Json(InboundCreated {
            inbound: inbound_out(i)?,
            warnings,
        }),
    ))
}

#[utoipa::path(delete, path = "/inbound/{id}", responses((status = 204)))]
pub async fn remove_inbound(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    actor.global()?;
    let txn = begin(&s.db).await?;
    if inbound::Entity::delete_by_id(id)
        .exec(&txn)
        .await?
        .rows_affected
        == 0
    {
        return Err(ApiError::NotFound);
    }
    audit::record(
        &txn,
        Some(actor.user_id),
        "inbound.delete",
        format!("inbound/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
