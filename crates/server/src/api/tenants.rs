//! Tenants, their pool blocks and their ceilings: the global admin's. A tenant admin
//! reads their own.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use ipnet::Ipv4Net;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use wgate_core::{is_inside, overlaps};
use wgate_db::entity::{ceiling, tenant, tenant_block};

use super::routes::clear_of_others_lans;
use super::{ServiceBody, begin, from_db, to_db};
use crate::audit;
use crate::auth::Actor;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct Tenant {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub disabled: bool,
}

impl From<tenant::Model> for Tenant {
    fn from(t: tenant::Model) -> Self {
        Self {
            id: t.id,
            slug: t.slug,
            name: t.name,
            disabled: t.disabled_at.is_some(),
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct TenantCreate {
    pub slug: String,
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct TenantUpdate {
    pub name: Option<String>,
    /// Disabling cuts every network of the tenant off at once (reversible).
    pub disabled: Option<bool>,
}

#[utoipa::path(get, path = "/tenants", responses((status = 200, body = [Tenant])))]
pub async fn list(State(s): State<AppState>, actor: Actor) -> Result<Json<Vec<Tenant>>, ApiError> {
    let mut q = tenant::Entity::find().order_by_asc(tenant::Column::Id);
    if let Some(own) = actor.scope() {
        q = q.filter(tenant::Column::Id.eq(own));
    }
    Ok(Json(
        q.all(&s.db).await?.into_iter().map(Tenant::from).collect(),
    ))
}

#[utoipa::path(get, path = "/tenants/{id}", responses((status = 200, body = Tenant)))]
pub async fn get(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Tenant>, ApiError> {
    actor.tenant(id)?;
    let t = tenant::Entity::find_by_id(id)
        .one(&s.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(t.into()))
}

#[utoipa::path(post, path = "/tenants", request_body = TenantCreate, responses((status = 201, body = Tenant)))]
pub async fn create(
    State(s): State<AppState>,
    actor: Actor,
    Json(body): Json<TenantCreate>,
) -> Result<(StatusCode, Json<Tenant>), ApiError> {
    actor.global()?;
    let txn = begin(&s.db).await?;
    let t = tenant::ActiveModel {
        slug: Set(body.slug),
        name: Set(body.name),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "tenant.create",
        format!("tenant/{}", t.id),
        json!({ "slug": t.slug }),
    )
    .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(t.into())))
}

#[utoipa::path(patch, path = "/tenants/{id}", request_body = TenantUpdate, responses((status = 200, body = Tenant)))]
pub async fn update(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<TenantUpdate>,
) -> Result<Json<Tenant>, ApiError> {
    actor.global()?;
    let txn = begin(&s.db).await?;
    let mut t = tenant::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ApiError::NotFound)?
        .into_active_model();
    if let Some(name) = &body.name {
        t.name = Set(name.clone());
    }
    if let Some(disabled) = body.disabled {
        t.disabled_at = Set(disabled.then(|| chrono::Utc::now().fixed_offset()));
    }
    let t = t.update(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "tenant.update",
        format!("tenant/{id}"),
        json!({ "name": body.name, "disabled": body.disabled }),
    )
    .await?;
    txn.commit().await?;
    Ok(Json(t.into()))
}

/// Takes everything of the tenant along: blocks, networks, users, devices, peers,
/// rules, ceilings.
#[utoipa::path(delete, path = "/tenants/{id}", responses((status = 204)))]
pub async fn remove(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    actor.global()?;
    let txn = begin(&s.db).await?;
    let gone = tenant::Entity::delete_by_id(id).exec(&txn).await?;
    if gone.rows_affected == 0 {
        return Err(ApiError::NotFound);
    }
    audit::record(
        &txn,
        Some(actor.user_id),
        "tenant.delete",
        format!("tenant/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct Block {
    pub id: i64,
    pub tenant_id: i64,
    #[schema(value_type = String)]
    pub cidr: Ipv4Net,
}

#[derive(Deserialize, ToSchema)]
pub struct BlockCreate {
    #[schema(value_type = String)]
    pub cidr: Ipv4Net,
}

fn block(b: tenant_block::Model) -> Result<Block, ApiError> {
    Ok(Block {
        id: b.id,
        tenant_id: b.tenant_id,
        cidr: from_db(b.cidr)?,
    })
}

#[utoipa::path(get, path = "/tenants/{id}/blocks", responses((status = 200, body = [Block])))]
pub async fn blocks(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Vec<Block>>, ApiError> {
    actor.tenant(id)?;
    let rows = tenant_block::Entity::find()
        .filter(tenant_block::Column::TenantId.eq(id))
        .order_by_asc(tenant_block::Column::Id)
        .all(&s.db)
        .await?;
    Ok(Json(rows.into_iter().map(block).collect::<Result<_, _>>()?))
}

/// A block of the pool (never reserved space); the schema keeps blocks and routed
/// LANs disjoint.
#[utoipa::path(post, path = "/tenants/{id}/blocks", request_body = BlockCreate, responses((status = 201, body = Block)))]
pub async fn add_block(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<BlockCreate>,
) -> Result<(StatusCode, Json<Block>), ApiError> {
    actor.global()?;
    let cidr = body.cidr.trunc();
    if cidr != body.cidr {
        return Err(ApiError::invalid(format!(
            "{} has host bits; {cidr}?",
            body.cidr
        )));
    }
    if !is_inside(cidr, &s.config.pool) {
        return Err(ApiError::invalid(format!("{cidr} is not inside the pool")));
    }
    if s.config.reserved.iter().any(|r| overlaps(*r, cidr)) {
        return Err(ApiError::invalid(format!("{cidr} overlaps reserved space")));
    }
    let txn = begin(&s.db).await?;
    let b = tenant_block::ActiveModel {
        tenant_id: Set(id),
        cidr: Set(to_db(cidr)),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "block.create",
        format!("tenant_block/{}", b.id),
        json!({ "tenant_id": id, "cidr": cidr.to_string() }),
    )
    .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(block(b)?)))
}

/// Takes the block's networks (and their peers) along.
#[utoipa::path(delete, path = "/blocks/{id}", responses((status = 204)))]
pub async fn remove_block(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    actor.global()?;
    let txn = begin(&s.db).await?;
    if tenant_block::Entity::delete_by_id(id)
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
        "block.delete",
        format!("tenant_block/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct Ceiling {
    pub id: i64,
    pub tenant_id: i64,
    #[schema(value_type = String)]
    pub dst: Ipv4Net,
    #[serde(flatten)]
    pub service: ServiceBody,
}

#[derive(Deserialize, ToSchema)]
pub struct CeilingCreate {
    #[schema(value_type = String)]
    pub dst: Ipv4Net,
    #[serde(flatten)]
    pub service: ServiceBody,
}

fn ceiling_out(c: ceiling::Model) -> Result<Ceiling, ApiError> {
    Ok(Ceiling {
        id: c.id,
        tenant_id: c.tenant_id,
        dst: from_db(c.dst)?,
        service: ServiceBody::from_columns(&c.proto, c.port_from, c.port_to),
    })
}

#[utoipa::path(get, path = "/tenants/{id}/ceilings", responses((status = 200, body = [Ceiling])))]
pub async fn ceilings(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Vec<Ceiling>>, ApiError> {
    actor.tenant(id)?;
    let rows = ceiling::Entity::find()
        .filter(ceiling::Column::TenantId.eq(id))
        .order_by_asc(ceiling::Column::Id)
        .all(&s.db)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(ceiling_out)
            .collect::<Result<_, _>>()?,
    ))
}

/// What a tenant's networks may be granted outside tenant space.
#[utoipa::path(post, path = "/tenants/{id}/ceilings", request_body = CeilingCreate, responses((status = 201, body = Ceiling)))]
pub async fn add_ceiling(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<CeilingCreate>,
) -> Result<(StatusCode, Json<Ceiling>), ApiError> {
    actor.global()?;
    let (proto, port_from, port_to) = body.service.columns()?;
    let txn = begin(&s.db).await?;
    clear_of_others_lans(&txn, id, body.dst.trunc()).await?;
    let c = ceiling::ActiveModel {
        tenant_id: Set(id),
        proto: Set(proto),
        dst: Set(to_db(body.dst.trunc())),
        port_from: Set(port_from),
        port_to: Set(port_to),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "ceiling.create",
        format!("ceiling/{}", c.id),
        json!({ "tenant_id": id, "dst": body.dst.to_string(), "service": body.service }),
    )
    .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(ceiling_out(c)?)))
}

/// Rules it no longer covers drop out of the next compile (fail closed).
#[utoipa::path(delete, path = "/ceilings/{id}", responses((status = 204)))]
pub async fn remove_ceiling(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    actor.global()?;
    let txn = begin(&s.db).await?;
    if ceiling::Entity::delete_by_id(id)
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
        "ceiling.delete",
        format!("ceiling/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
