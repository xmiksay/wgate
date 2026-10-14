//! Who is signed in, whether the hub has caught up, the audit trail, and suggestions
//! for free addresses and ports (computed with core's allocators; nothing is taken
//! until a create sends it).

use std::net::Ipv4Addr;

use axum::Json;
use axum::extract::{Path, Query, State};
use ipnet::Ipv4Net;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    Statement,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use wgate_core::{next_free_net, next_peer_ip, next_port};
use wgate_db::entity::{audit, network, peer, tenant_block};

use super::{from_db, tenant_of_network};
use crate::auth::{Actor, Role};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct Session {
    pub user_id: i64,
    pub email: String,
    pub role: Role,
    pub tenant_id: Option<i64>,
    /// Send it back as `X-CSRF-Token` on every write.
    pub csrf: String,
}

#[utoipa::path(get, path = "/session", responses((status = 200, body = Session)))]
pub async fn session(actor: Actor) -> Json<Session> {
    Json(Session {
        user_id: actor.user_id,
        email: actor.email,
        role: actor.role,
        tenant_id: actor.tenant_id,
        csrf: actor.csrf,
    })
}

#[derive(Serialize, ToSchema)]
pub struct Status {
    /// The database's state revision.
    pub revision: i64,
    /// What the agent last applied (behind `revision` while it catches up).
    pub applied_revision: Option<i64>,
    pub applied_at: Option<String>,
    /// What the agent could not apply, if anything: its own words (every tenant's
    /// interfaces and ranges), so for a global admin only.
    pub error: Option<String>,
    /// Whether the agent reported an error.
    pub failing: bool,
}

#[utoipa::path(get, path = "/status", responses((status = 200, body = Status)))]
pub async fn status(State(s): State<AppState>, actor: Actor) -> Result<Json<Status>, ApiError> {
    let row =
        s.db.query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT r.revision, a.applied_revision, a.applied_at::text AS applied_at, a.error
             FROM state_revision r LEFT JOIN agent_status a ON true LIMIT 1",
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no state revision row"))?;
    let error: Option<String> = row.try_get("", "error")?;
    Ok(Json(Status {
        revision: row.try_get("", "revision")?,
        applied_revision: row.try_get("", "applied_revision")?,
        applied_at: row.try_get("", "applied_at")?,
        failing: error.is_some(),
        error: error.filter(|_| actor.is_global()),
    }))
}

#[derive(Serialize, ToSchema)]
pub struct AuditEntry {
    pub id: i64,
    pub at: String,
    pub actor_user_id: Option<i64>,
    pub action: String,
    pub target: String,
    pub detail: serde_json::Value,
}

#[derive(Deserialize, IntoParams)]
pub struct AuditPage {
    /// Entries older than this id (the previous page's last).
    pub before: Option<i64>,
    /// At most 200; 50 by default.
    pub limit: Option<u64>,
}

/// Newest first, a page at a time.
#[utoipa::path(get, path = "/audit", params(AuditPage), responses((status = 200, body = [AuditEntry])))]
pub async fn audit(
    State(s): State<AppState>,
    actor: Actor,
    Query(page): Query<AuditPage>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    actor.global()?;
    let mut q = audit::Entity::find().order_by_desc(audit::Column::Id);
    if let Some(before) = page.before {
        q = q.filter(audit::Column::Id.lt(before));
    }
    let rows = q
        .limit(page.limit.unwrap_or(50).min(200))
        .all(&s.db)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|a| AuditEntry {
                id: a.id,
                at: a.at.to_rfc3339(),
                actor_user_id: a.actor_user_id,
                action: a.action,
                target: a.target,
                detail: a.detail,
            })
            .collect(),
    ))
}

#[derive(Serialize, ToSchema)]
pub struct Suggestion<T: ToSchema> {
    /// `None`: nothing free.
    pub free: Option<T>,
}

#[derive(Deserialize, IntoParams)]
pub struct Prefix {
    pub prefix: u8,
}

/// A free peer address in the network.
#[utoipa::path(get, path = "/networks/{id}/free-ip", responses((status = 200, body = Suggestion<String>)))]
pub async fn free_ip(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Suggestion<String>>, ApiError> {
    actor.tenant(tenant_of_network(&s.db, id).await?)?;
    let net = network::Entity::find_by_id(id)
        .one(&s.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let used: Vec<Ipv4Addr> = peer::Entity::find()
        .filter(peer::Column::NetworkId.eq(id))
        .filter(peer::Column::RevokedAt.is_null())
        .all(&s.db)
        .await?
        .into_iter()
        .map(|p| from_db(p.ip).map(|n| n.addr()))
        .collect::<Result<_, _>>()?;
    let free = next_peer_ip(from_db(net.cidr)?, &used).map(|a| a.to_string());
    Ok(Json(Suggestion { free }))
}

#[derive(Deserialize, IntoParams)]
pub struct RangeQuery {
    pub prefix: u8,
    /// Only inside this block of the tenant's.
    pub block_id: Option<i64>,
}

/// A free range of `prefix` in the tenant's blocks (or in one of them).
#[utoipa::path(get, path = "/tenants/{id}/free-range", params(RangeQuery), responses((status = 200, body = Suggestion<String>)))]
pub async fn free_range(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Suggestion<String>>, ApiError> {
    actor.tenant(id)?;
    super::tenants::tenant_exists(&s.db, id).await?;
    let mut blocks = tenant_block::Entity::find().filter(tenant_block::Column::TenantId.eq(id));
    if let Some(block) = q.block_id {
        blocks = blocks.filter(tenant_block::Column::Id.eq(block));
    }
    let blocks: Vec<Ipv4Net> = blocks
        .all(&s.db)
        .await?
        .into_iter()
        .map(|b| from_db(b.cidr))
        .collect::<Result<_, _>>()?;
    let taken = all_cidrs(&s.db, "SELECT cidr::text AS c FROM network").await?;
    let free = next_free_net(&blocks, &taken, q.prefix).map(|n| n.to_string());
    Ok(Json(Suggestion { free }))
}

/// A free block of `prefix` in the pool (clear of reserved space and routed LANs).
#[utoipa::path(get, path = "/free-block", params(Prefix), responses((status = 200, body = Suggestion<String>)))]
pub async fn free_block(
    State(s): State<AppState>,
    actor: Actor,
    Query(q): Query<Prefix>,
) -> Result<Json<Suggestion<String>>, ApiError> {
    actor.global()?;
    let mut taken = all_cidrs(&s.db, "SELECT cidr::text AS c FROM tenant_block").await?;
    taken.extend(all_cidrs(&s.db, "SELECT cidr::text AS c FROM peer_route WHERE active").await?);
    taken.extend(s.config.reserved.iter().copied());
    let free = next_free_net(&s.config.pool, &taken, q.prefix).map(|n| n.to_string());
    Ok(Json(Suggestion { free }))
}

/// A free listen port.
#[utoipa::path(get, path = "/free-port", responses((status = 200, body = Suggestion<u16>)))]
pub async fn free_port(
    State(s): State<AppState>,
    _actor: Actor,
) -> Result<Json<Suggestion<u16>>, ApiError> {
    let used: Vec<u16> = network::Entity::find()
        .all(&s.db)
        .await?
        .into_iter()
        .filter_map(|n| u16::try_from(n.port).ok())
        .collect();
    Ok(Json(Suggestion {
        free: next_port(&used),
    }))
}

async fn all_cidrs<C: ConnectionTrait>(db: &C, sql: &str) -> Result<Vec<Ipv4Net>, ApiError> {
    let rows = db
        .query_all_raw(Statement::from_string(DbBackend::Postgres, sql))
        .await?;
    rows.into_iter()
        .map(|r| {
            let c: String = r.try_get("", "c")?;
            c.parse::<Ipv4Net>()
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("{c}: {e}")))
        })
        .collect()
}
