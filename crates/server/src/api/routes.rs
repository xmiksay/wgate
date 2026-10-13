//! The LANs a router peer routes: globally unique, inside routed space.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use ipnet::Ipv4Net;
use sea_orm::prelude::IpNetwork;
use sea_orm::{ActiveModelTrait, ConnectionTrait, DbBackend, EntityTrait, Set, Statement};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use wgate_core::{is_inside, overlaps};
use wgate_db::entity::peer_route;

use super::peers::owned;
use super::{begin, from_db, one_i64, tenant_of_network, to_db};
use crate::audit;
use crate::auth::Actor;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct Route {
    pub id: i64,
    #[schema(value_type = String)]
    pub cidr: Ipv4Net,
}

#[derive(Deserialize, ToSchema)]
pub struct RouteCreate {
    #[schema(value_type = String)]
    pub cidr: Ipv4Net,
}

/// Serializes the writes that check a LAN against other tenants' grants and back
/// (routes, ceilings, inbound): two concurrent ones could each miss the other.
pub(super) async fn lock_lans<C: ConnectionTrait>(db: &C) -> Result<(), ApiError> {
    db.execute_unprepared("SELECT pg_advisory_xact_lock(7767001)")
        .await?;
    Ok(())
}

/// A ceiling (`dst`) or inbound source of `tenant` must not reach another tenant's
/// routed LAN: across tenants only a federation grants access.
pub(super) async fn clear_of_others_lans<C: ConnectionTrait>(
    db: &C,
    tenant: i64,
    cidr: Ipv4Net,
) -> Result<(), ApiError> {
    lock_lans(db).await?;
    let clash = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT EXISTS (SELECT FROM peer_route r JOIN peer p ON p.id = r.peer_id
                            JOIN network n ON n.id = p.network_id
                            WHERE r.active AND n.tenant_id <> $1 AND r.cidr && $2) AS clash",
            [tenant.into(), to_db(cidr).into()],
        ))
        .await?
        .map(|r| r.try_get::<bool>("", "clash"))
        .transpose()?
        .unwrap_or(false);
    if clash {
        return Err(ApiError::invalid(format!(
            "{cidr} overlaps another tenant's routed LAN: a federation grants that"
        )));
    }
    Ok(())
}

/// A router's LAN: inside routed space, clear of the pool and of infrastructure
/// (node networks, the SNAT source, reserved space) as compile wants it, and of
/// every other tenant's ceilings and inbound sources (else their rights would reach
/// it). The schema keeps it clear of tenant blocks and other active LANs.
pub(super) async fn insert_route<C: ConnectionTrait>(
    s: &AppState,
    db: &C,
    tenant: i64,
    peer_id: i64,
    lan: Ipv4Net,
) -> Result<peer_route::Model, ApiError> {
    if lan.trunc() != lan {
        return Err(ApiError::invalid(format!("{lan} has host bits")));
    }
    if !is_inside(lan, &s.config.routed_space) {
        return Err(ApiError::invalid(format!("{lan} is outside routed space")));
    }
    let c = &s.config;
    let snat = [Ipv4Net::from(c.snat_source)];
    for (space, what) in [
        (c.pool.as_slice(), "the pool"),
        (&c.node_cidrs, "the node networks"),
        (&c.reserved, "reserved space"),
        (&snat, "the SNAT source"),
    ] {
        if space.iter().any(|r| overlaps(*r, lan)) {
            return Err(ApiError::invalid(format!("{lan} overlaps {what}")));
        }
    }
    lock_lans(db).await?;
    let cidr: IpNetwork = to_db(lan);
    let clash = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT EXISTS (SELECT FROM ceiling WHERE tenant_id <> $1 AND dst && $2)
                 OR EXISTS (SELECT FROM inbound i JOIN network n ON n.id = i.network_id
                            WHERE n.tenant_id <> $1 AND i.source && $2) AS clash",
            [tenant.into(), cidr.into()],
        ))
        .await?
        .map(|r| r.try_get::<bool>("", "clash"))
        .transpose()?
        .unwrap_or(false);
    if clash {
        return Err(ApiError::invalid(format!(
            "{lan} overlaps another tenant's ceiling or inbound source"
        )));
    }
    Ok(peer_route::ActiveModel {
        peer_id: Set(peer_id),
        cidr: Set(cidr),
        ..Default::default()
    }
    .insert(db)
    .await?)
}

#[utoipa::path(post, path = "/peers/{id}/routes", request_body = RouteCreate, responses((status = 201, body = Route)))]
pub async fn add_route(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<RouteCreate>,
) -> Result<(StatusCode, Json<Route>), ApiError> {
    let txn = begin(&s.db).await?;
    let p = owned(&txn, &actor, id).await?;
    let tenant = tenant_of_network(&txn, p.network_id).await?;
    let r = insert_route(&s, &txn, tenant, id, body.cidr).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "route.create",
        format!("peer_route/{}", r.id),
        json!({ "peer_id": id, "cidr": body.cidr.to_string() }),
    )
    .await?;
    txn.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(Route {
            id: r.id,
            cidr: from_db(r.cidr)?,
        }),
    ))
}

#[utoipa::path(delete, path = "/routes/{id}", responses((status = 204)))]
pub async fn remove_route(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let txn = begin(&s.db).await?;
    let peer_id = one_i64(
        &txn,
        "SELECT peer_id AS v FROM peer_route WHERE id = $1",
        id,
    )
    .await?;
    owned(&txn, &actor, peer_id).await?;
    peer_route::Entity::delete_by_id(id).exec(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "route.delete",
        format!("peer_route/{id}"),
        json!({ "peer_id": peer_id }),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
