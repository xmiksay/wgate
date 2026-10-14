//! Peers: a device's membership in a network, with its own key and address. A server key is shown once, and every config download of a
//! server-key peer rotates it; a pasted key stays the user's.

use std::net::Ipv4Addr;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use ipnet::Ipv4Net;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, Statement,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use wgate_core::is_wg_key;
use wgate_db::entity::{peer, peer_route};

use super::clientconf::{self, Rendered};
use super::routes::{Route, insert_route};
use super::{begin, from_db, one_i64, tenant_of_network, tenant_of_user, to_db};
use crate::audit;
use crate::auth::Actor;
use crate::error::ApiError;
use crate::state::AppState;
use crate::wgkey;

#[derive(Serialize, ToSchema)]
pub struct Peer {
    pub id: i64,
    pub device_id: i64,
    pub network_id: i64,
    #[schema(value_type = String)]
    pub ip: Ipv4Addr,
    pub public_key: String,
    /// `server` (the server made the key) or `pasted`.
    pub key_source: String,
    pub revoked: bool,
    /// The LANs it routes (active routes only).
    pub routes: Vec<Route>,
}

#[derive(Deserialize, ToSchema)]
pub struct PeerCreate {
    pub device_id: i64,
    pub network_id: i64,
    #[schema(value_type = String)]
    pub ip: Ipv4Addr,
    /// The device's own public key; omitted, the server makes the pair.
    pub public_key: Option<String>,
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub routes: Vec<Ipv4Net>,
}

#[derive(Serialize, ToSchema)]
pub struct PeerCreated {
    pub peer: Peer,
    /// With the private key: the only time a server key is shown.
    pub config: Option<Rendered>,
    pub warnings: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ConfigOut {
    pub config: Option<Rendered>,
    pub warnings: Vec<String>,
}

#[derive(Deserialize, IntoParams)]
pub struct PeerFilter {
    pub network_id: Option<i64>,
    pub device_id: Option<i64>,
}

async fn peer_out<C: ConnectionTrait>(db: &C, p: peer::Model) -> Result<Peer, ApiError> {
    let routes = peer_route::Entity::find()
        .filter(peer_route::Column::PeerId.eq(p.id))
        .filter(peer_route::Column::Active.eq(true))
        .order_by_asc(peer_route::Column::Id)
        .all(db)
        .await?;
    let ip = from_db(p.ip)?.addr();
    Ok(Peer {
        id: p.id,
        device_id: p.device_id,
        network_id: p.network_id,
        ip,
        public_key: p.public_key,
        key_source: p.key_source,
        revoked: p.revoked_at.is_some(),
        routes: routes
            .into_iter()
            .map(|r| {
                Ok(Route {
                    id: r.id,
                    cidr: from_db(r.cidr)?,
                })
            })
            .collect::<Result<_, ApiError>>()?,
    })
}

/// The peer, if the actor manages both its network's tenant and its device (a global
/// admin's device only a global admin does).
pub(super) async fn owned<C: ConnectionTrait>(
    db: &C,
    actor: &Actor,
    id: i64,
) -> Result<peer::Model, ApiError> {
    let p = peer::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ApiError::NotFound)?;
    actor.tenant(tenant_of_network(db, p.network_id).await?)?;
    device_managed(db, actor, p.device_id).await?;
    Ok(p)
}

async fn device_managed<C: ConnectionTrait>(
    db: &C,
    actor: &Actor,
    device: i64,
) -> Result<(), ApiError> {
    let user = one_i64(db, "SELECT user_id AS v FROM device WHERE id = $1", device).await?;
    match tenant_of_user(db, user).await? {
        Some(t) => actor.tenant(t),
        None => actor.global(),
    }
}

#[utoipa::path(get, path = "/peers", params(PeerFilter), responses((status = 200, body = [Peer])))]
pub async fn list(
    State(s): State<AppState>,
    actor: Actor,
    Query(f): Query<PeerFilter>,
) -> Result<Json<Vec<Peer>>, ApiError> {
    let mut q = peer::Entity::find().order_by_asc(peer::Column::Id);
    if let Some(n) = f.network_id {
        actor.tenant(tenant_of_network(&s.db, n).await?)?;
        q = q.filter(peer::Column::NetworkId.eq(n));
        if !actor.is_global() {
            // Only what `owned` lets the actor open: devices of their own tenant.
            q = q.filter(Expr::cust_with_values(
                "device_id IN (SELECT d.id FROM device d JOIN app_user u ON u.id = d.user_id
                               WHERE u.tenant_id = $1)",
                [actor.tenant_id],
            ));
        }
    } else {
        actor.global()?;
    }
    if let Some(d) = f.device_id {
        q = q.filter(peer::Column::DeviceId.eq(d));
    }
    let mut out = vec![];
    for p in q.all(&s.db).await? {
        out.push(peer_out(&s.db, p).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(get, path = "/peers/{id}", responses((status = 200, body = Peer)))]
pub async fn get(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Peer>, ApiError> {
    let p = owned(&s.db, &actor, id).await?;
    Ok(Json(peer_out(&s.db, p).await?))
}

#[utoipa::path(post, path = "/peers", request_body = PeerCreate, responses((status = 201, body = PeerCreated)))]
pub async fn create(
    State(s): State<AppState>,
    actor: Actor,
    Json(body): Json<PeerCreate>,
) -> Result<(StatusCode, Json<PeerCreated>), ApiError> {
    let (pair, public_key, key_source) = match &body.public_key {
        Some(key) if !is_wg_key(key) => {
            return Err(ApiError::invalid("not a WireGuard public key"));
        }
        Some(key) => (None, key.clone(), "pasted"),
        None => {
            let pair = wgkey::generate();
            let public = pair.public.clone();
            (Some(pair), public, "server")
        }
    };
    let txn = begin(&s.db).await?;
    let tenant = tenant_of_network(&txn, body.network_id).await?;
    actor.tenant(tenant)?;
    device_managed(&txn, &actor, body.device_id).await?;
    let p = peer::ActiveModel {
        device_id: Set(body.device_id),
        network_id: Set(body.network_id),
        public_key: Set(public_key),
        key_source: Set(key_source.into()),
        ip: Set(to_db(Ipv4Net::from(body.ip))),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    for lan in &body.routes {
        insert_route(&s, &txn, tenant, p.id, *lan).await?;
    }
    audit::record(&txn, Some(actor.user_id), "peer.create", format!("peer/{}", p.id), json!({ "device_id": p.device_id, "network_id": p.network_id, "ip": body.ip.to_string(), "key_source": key_source, "routes": body.routes.iter().map(ToString::to_string).collect::<Vec<_>>() })).await?;
    txn.commit().await?;
    let mut warnings = vec![];
    let private = pair.as_ref().map(|p| p.private.as_str());
    // The peer exists now: a failed render is a warning, and a download makes a new
    // config (and key).
    let config = clientconf::render(&s, p.id, private, &mut warnings)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(peer = p.id, error = %e, "rendering the new peer's config");
            warnings.push("no config: rendering it failed; download it again".into());
            None
        });
    Ok((
        StatusCode::CREATED,
        Json(PeerCreated {
            peer: peer_out(&s.db, p).await?,
            config,
            warnings,
        }),
    ))
}

/// A server-key peer gets a new key pair (the previous config stops working at once);
/// a pasted-key peer's config comes without a private key. The rotation commits only
/// with a config to show for it: else the working key stays.
#[utoipa::path(post, path = "/peers/{id}/config", responses((status = 200, body = ConfigOut)))]
pub async fn config(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<ConfigOut>, ApiError> {
    let p = owned(&s.db, &actor, id).await?;
    if p.revoked_at.is_some() {
        return Err(ApiError::invalid("the peer is revoked"));
    }
    let pair = (p.key_source == "server").then(wgkey::generate);
    // Rendered with no transaction open (the render needs connections of its own),
    // from the committed state: the rights do not depend on the key.
    let mut warnings = vec![];
    let private = pair.as_ref().map(|p| p.private.as_str());
    let config = clientconf::render(&s, id, private, &mut warnings).await?;
    if let (Some(pair), Some(rendered)) = (&pair, &config) {
        let txn = begin(&s.db).await?;
        // Only over the key and the state this download started from: of two
        // concurrent downloads the later one learns that the earlier one's config is
        // the live one, and a change meanwhile (rights, the hub's key) is rendered anew.
        let swapped = txn
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE peer SET public_key = $1
                 WHERE id = $2 AND public_key = $3 AND revoked_at IS NULL
                   AND (SELECT revision FROM state_revision) = $4
                   AND EXISTS (SELECT FROM hub_key k
                               WHERE k.network_id = peer.network_id AND k.public_key = $5)",
                [
                    pair.public.clone().into(),
                    id.into(),
                    p.public_key.into(),
                    rendered.revision.into(),
                    rendered.hub_key.clone().into(),
                ],
            ))
            .await?
            .rows_affected();
        if swapped == 0 {
            return Err(ApiError::Conflict(
                "the peer or its rights changed meanwhile; download it again".into(),
            ));
        }
        audit::record(
            &txn,
            Some(actor.user_id),
            "peer.rotate",
            format!("peer/{id}"),
            json!({ "public_key": pair.public }),
        )
        .await?;
        txn.commit().await?;
    }
    Ok(Json(ConfigOut { config, warnings }))
}

/// Final: its address, key and LANs are free again.
#[utoipa::path(post, path = "/peers/{id}/revoke", responses((status = 200, body = Peer)))]
pub async fn revoke(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Peer>, ApiError> {
    let txn = begin(&s.db).await?;
    let p = owned(&txn, &actor, id).await?;
    let mut m = p.into_active_model();
    m.revoked_at = Set(Some(chrono::Utc::now().fixed_offset()));
    let p = m.update(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "peer.revoke",
        format!("peer/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(Json(peer_out(&s.db, p).await?))
}

#[utoipa::path(delete, path = "/peers/{id}", responses((status = 204)))]
pub async fn remove(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let txn = begin(&s.db).await?;
    owned(&txn, &actor, id).await?;
    peer::Entity::delete_by_id(id).exec(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "peer.delete",
        format!("peer/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
