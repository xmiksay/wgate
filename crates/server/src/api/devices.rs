//! Devices: a user's laptops and phones, each holding its peers. Who may manage one
//! is who may manage its user ([`super::users`]).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use wgate_db::entity::{app_user, device};

use super::users::may_manage;
use super::{begin, tenant_of_user};
use crate::audit;
use crate::auth::Actor;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct Device {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct DeviceCreate {
    pub user_id: i64,
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct DeviceRename {
    pub name: String,
}

#[derive(Deserialize, IntoParams)]
pub struct DeviceFilter {
    pub user_id: Option<i64>,
}

impl From<device::Model> for Device {
    fn from(d: device::Model) -> Self {
        Self {
            id: d.id,
            user_id: d.user_id,
            name: d.name,
        }
    }
}

#[utoipa::path(get, path = "/devices", params(DeviceFilter), responses((status = 200, body = [Device])))]
pub async fn devices(
    State(s): State<AppState>,
    actor: Actor,
    Query(f): Query<DeviceFilter>,
) -> Result<Json<Vec<Device>>, ApiError> {
    let mut q = device::Entity::find().order_by_asc(device::Column::Id);
    if let Some(user) = f.user_id {
        may_manage(&actor, tenant_of_user(&s.db, user).await?)?;
        q = q.filter(device::Column::UserId.eq(user));
    } else if let Some(own) = actor.scope() {
        let users = app_user::Entity::find()
            .filter(app_user::Column::TenantId.eq(own))
            .all(&s.db)
            .await?;
        q = q.filter(device::Column::UserId.is_in(users.into_iter().map(|u| u.id)));
    }
    Ok(Json(
        q.all(&s.db).await?.into_iter().map(Device::from).collect(),
    ))
}

#[utoipa::path(post, path = "/devices", request_body = DeviceCreate, responses((status = 201, body = Device)))]
pub async fn add_device(
    State(s): State<AppState>,
    actor: Actor,
    Json(body): Json<DeviceCreate>,
) -> Result<(StatusCode, Json<Device>), ApiError> {
    let txn = begin(&s.db).await?;
    may_manage(&actor, tenant_of_user(&txn, body.user_id).await?)?;
    let d = device::ActiveModel {
        user_id: Set(body.user_id),
        name: Set(body.name),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "device.create",
        format!("device/{}", d.id),
        json!({ "user_id": d.user_id, "name": d.name }),
    )
    .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(d.into())))
}

async fn device_tenant<C: sea_orm::ConnectionTrait>(
    db: &C,
    id: i64,
) -> Result<Option<i64>, ApiError> {
    let d = device::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ApiError::NotFound)?;
    tenant_of_user(db, d.user_id).await
}

#[utoipa::path(patch, path = "/devices/{id}", request_body = DeviceRename, responses((status = 200, body = Device)))]
pub async fn rename_device(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<DeviceRename>,
) -> Result<Json<Device>, ApiError> {
    let txn = begin(&s.db).await?;
    may_manage(&actor, device_tenant(&txn, id).await?)?;
    let mut m = device::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ApiError::NotFound)?
        .into_active_model();
    m.name = Set(body.name.clone());
    let d = m.update(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "device.update",
        format!("device/{id}"),
        json!({ "name": body.name }),
    )
    .await?;
    txn.commit().await?;
    Ok(Json(d.into()))
}

/// Takes the device's peers along.
#[utoipa::path(delete, path = "/devices/{id}", responses((status = 204)))]
pub async fn remove_device(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let txn = begin(&s.db).await?;
    may_manage(&actor, device_tenant(&txn, id).await?)?;
    device::Entity::delete_by_id(id).exec(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "device.delete",
        format!("device/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
