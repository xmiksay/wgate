//! Users and their devices. A tenant admin manages their tenant's (never a global
//! admin); a global admin manages anyone's.

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

use super::{begin, tenant_of_user};
use crate::audit;
use crate::auth::Actor;
use crate::error::{ApiError, unique_violation};
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct User {
    pub id: i64,
    /// `None` for a global admin.
    pub tenant_id: Option<i64>,
    pub email: String,
    /// `global_admin`, `tenant_admin` or `user`.
    pub role: String,
    pub disabled: bool,
}

impl From<app_user::Model> for User {
    fn from(u: app_user::Model) -> Self {
        Self {
            id: u.id,
            tenant_id: u.tenant_id,
            email: u.email,
            role: u.role,
            disabled: u.disabled_at.is_some(),
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct UserCreate {
    /// `None` makes a global admin (a global admin's call only).
    pub tenant_id: Option<i64>,
    pub email: String,
    pub role: String,
}

#[derive(Deserialize, ToSchema)]
pub struct UserUpdate {
    /// Within the tenant: `tenant_admin` or `user`.
    pub role: Option<String>,
    /// Disabling ends their sessions and takes their peers out at once (reversible).
    pub disabled: Option<bool>,
}

#[derive(Deserialize, IntoParams)]
pub struct UserFilter {
    pub tenant_id: Option<i64>,
}

/// Who may manage a user of `tenant` (`None` = global admins: global admins only).
fn may_manage(actor: &Actor, tenant: Option<i64>) -> Result<(), ApiError> {
    match tenant {
        Some(t) => actor.tenant(t),
        None => actor.global(),
    }
}

fn check_role(role: &str, tenant: Option<i64>) -> Result<(), ApiError> {
    match (role, tenant) {
        ("global_admin", None) | ("tenant_admin" | "user", Some(_)) => Ok(()),
        ("global_admin", Some(_)) => Err(ApiError::invalid("a global admin belongs to no tenant")),
        _ => Err(ApiError::invalid(format!("role {role} needs a tenant"))),
    }
}

#[utoipa::path(get, path = "/users", operation_id = "list_users", params(UserFilter), responses((status = 200, body = [User])))]
pub async fn list(
    State(s): State<AppState>,
    actor: Actor,
    Query(f): Query<UserFilter>,
) -> Result<Json<Vec<User>>, ApiError> {
    let mut q = app_user::Entity::find().order_by_asc(app_user::Column::Id);
    if let Some(own) = actor.scope() {
        q = q.filter(app_user::Column::TenantId.eq(own));
    }
    if let Some(t) = f.tenant_id {
        q = q.filter(app_user::Column::TenantId.eq(t));
    }
    Ok(Json(
        q.all(&s.db).await?.into_iter().map(User::from).collect(),
    ))
}

#[utoipa::path(post, path = "/users", operation_id = "create_user", request_body = UserCreate, responses((status = 201, body = User)))]
pub async fn create(
    State(s): State<AppState>,
    actor: Actor,
    Json(body): Json<UserCreate>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    may_manage(&actor, body.tenant_id)?;
    check_role(&body.role, body.tenant_id)?;
    let txn = begin(&s.db).await?;
    let u = app_user::ActiveModel {
        tenant_id: Set(body.tenant_id),
        email: Set(body.email.trim().to_owned()),
        role: Set(body.role),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| match unique_violation(&e).as_deref() {
        // One account per email across wgate, whichever tenant has it.
        Some("app_user_email") => {
            ApiError::Conflict("an account with this email already exists".into())
        }
        _ => e.into(),
    })?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "user.create",
        format!("app_user/{}", u.id),
        json!({ "tenant_id": u.tenant_id, "email": u.email, "role": u.role }),
    )
    .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(u.into())))
}

#[utoipa::path(patch, path = "/users/{id}", operation_id = "update_user", request_body = UserUpdate, responses((status = 200, body = User)))]
pub async fn update(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<UserUpdate>,
) -> Result<Json<User>, ApiError> {
    if id == actor.user_id && body.disabled == Some(true) {
        return Err(ApiError::invalid("you cannot disable yourself"));
    }
    let txn = begin(&s.db).await?;
    let u = app_user::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ApiError::NotFound)?;
    may_manage(&actor, u.tenant_id)?;
    let tenant = u.tenant_id;
    let mut m = u.into_active_model();
    if let Some(role) = &body.role {
        check_role(role, tenant)?;
        m.role = Set(role.clone());
    }
    if let Some(disabled) = body.disabled {
        m.disabled_at = Set(disabled.then(|| chrono::Utc::now().fixed_offset()));
    }
    let u = m.update(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "user.update",
        format!("app_user/{id}"),
        json!({ "role": body.role, "disabled": body.disabled }),
    )
    .await?;
    txn.commit().await?;
    Ok(Json(u.into()))
}

/// Takes the user's devices and peers along.
#[utoipa::path(delete, path = "/users/{id}", operation_id = "remove_user", responses((status = 204)))]
pub async fn remove(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    if id == actor.user_id {
        return Err(ApiError::invalid("you cannot delete yourself"));
    }
    let txn = begin(&s.db).await?;
    may_manage(&actor, tenant_of_user(&txn, id).await?)?;
    app_user::Entity::delete_by_id(id).exec(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "user.delete",
        format!("app_user/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

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
