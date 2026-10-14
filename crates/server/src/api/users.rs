//! Users. A tenant admin manages their tenant's plain users; a global admin anyone,
//! and alone gives or takes an admin role.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use std::collections::HashMap;

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, Statement,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use wgate_db::entity::app_user;

use super::begin;
use crate::audit;
use crate::auth::{Actor, account, identity, session};
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
    /// Whether it has a password (then an invite is refused: send a reset link).
    pub has_password: bool,
    /// Whether TOTP is on.
    pub totp_enabled: bool,
    /// In an update's answer only, when a promotion took identities at tenant
    /// providers away: whether that left the account without a way in (send an
    /// invite link).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stranded: Option<bool>,
}

impl User {
    fn new(u: app_user::Model, (has_password, totp_enabled): (bool, bool)) -> Self {
        Self {
            id: u.id,
            tenant_id: u.tenant_id,
            email: u.email,
            role: u.role,
            disabled: u.disabled_at.is_some(),
            has_password,
            totp_enabled,
            stranded: None,
        }
    }
}

/// (has a password, TOTP on) of the accounts `ids` (columns outside the entity).
async fn login_flags<C: ConnectionTrait>(
    db: &C,
    ids: Vec<i64>,
) -> Result<HashMap<i64, (bool, bool)>, ApiError> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id, password_hash IS NOT NULL AS p, totp_enabled_at IS NOT NULL AS t
             FROM app_user WHERE id = ANY($1::bigint[])",
            [ids.into()],
        ))
        .await?;
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get("", "id")?,
                (r.try_get("", "p")?, r.try_get("", "t")?),
            ))
        })
        .collect()
}

/// `users` as the API shows them.
async fn shown<C: ConnectionTrait>(
    db: &C,
    users: Vec<app_user::Model>,
) -> Result<Vec<User>, ApiError> {
    let flags = login_flags(db, users.iter().map(|u| u.id).collect()).await?;
    Ok(users
        .into_iter()
        .map(|u| {
            let f = flags.get(&u.id).copied().unwrap_or_default();
            User::new(u, f)
        })
        .collect())
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
pub(super) fn may_manage(actor: &Actor, tenant: Option<i64>) -> Result<(), ApiError> {
    match tenant {
        Some(t) => actor.tenant(t),
        None => actor.global(),
    }
}

/// Who may create, change or delete an account of `tenant` with `role` (as it is, and
/// as it becomes): an admin role is a global admin's alone, so a tenant admin can
/// neither make an admin nor turn one into a user it then reaches (links, resets).
fn may_change(actor: &Actor, tenant: Option<i64>, role: &str) -> Result<(), ApiError> {
    if role == "user" {
        may_manage(actor, tenant)
    } else {
        actor.global()
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
    Ok(Json(shown(&s.db, q.all(&s.db).await?).await?))
}

#[utoipa::path(post, path = "/users", operation_id = "create_user", request_body = UserCreate, responses((status = 201, body = User)))]
pub async fn create(
    State(s): State<AppState>,
    actor: Actor,
    Json(body): Json<UserCreate>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    may_change(&actor, body.tenant_id, &body.role)?;
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
    // New: no password, no TOTP.
    Ok((StatusCode::CREATED, Json(User::new(u, (false, false)))))
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
        .lock_exclusive()
        .one(&txn)
        .await?
        .ok_or(ApiError::NotFound)?;
    may_change(&actor, u.tenant_id, &u.role)?;
    let tenant = u.tenant_id;
    // To or from an admin role: its sessions and unused links end, so neither a link
    // made for a user nor a session from before carries over (and a new admin's next
    // password login sets TOTP up).
    let changed = body.role.as_deref().is_some_and(|r| r != u.role);
    let mut m = u.into_active_model();
    if let Some(role) = &body.role {
        may_change(&actor, tenant, role)?;
        check_role(role, tenant)?;
        m.role = Set(role.clone());
    }
    if let Some(disabled) = body.disabled {
        m.disabled_at = Set(disabled.then(|| chrono::Utc::now().fixed_offset()));
    }
    let u = m.update(&txn).await?;
    let ended = if changed {
        account::void_links(&txn, id).await?;
        session::end_others(&txn, id, None).await?
    } else {
        0
    };
    // A tenant admin binds the tenant's plain users to its providers (pre-link, email):
    // none of that may carry over to an admin account, which its owner links again.
    let unlinked = if changed && u.role != "user" {
        identity::unlink_tenant_providers(&txn, id).await?
    } else {
        0
    };
    // Said, not refused: the global admin promoting it sends an invite link next.
    let stranded = unlinked > 0 && identity::no_way_in(&txn, id).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "user.update",
        format!("app_user/{id}"),
        json!({ "role": body.role, "disabled": body.disabled, "ended_sessions": ended,
                "identities_removed": unlinked, "stranded": stranded }),
    )
    .await?;
    let mut u = shown(&txn, vec![u])
        .await?
        .pop()
        .ok_or(ApiError::NotFound)?;
    u.stranded = (unlinked > 0).then_some(stranded);
    txn.commit().await?;
    Ok(Json(u))
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
    let u = app_user::Entity::find_by_id(id)
        .lock_exclusive()
        .one(&txn)
        .await?
        .ok_or(ApiError::NotFound)?;
    may_change(&actor, u.tenant_id, &u.role)?;
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
