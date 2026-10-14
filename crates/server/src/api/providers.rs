//! OIDC providers: a global admin manages all of them, a tenant admin their own
//! tenant's (and sees the enabled global ones by name: what their users can link).
//! The client secret is write-only: sealed on the way in, never shown, logged or
//! audited. `link_by_email` is a global admin's, and only for a global provider.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use sea_orm::sea_query::LockType;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DbBackend, EntityTrait, IntoActiveModel,
    QueryOrder, QuerySelect, Statement,
};
use serde_json::json;
use wgate_db::entity::oidc_provider;

use super::begin;
use super::provider_types::{
    Provider, ProviderCreate, ProviderRemoved, ProviderUpdate, manage, may_change, shown,
};
use crate::audit;
use crate::auth::provider::{check_client_id, check_issuer, check_name};
use crate::auth::{Actor, identity};
use crate::error::{ApiError, unique_violation};
use crate::state::AppState;

/// `link_by_email` may be on only for a global provider, and only a global admin
/// turns it on.
fn check_link_by_email(actor: &Actor, tenant: Option<i64>, on: bool) -> Result<(), ApiError> {
    if !on {
        return Ok(());
    }
    actor.global()?;
    match tenant {
        None => Ok(()),
        Some(_) => Err(ApiError::invalid(
            "link_by_email is for global providers: a tenant's binds its own users by email",
        )),
    }
}

async fn identity_count<C: ConnectionTrait>(db: &C, id: i64) -> Result<i64, ApiError> {
    super::one_i64(
        db,
        "SELECT count(*) AS v FROM identity WHERE provider_id = $1",
        id,
    )
    .await
}

fn taken(e: sea_orm::DbErr) -> ApiError {
    match unique_violation(&e).as_deref() {
        Some("oidc_provider_name") => {
            ApiError::Conflict("a provider of that name is on the same login page".into())
        }
        _ => e.into(),
    }
}

#[utoipa::path(get, path = "/providers", operation_id = "list_providers", responses((status = 200, body = [Provider])))]
pub async fn list(
    State(s): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<Provider>>, ApiError> {
    let rows = oidc_provider::Entity::find()
        .order_by_asc(oidc_provider::Column::Id)
        .all(&s.db)
        .await?;
    let counts: std::collections::HashMap<i64, i64> =
        s.db.query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT provider_id, count(*) AS n FROM identity GROUP BY provider_id",
        ))
        .await?
        .iter()
        .map(|r| Ok((r.try_get("", "provider_id")?, r.try_get("", "n")?)))
        .collect::<Result<_, ApiError>>()?;
    Ok(Json(
        rows.into_iter()
            .filter_map(|p| {
                let n = counts.get(&p.id).copied().unwrap_or_default();
                shown(&actor, p, n)
            })
            .collect(),
    ))
}

#[utoipa::path(get, path = "/providers/{id}", operation_id = "get_provider", responses((status = 200, body = Provider)))]
pub async fn get(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Provider>, ApiError> {
    let p = oidc_provider::Entity::find_by_id(id)
        .one(&s.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let n = identity_count(&s.db, id).await?;
    // Another tenant's is none of a tenant admin's business, not even that it exists.
    Ok(Json(shown(&actor, p, n).ok_or(ApiError::NotFound)?))
}

/// 409 for a name already on the same login page; 422 for a malformed issuer, an
/// empty field, or `link_by_email` on a tenant's provider.
#[utoipa::path(
    post, path = "/providers", operation_id = "create_provider", request_body = ProviderCreate,
    responses(
        (status = 201, body = Provider),
        (status = 403, body = crate::error::ErrorBody),
        (status = 409, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn create(
    State(s): State<AppState>,
    actor: Actor,
    Json(body): Json<ProviderCreate>,
) -> Result<(StatusCode, Json<Provider>), ApiError> {
    manage(&actor, body.tenant_id)?;
    check_link_by_email(&actor, body.tenant_id, body.link_by_email)?;
    let name = check_name(&body.name)?;
    check_issuer(&body.issuer)?;
    check_client_id(&body.client_id)?;
    body.client_secret.check()?;
    let txn = begin(&s.db).await?;
    // The id first: the sealed secret is bound to its row.
    let id: i64 = txn
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT nextval(pg_get_serial_sequence('oidc_provider', 'id')) AS v",
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no id"))?
        .try_get("", "v")?;
    let p = oidc_provider::ActiveModel {
        id: Set(id),
        tenant_id: Set(body.tenant_id),
        name: Set(name),
        issuer: Set(body.issuer),
        client_id: Set(body.client_id),
        client_secret: Set(body.client_secret.seal(&s.key, id)?),
        link_by_email: Set(body.link_by_email),
        disabled_at: Set(body.disabled.then(|| chrono::Utc::now().fixed_offset())),
    }
    .insert(&txn)
    .await
    .map_err(taken)?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "provider.create",
        format!("oidc_provider/{id}"),
        json!({ "tenant_id": p.tenant_id, "name": p.name, "issuer": p.issuer,
                "client_id": p.client_id, "link_by_email": p.link_by_email,
                "disabled": body.disabled }),
    )
    .await?;
    txn.commit().await?;
    let p = shown(&actor, p, 0).ok_or(ApiError::Forbidden)?;
    Ok((StatusCode::CREATED, Json(p)))
}

/// 403/409/422 as for a create. A new issuer drops the provider's identities (its
/// subjects were the old issuer's); that and disabling end the sessions made through
/// it, and answer with `stranded`: the accounts left without a way in. 409 when one
/// of those is an admin account, unless a global admin asks.
#[utoipa::path(
    patch, path = "/providers/{id}", operation_id = "update_provider",
    request_body = ProviderUpdate,
    responses(
        (status = 200, body = Provider),
        (status = 403, body = crate::error::ErrorBody),
        (status = 404, body = crate::error::ErrorBody),
        (status = 409, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn update(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<ProviderUpdate>,
) -> Result<Json<Provider>, ApiError> {
    let txn = begin(&s.db).await?;
    let p = oidc_provider::Entity::find_by_id(id)
        // Not FOR UPDATE: a login binding an identity takes KEY SHARE on this row
        // while it holds its account; strands() below then waits for that account.
        .lock(LockType::NoKeyUpdate)
        .one(&txn)
        .await?
        .ok_or(ApiError::NotFound)?;
    may_change(&actor, &p)?;
    if let Some(on) = body.link_by_email {
        check_link_by_email(&actor, p.tenant_id, on)?;
    }
    let new_issuer = body.issuer.as_ref().filter(|i| **i != p.issuer).cloned();
    let was_disabled = p.disabled_at.is_some();
    let disabling = body.disabled == Some(true) && !was_disabled;
    let stranded = if disabling || new_issuer.is_some() {
        Some(strands(&txn, &actor, id).await?)
    } else {
        None
    };
    let mut m = p.into_active_model();
    if let Some(name) = &body.name {
        m.name = Set(check_name(name)?);
    }
    if let Some(issuer) = &new_issuer {
        check_issuer(issuer)?;
        m.issuer = Set(issuer.clone());
    }
    if let Some(client_id) = &body.client_id {
        check_client_id(client_id)?;
        m.client_id = Set(client_id.clone());
    }
    if let Some(secret) = &body.client_secret {
        secret.check()?;
        m.client_secret = Set(secret.seal(&s.key, id)?);
    }
    if let Some(on) = body.link_by_email {
        m.link_by_email = Set(on);
    }
    if let Some(disabled) = body.disabled
        && disabled != was_disabled
    {
        m.disabled_at = Set(disabled.then(|| chrono::Utc::now().fixed_offset()));
    }
    let p = m.update(&txn).await.map_err(taken)?;
    let dropped = if new_issuer.is_some() {
        exec(&txn, "DELETE FROM identity WHERE provider_id = $1", id).await?
    } else {
        0
    };
    // Disabled, or another issuer's subjects from now on: its sessions end too.
    let ended = if disabling || new_issuer.is_some() {
        exec(&txn, "DELETE FROM session WHERE provider_id = $1", id).await?
    } else {
        0
    };
    audit::record(
        &txn,
        Some(actor.user_id),
        "provider.update",
        format!("oidc_provider/{id}"),
        json!({ "name": body.name, "issuer": new_issuer, "client_id": body.client_id,
                "client_secret_changed": body.client_secret.is_some(),
                "link_by_email": body.link_by_email, "disabled": body.disabled,
                "identities_removed": dropped, "ended_sessions": ended,
                "stranded": stranded }),
    )
    .await?;
    let n = identity_count(&txn, id).await?;
    txn.commit().await?;
    s.discovery.forget(id);
    let mut shown = shown(&actor, p, n).ok_or(ApiError::Forbidden)?;
    shown.stranded = stranded;
    Ok(Json(shown))
}

/// How many accounts a provider's going (disabled, deleted, or its identities
/// dropped) leaves without a way in. An admin account among them only a global
/// admin may strand (409 for anyone else): a tenant admin cannot lock a fellow
/// admin out this way, as they cannot reach them with a reset link.
async fn strands<C: ConnectionTrait>(db: &C, actor: &Actor, id: i64) -> Result<i64, ApiError> {
    let (n, admin) = identity::stranded(db, id).await?;
    if admin && !actor.is_global() {
        return Err(ApiError::Conflict(
            "an admin account would be left without a way to log in: a global admin may \
             do this"
                .into(),
        ));
    }
    Ok(n)
}

/// Takes its identities along (an account left without a way in needs an invite
/// link) and ends the sessions made through it; audited with how many. 409 when an
/// admin account would be left without a way in, unless a global admin asks.
#[utoipa::path(
    delete, path = "/providers/{id}", operation_id = "remove_provider",
    responses(
        (status = 200, body = ProviderRemoved),
        (status = 403, body = crate::error::ErrorBody),
        (status = 404, body = crate::error::ErrorBody),
        (status = 409, body = crate::error::ErrorBody),
    )
)]
pub async fn remove(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<ProviderRemoved>, ApiError> {
    let txn = begin(&s.db).await?;
    // As for an update: the DELETE at the end takes the row's full lock, briefly.
    let p = oidc_provider::Entity::find_by_id(id)
        .lock(LockType::NoKeyUpdate)
        .one(&txn)
        .await?
        .ok_or(ApiError::NotFound)?;
    may_change(&actor, &p)?;
    let stranded = strands(&txn, &actor, id).await?;
    let dropped = identity_count(&txn, id).await?;
    let ended = exec(&txn, "DELETE FROM session WHERE provider_id = $1", id).await?;
    oidc_provider::Entity::delete_by_id(id).exec(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "provider.delete",
        format!("oidc_provider/{id}"),
        json!({ "name": p.name, "identities_removed": dropped, "ended_sessions": ended,
                "stranded": stranded }),
    )
    .await?;
    txn.commit().await?;
    s.discovery.forget(id);
    Ok(Json(ProviderRemoved { stranded }))
}

async fn exec<C: ConnectionTrait>(db: &C, sql: &str, id: i64) -> Result<u64, ApiError> {
    Ok(db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            [id.into()],
        ))
        .await?
        .rows_affected())
}
