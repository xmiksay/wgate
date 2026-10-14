//! Identities linked to accounts: the owner's from `/me` (linked by a round trip
//! through the provider, never by email), and an admin's pre-link and unlink within
//! the reach of invite and reset links (see `credentials`). Unlinking never takes an
//! account's last way in.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use super::credentials::{reach, reach_read};
use super::me::target;
use super::{begin, tenant_of_user};
use crate::audit;
use crate::auth::oidc::{self, Link};
use crate::auth::{Account, Actor, identity, provider, session};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct Identity {
    pub id: i64,
    pub provider_id: i64,
    pub provider_name: String,
    /// The provider's subject identifier for the account.
    pub subject: String,
    /// RFC 3339, UTC.
    pub created_at: String,
}

async fn identities<C: ConnectionTrait>(db: &C, user: i64) -> Result<Vec<Identity>, ApiError> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT i.id, i.provider_id, p.name, i.subject,
                    to_char(i.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                        AS created_at
             FROM identity i JOIN oidc_provider p ON p.id = i.provider_id
             WHERE i.user_id = $1 ORDER BY i.id",
            [user.into()],
        ))
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Identity {
                id: r.try_get("", "id")?,
                provider_id: r.try_get("", "provider_id")?,
                provider_name: r.try_get("", "name")?,
                subject: r.try_get("", "subject")?,
                created_at: r.try_get("", "created_at")?,
            })
        })
        .collect()
}

#[utoipa::path(get, path = "/me/identities", operation_id = "my_identities", responses((status = 200, body = [Identity])))]
pub async fn mine(
    State(s): State<AppState>,
    Account(actor): Account,
) -> Result<Json<Vec<Identity>>, ApiError> {
    Ok(Json(identities(&s.db, actor.user_id).await?))
}

#[derive(Serialize, ToSchema)]
pub struct LinkableProvider {
    pub id: i64,
    pub name: String,
    /// A global provider (else the account's tenant's own).
    pub global: bool,
    /// Whether the account has an identity there already (then unlink it first).
    pub linked: bool,
}

/// The enabled providers the signed-in account may link, any role: the global ones
/// and its tenant's.
#[utoipa::path(get, path = "/me/providers", operation_id = "my_providers", responses((status = 200, body = [LinkableProvider])))]
pub async fn linkable(
    State(s): State<AppState>,
    Account(actor): Account,
) -> Result<Json<Vec<LinkableProvider>>, ApiError> {
    let rows =
        s.db.query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT p.id, p.name, p.tenant_id IS NULL AS global,
                    EXISTS (SELECT FROM identity i
                            WHERE i.provider_id = p.id AND i.user_id = $1) AS linked
             FROM oidc_provider p
             WHERE p.disabled_at IS NULL AND (p.tenant_id IS NULL OR p.tenant_id = $2)
             ORDER BY p.tenant_id NULLS FIRST, lower(p.name)",
            [actor.user_id.into(), actor.tenant_id.into()],
        ))
        .await?;
    rows.iter()
        .map(|r| {
            Ok(LinkableProvider {
                id: r.try_get("", "id")?,
                name: r.try_get("", "name")?,
                global: r.try_get("", "global")?,
                linked: r.try_get("", "linked")?,
            })
        })
        .collect::<Result<_, ApiError>>()
        .map(Json)
}

#[derive(Serialize, ToSchema)]
pub struct LinkStart {
    /// Send the browser here (the provider's login); it comes back to `/me`, with
    /// `?linked=<provider id>` or `?error=` (`taken`: the identity is another
    /// account's; `exists`, `forbidden`, `expired`, `cancelled`, `unavailable`,
    /// `failed`). Only this browser, in this session, can finish it.
    pub url: String,
}

/// Starts linking an identity at provider `id` to the signed-in account: an
/// enabled provider that serves it (a tenant's provider only its own tenant's
/// accounts). 404 for no such (enabled) provider, 403 for one that does not serve the
/// account, 409 if the account has an identity there already, 503 `unavailable` when
/// the provider cannot be reached (the cause is in the server's log).
#[utoipa::path(
    post, path = "/me/identities/{id}/link", operation_id = "link_my_identity",
    params(("id" = i64, Path, description = "The provider")),
    responses(
        (status = 200, body = LinkStart, description = "The `wgate_login` cookie is set"),
        (status = 403, body = crate::error::ErrorBody),
        (status = 404, body = crate::error::ErrorBody),
        (status = 409, body = crate::error::ErrorBody),
        (status = 503, body = crate::error::ErrorBody),
    )
)]
pub async fn link(
    State(s): State<AppState>,
    Account(actor): Account,
    jar: CookieJar,
    Path(provider_id): Path<i64>,
) -> Result<(CookieJar, Json<LinkStart>), ApiError> {
    let p = provider::enabled(&s.db, provider_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !provider::serves(p.tenant_id, actor.tenant_id) {
        return Err(ApiError::Forbidden);
    }
    if identities(&s.db, actor.user_id)
        .await?
        .iter()
        .any(|i| i.provider_id == p.id)
    {
        return Err(identity::Taken::Here.error());
    }
    let token = jar
        .get(session::COOKIE)
        .map(|c| c.value().to_owned())
        .ok_or(ApiError::Unauthorized)?;
    let link = Link::new(actor.user_id, &token);
    let (cookie, url) = oidc::round_trip(&s, &p, Some(link)).await?;
    Ok((jar.add(cookie), Json(LinkStart { url: url.into() })))
}

/// Unlinks one of the account's identities, and ends its other sessions made through
/// that provider. 422 if it is the last way in (no password, no other identity at
/// an enabled provider).
#[utoipa::path(
    delete, path = "/me/identities/{id}", operation_id = "unlink_my_identity",
    responses(
        (status = 204),
        (status = 404, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn unlink_mine(
    State(s): State<AppState>,
    Account(actor): Account,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let user = actor.user_id;
    let txn = begin(&s.db).await?;
    let provider = identity::unlink(&txn, user, id).await?;
    let ended = identity::end_sessions(&txn, user, provider, Some(actor.session_id)).await?;
    audit::record(
        &txn,
        Some(user),
        "user.identity.unlink",
        target(user),
        json!({ "identity_id": id, "provider_id": provider, "via": "me",
                "ended_sessions": ended }),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// An account's identities, as far as invite and reset links reach (a tenant admin
/// their tenant's plain users, a global admin anyone; one's own: `/me`).
#[utoipa::path(get, path = "/users/{id}/identities", operation_id = "user_identities", responses((status = 200, body = [Identity])))]
pub async fn of_user(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Vec<Identity>>, ApiError> {
    reach_read(&s.db, &actor, id).await?;
    Ok(Json(identities(&s.db, id).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct IdentityCreate {
    pub provider_id: i64,
    /// The provider's subject identifier (`sub`) for the account's owner.
    pub subject: String,
}

/// Pre-links an identity: its next login through that provider is this account. As
/// far as invite and reset links reach (a tenant admin their tenant's plain users, a
/// global admin anyone, nobody their own account: 422). The provider must serve the
/// account (422 otherwise); 409 if the subject is another account's or the account
/// has an identity there already.
#[utoipa::path(
    post, path = "/users/{id}/identities", operation_id = "add_user_identity",
    request_body = IdentityCreate,
    responses(
        (status = 201, body = Identity),
        (status = 403, body = crate::error::ErrorBody),
        (status = 404, body = crate::error::ErrorBody),
        (status = 409, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn add(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<IdentityCreate>,
) -> Result<(StatusCode, Json<Identity>), ApiError> {
    let subject = body.subject.trim();
    if subject.is_empty() || subject.chars().count() > 255 {
        return Err(ApiError::invalid("a subject has 1 to 255 characters"));
    }
    let txn = begin(&s.db).await?;
    reach(&txn, &actor, id).await?;
    // One answer for whatever the actor may not use: none, disabled, another tenant's.
    let p = provider::enabled(&txn, body.provider_id)
        .await?
        .filter(|p| p.tenant_id.is_none_or(|t| actor.tenant(t).is_ok()))
        .ok_or_else(|| ApiError::invalid("no such provider"))?;
    if !provider::serves(p.tenant_id, tenant_of_user(&txn, id).await?) {
        return Err(ApiError::invalid(
            "a tenant's provider serves only that tenant's accounts",
        ));
    }
    let identity_id = identity::bind(&txn, id, p.id, subject)
        .await?
        .map_err(identity::Taken::error)?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "user.identity.link",
        target(id),
        json!({ "identity_id": identity_id, "provider_id": p.id, "subject": subject,
                "via": "admin" }),
    )
    .await?;
    let made = identities(&txn, id)
        .await?
        .into_iter()
        .find(|i| i.id == identity_id)
        .ok_or(ApiError::NotFound)?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(made)))
}

/// Unlinks an identity of an account in reach (as for a pre-link), and ends the
/// account's sessions made through that provider. 422 for the last way in.
#[utoipa::path(
    delete, path = "/users/{id}/identities/{identity_id}", operation_id = "remove_user_identity",
    responses(
        (status = 204),
        (status = 403, body = crate::error::ErrorBody),
        (status = 404, body = crate::error::ErrorBody),
        (status = 422, body = crate::error::ErrorBody),
    )
)]
pub async fn remove(
    State(s): State<AppState>,
    actor: Actor,
    Path((id, identity_id)): Path<(i64, i64)>,
) -> Result<StatusCode, ApiError> {
    let txn = begin(&s.db).await?;
    reach(&txn, &actor, id).await?;
    let provider = identity::unlink(&txn, id, identity_id).await?;
    let ended = identity::end_sessions(&txn, id, provider, None).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "user.identity.unlink",
        target(id),
        json!({ "identity_id": identity_id, "provider_id": provider, "via": "admin",
                "ended_sessions": ended }),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
