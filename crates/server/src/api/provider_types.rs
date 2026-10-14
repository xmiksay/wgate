//! What the provider API takes and answers, and who sees which of it.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use wgate_db::entity::oidc_provider;

use crate::auth::Actor;
use crate::auth::provider::Secret;
use crate::error::ApiError;

#[derive(Serialize, ToSchema)]
pub struct Provider {
    pub id: i64,
    /// `None` for a global provider.
    pub tenant_id: Option<i64>,
    pub name: String,
    pub disabled: bool,
    pub link_by_email: bool,
    /// Whether the caller manages it; a tenant admin sees a global provider's name
    /// only (the fields below are then `None`).
    pub managed: bool,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    /// How many accounts have linked an identity there.
    pub identities: Option<i64>,
    /// In an update's answer only: how many accounts it left without a way to log
    /// in (they need an invite link).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stranded: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct ProviderRemoved {
    /// How many accounts the delete left without a way to log in (they need an
    /// invite link).
    pub stranded: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct ProviderCreate {
    /// `None` makes a global provider (a global admin's call only).
    pub tenant_id: Option<i64>,
    /// On the login button; unique among the providers of the same login page.
    pub name: String,
    /// Exactly as the provider's discovery names itself (a trailing slash counts);
    /// `https`, or plain `http` to addresses in `oidc_allow_private` (checked when
    /// it is asked).
    pub issuer: String,
    pub client_id: String,
    /// Write-only.
    #[schema(value_type = String)]
    pub client_secret: Secret,
    /// A first login binds by verified email (global providers, global admins only).
    #[serde(default)]
    pub link_by_email: bool,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct ProviderUpdate {
    pub name: Option<String>,
    /// A new issuer is another provider's subjects: its identities go.
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    /// Write-only; left out, the stored one stays.
    #[schema(value_type = Option<String>)]
    pub client_secret: Option<Secret>,
    pub link_by_email: Option<bool>,
    /// Disabling ends the sessions made through it; nobody logs in or links there.
    pub disabled: Option<bool>,
}

/// Who manages a provider of `tenant` (`None`: global ones, global admins only).
pub(super) fn manage(actor: &Actor, tenant: Option<i64>) -> Result<(), ApiError> {
    match tenant {
        Some(t) => actor.tenant(t),
        None => actor.global(),
    }
}

/// `p` as `actor` may see it: in full if they manage it, by name if it is an
/// enabled global one, else not at all.
pub(super) fn shown(actor: &Actor, p: oidc_provider::Model, identities: i64) -> Option<Provider> {
    let managed = manage(actor, p.tenant_id).is_ok();
    if !managed && (p.tenant_id.is_some() || p.disabled_at.is_some()) {
        return None;
    }
    Some(Provider {
        id: p.id,
        tenant_id: p.tenant_id,
        name: p.name,
        disabled: p.disabled_at.is_some(),
        link_by_email: p.link_by_email,
        managed,
        issuer: managed.then_some(p.issuer),
        client_id: managed.then_some(p.client_id),
        identities: managed.then_some(identities),
        stranded: None,
    })
}

/// Who may change or delete `p`: those who manage it. Anyone else gets what they
/// would see of it: 403 for an enabled global one (they know it by name), 404 for
/// the rest (another tenant's is not even there for them).
pub(super) fn may_change(actor: &Actor, p: &oidc_provider::Model) -> Result<(), ApiError> {
    if manage(actor, p.tenant_id).is_ok() {
        Ok(())
    } else if p.tenant_id.is_none() && p.disabled_at.is_none() {
        Err(ApiError::Forbidden)
    } else {
        Err(ApiError::NotFound)
    }
}
