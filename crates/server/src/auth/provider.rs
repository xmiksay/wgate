//! OpenID Connect providers as the database keeps them: global ones (`tenant_id`
//! NULL) and a tenant's own. The client secret is sealed with its row as associated
//! data and only opened to talk to the provider. Discovered metadata is cached per
//! provider and dropped as soon as the row it came from changes.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{
    ClientId, ClientSecret, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, RedirectUrl,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Deserializer};
use url::Url;
use wgate_db::entity::oidc_provider;
use zeroize::Zeroizing;

use super::Role;
use crate::error::ApiError;
use crate::seal::{Place, SecretKey};
use crate::state::AppState;

pub use oidc_provider::Model as Provider;

/// How long discovered metadata (endpoints, signing keys) is reused.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
pub const MAX_NAME_CHARS: usize = 64;
const MAX_CLIENT_ID_CHARS: usize = 256;
const MAX_SECRET_CHARS: usize = 1024;

pub type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub fn place(id: i64) -> Place<'static> {
    Place {
        table: "oidc_provider",
        column: "client_secret",
        id,
    }
}

/// Provider `id` if it exists and is not disabled.
pub async fn enabled<C: ConnectionTrait>(db: &C, id: i64) -> Result<Option<Provider>, ApiError> {
    Ok(oidc_provider::Entity::find_by_id(id)
        .filter(oidc_provider::Column::DisabledAt.is_null())
        .one(db)
        .await?)
}

/// A client secret as an admin sends it: write-only, zeroized on drop, redacted in
/// `Debug`, never serialized.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn check(&self) -> Result<(), ApiError> {
        bounded("client_secret", &self.0, MAX_SECRET_CHARS)
    }

    pub fn seal(&self, key: &SecretKey, id: i64) -> Result<Vec<u8>, ApiError> {
        Ok(key.seal(place(id), self.0.as_bytes())?)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}

fn bounded(what: &str, s: &str, max: usize) -> Result<(), ApiError> {
    let n = s.chars().count();
    if n == 0 || n > max || s.chars().any(char::is_control) {
        return Err(ApiError::invalid(format!(
            "{what} has 1 to {max} characters, none of them control characters"
        )));
    }
    Ok(())
}

/// What the login button says: trimmed, 1 to 64 characters.
pub fn check_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    bounded("a name", name, MAX_NAME_CHARS)?;
    Ok(name.to_owned())
}

pub fn check_client_id(id: &str) -> Result<(), ApiError> {
    bounded("client_id", id, MAX_CLIENT_ID_CHARS)
}

/// An `https` or `http` URL with a host and without query, fragment or credentials
/// (OpenID Connect Discovery). Whether it may be asked is the request's business
/// (`outbound`: public addresses over https, plain http only into
/// `oidc_allow_private`), decided on where it resolves to then. Kept verbatim:
/// discovery compares it byte for byte.
pub fn check_issuer(issuer: &str) -> Result<(), ApiError> {
    let bad = |why: &str| Err(ApiError::invalid(format!("issuer: {why}")));
    let Ok(url) = Url::parse(issuer) else {
        return bad("not a URL");
    };
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return bad("no query, fragment or credentials");
    }
    if url.host().is_none() {
        return bad("no host");
    }
    match url.scheme() {
        "https" | "http" => Ok(()),
        _ => bad("an https (or http) URL"),
    }
}

/// Whether a login through a provider of `provider_tenant` may sign in (or a link
/// bind) an account of `account_tenant`: a tenant's provider only its own accounts
/// (never a global admin's), a global one anyone's.
pub fn serves(provider_tenant: Option<i64>, account_tenant: Option<i64>) -> bool {
    provider_tenant.is_none_or(|t| account_tenant == Some(t))
}

/// Whether a first login with a verified email may bind to the account of that
/// email: a tenant's provider for its plain users (an admin account is a global
/// admin's to reach, never its tenant's provider's), a global one with
/// `link_by_email` for anyone but a global admin.
pub fn binds_by_email(p: &Provider, account_tenant: Option<i64>, role: Role) -> bool {
    match p.tenant_id {
        Some(t) => account_tenant == Some(t) && role == Role::User,
        None => p.link_by_email && role != Role::GlobalAdmin,
    }
}

/// What a cached client was discovered from: a change to any of it is another client.
type Origin = (String, String, Vec<u8>);

fn origin(p: &Provider) -> Origin {
    (
        p.issuer.clone(),
        p.client_id.clone(),
        p.client_secret.clone(),
    )
}

/// How long a failed discovery is not retried: a provider that is down (or refused)
/// is not asked again for every hit on `/auth/oidc/{id}`.
const FAILED_TTL: Duration = Duration::from_secs(30);

enum Cached {
    Found(Instant, Origin, Box<Client>),
    Failed(Instant, Origin),
}

type Slot = Arc<tokio::sync::Mutex<Option<Cached>>>;

/// Discovered clients by provider id, each reused for [`DISCOVERY_TTL`] while its
/// row stays as it was: neither a login nor a stream of unauthenticated
/// `/auth/oidc/{id}` hits rediscovers it each time. One lock per provider, so a slow
/// provider holds up only its own logins.
#[derive(Default)]
pub struct Discovery(std::sync::Mutex<HashMap<i64, Slot>>);

impl Discovery {
    fn slot(&self, id: i64) -> Slot {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        map.entry(id).or_default().clone()
    }

    pub async fn client(&self, state: &AppState, p: &Provider) -> Result<Client, ApiError> {
        let slot = self.slot(p.id);
        let mut cached = slot.lock().await;
        let from = origin(p);
        match cached.as_ref() {
            Some(Cached::Found(at, was, client))
                if at.elapsed() < DISCOVERY_TTL && *was == from =>
            {
                return Ok(Client::clone(client));
            }
            Some(Cached::Failed(at, was)) if at.elapsed() < FAILED_TTL && *was == from => {
                tracing::debug!(
                    provider = p.id,
                    "OIDC discovery failed lately: not retried yet"
                );
                return Err(ApiError::ProviderUnavailable);
            }
            _ => {}
        }
        match discover(state, p).await {
            Ok(client) => {
                *cached = Some(Cached::Found(
                    Instant::now(),
                    from,
                    Box::new(client.clone()),
                ));
                Ok(client)
            }
            Err(Failure::Provider(e)) => {
                tracing::warn!(provider = p.id, error = e, "OIDC provider unavailable");
                *cached = Some(Cached::Failed(Instant::now(), from));
                Err(ApiError::ProviderUnavailable)
            }
            // Ours (the issuer, public_url, the sealed secret): an operator's to fix.
            Err(Failure::Ours(e)) => {
                tracing::error!(provider = p.id, error = e.chain(), "OIDC provider unusable");
                *cached = Some(Cached::Failed(Instant::now(), from));
                Err(ApiError::ProviderUnavailable)
            }
        }
    }

    /// The next login through `id` rediscovers (it changed, went, or may have
    /// rotated its keys).
    pub fn forget(&self, id: i64) {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        map.remove(&id);
    }
}

/// Why discovery gave no client.
enum Failure {
    /// The provider did not answer as it should, or the outbound checks refused it.
    Provider(String),
    /// Ours: what is stored or configured does not work.
    Ours(ApiError),
}

impl<E: Into<ApiError>> From<E> for Failure {
    fn from(e: E) -> Self {
        Self::Ours(e.into())
    }
}

async fn discover(state: &AppState, p: &Provider) -> Result<Client, Failure> {
    let issuer = IssuerUrl::new(p.issuer.clone()).map_err(anyhow::Error::from)?;
    let metadata = CoreProviderMetadata::discover_async(issuer, &state.http)
        .await
        .map_err(|e| Failure::Provider(format!("discovery: {}", super::outbound::chain(&e))))?;
    let redirect = state
        .config
        .public_url
        .join("auth/callback")
        .map_err(anyhow::Error::from)?;
    let secret = state.key.open(place(p.id), &p.client_secret)?;
    let secret = String::from_utf8(secret.to_vec())
        .map_err(|_| anyhow::anyhow!("provider {}: client secret not UTF-8", p.id))?;
    Ok(CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(p.client_id.clone()),
        Some(ClientSecret::new(secret)),
    )
    .set_redirect_uri(RedirectUrl::from_url(redirect)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(tenant: Option<i64>, link_by_email: bool) -> Provider {
        Provider {
            id: 1,
            tenant_id: tenant,
            name: "p".into(),
            issuer: "https://idp.test".into(),
            client_id: "c".into(),
            client_secret: vec![],
            link_by_email,
            disabled_at: None,
        }
    }

    #[test]
    fn issuers_are_http_or_https_urls() {
        for ok in [
            "https://accounts.google.com",
            "https://kc.example.org/realms/acme",
            "https://kc.example.org/realms/acme/",
            "http://127.0.0.1:8080",
            "http://localhost:9/",
            "http://[::1]:9",
            "http://kc.internal",
            "http://10.0.0.1",
        ] {
            assert!(check_issuer(ok).is_ok(), "{ok}");
        }
        for bad in [
            "accounts.google.com",
            "ftp://x.test",
            "file:///etc/passwd",
            "https://x.test/?a=1",
            "https://x.test/#f",
            "https://u:p@x.test",
            "",
        ] {
            assert!(check_issuer(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn names_ids_and_secrets_are_bounded() {
        assert_eq!(check_name("  Google ").unwrap(), "Google");
        assert!(check_name("   ").is_err());
        assert!(check_name(&"x".repeat(65)).is_err());
        assert!(check_name(&"ž".repeat(64)).is_ok());
        assert!(check_name("a\nb").is_err());
        assert!(check_client_id("").is_err());
        assert!(check_client_id("wgate").is_ok());
        assert!(Secret(Zeroizing::new(String::new())).check().is_err());
        let s = Secret(Zeroizing::new("hunter2".into()));
        assert!(s.check().is_ok());
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn a_tenant_provider_serves_its_tenant_only() {
        assert!(serves(None, None));
        assert!(serves(None, Some(1)));
        assert!(serves(Some(1), Some(1)));
        assert!(!serves(Some(1), Some(2)));
        assert!(!serves(Some(1), None), "never a global admin");
    }

    #[test]
    fn email_binds_only_where_the_rules_say() {
        let (tenant, global, flagged) = (
            provider(Some(1), false),
            provider(None, false),
            provider(None, true),
        );
        assert!(binds_by_email(&tenant, Some(1), Role::User));
        assert!(!binds_by_email(&tenant, Some(1), Role::TenantAdmin));
        assert!(!binds_by_email(&tenant, Some(2), Role::User));
        assert!(!binds_by_email(&tenant, None, Role::GlobalAdmin));
        assert!(!binds_by_email(&global, Some(1), Role::User));
        assert!(binds_by_email(&flagged, Some(1), Role::User));
        assert!(binds_by_email(&flagged, Some(1), Role::TenantAdmin));
        assert!(!binds_by_email(&flagged, None, Role::GlobalAdmin));
    }
}
