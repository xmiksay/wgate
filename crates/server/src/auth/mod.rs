//! Who is asking: the session's user, and what their role lets them touch. Global
//! admins may do anything; a tenant admin only within their own tenant. Any account
//! may sign in ([`Account`]: its session and profile); the API's resources are the
//! admins' ([`Actor`]). Both need a `full` session; [`AnyStage`] takes one whose
//! login is still going, for the few endpoints that finish it.

pub mod account;
pub mod challenge;
pub mod factor;
pub mod identity;
pub mod limit;
pub mod links;
pub mod local;
pub mod logout;
pub mod oidc;
mod oidc_done;
pub mod outbound;
pub mod password;
pub mod provider;
pub mod session;
pub mod totp;

use axum::extract::FromRequestParts;
use axum::http::Method;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use serde::Serialize;
use subtle::ConstantTimeEq;
use utoipa::ToSchema;

use crate::error::ApiError;
use crate::state::AppState;
use session::Stage;

/// The CSRF token comes back in this header on every write.
pub const CSRF_HEADER: &str = "x-csrf-token";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    GlobalAdmin,
    TenantAdmin,
    User,
}

impl Role {
    pub fn parse(role: &str) -> Option<Self> {
        match role {
            "global_admin" => Some(Self::GlobalAdmin),
            "tenant_admin" => Some(Self::TenantAdmin),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

/// An admin's session: the extractor refuses a plain user (403), so every check
/// below speaks of admins only.
#[derive(Clone, Debug)]
pub struct Actor {
    pub session_id: i64,
    pub user_id: i64,
    pub role: Role,
    pub tenant_id: Option<i64>,
    pub email: String,
    pub csrf: String,
    /// How far the login got, as the API treats it (see [`session::lookup`]).
    pub stage: Stage,
    /// As the row says: `enrol` only for a password login of the last 30 minutes.
    pub row_stage: Stage,
    /// How the session was made (`password`, `password_totp`, `oidc`).
    pub method: String,
}

impl Actor {
    pub fn is_global(&self) -> bool {
        self.role == Role::GlobalAdmin
    }

    pub fn global(&self) -> Result<(), ApiError> {
        if self.is_global() {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    /// May manage what belongs to `tenant_id`.
    pub fn tenant(&self, tenant_id: i64) -> Result<(), ApiError> {
        if self.is_global() || self.tenant_id == Some(tenant_id) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    /// The tenant a listing is limited to: none for a global admin.
    pub fn scope(&self) -> Option<i64> {
        if self.is_global() {
            None
        } else {
            self.tenant_id
        }
    }
}

/// A session in any stage, its CSRF token checked on writes: only for what a login
/// in progress may do (see the handlers for which stages each takes).
#[derive(Clone, Debug)]
pub struct AnyStage(pub Actor);

impl FromRequestParts<AppState> for AnyStage {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(session::COOKIE)
            .map(|c| c.value().to_owned())
            .ok_or(ApiError::Unauthorized)?;
        let actor = session::lookup(&state.db, &token)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        let safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
        if !safe {
            let sent = parts
                .headers
                .get(CSRF_HEADER)
                .map(|v| v.as_bytes())
                .unwrap_or_default();
            if !bool::from(sent.ct_eq(actor.csrf.as_bytes())) {
                return Err(ApiError::Forbidden);
            }
        }
        Ok(Self(actor))
    }
}

/// Anyone signed in (a `full` session), whatever their role: their own session and
/// profile. An admin still to set up TOTP gets 403 `totp_required`; a login waiting
/// for its code is not signed in yet (401).
#[derive(Clone, Debug)]
pub struct Account(pub Actor);

impl FromRequestParts<AppState> for Account {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let AnyStage(actor) = AnyStage::from_request_parts(parts, state).await?;
        match actor.stage {
            Stage::Full => Ok(Self(actor)),
            Stage::Enrol => Err(ApiError::TotpRequired),
            Stage::Totp => Err(ApiError::Unauthorized),
        }
    }
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Account(actor) = Account::from_request_parts(parts, state).await?;
        if actor.role == Role::User {
            return Err(ApiError::Forbidden);
        }
        Ok(actor)
    }
}
