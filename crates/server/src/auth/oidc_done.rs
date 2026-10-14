//! What a verified provider answer does: a login signs in the account it is (see
//! [`identity::resolve`]), a link binds it to the session that started the round
//! trip. Both audited, with the provider and subject, never a token.

use std::net::IpAddr;

use serde_json::json;

use super::identity::{self, Taken};
use super::oidc::{Done, Link, Why};
use super::provider::{self, Provider};
use super::session::{self, Method, Stage};
use crate::audit;
use crate::state::AppState;

/// A provider login: a `full` session (the provider does its own second factor).
pub async fn login(
    state: &AppState,
    ip: IpAddr,
    p: &Provider,
    subject: &str,
    email: Option<&str>,
) -> Result<Done, Why> {
    let mut detail = json!({ "provider_id": p.id, "subject": subject, "ip": ip.to_string() });
    let resolved = identity::resolve(&state.db, p, subject, email)
        .await
        .map_err(Why::failed)?;
    let (id, by_email) = match resolved {
        Ok(found) => found,
        Err(refused) => {
            tracing::warn!(
                provider = p.id,
                reason = refused.as_str(),
                "OIDC login refused"
            );
            detail["reason"] = json!(refused.as_str());
            let target = format!("oidc_provider/{}", p.id);
            audit::record(&state.db, None, "login.oidc.failed", target, detail)
                .await
                .map_err(Why::failed)?;
            return Err(Why::Forbidden);
        }
    };
    let token = session::create(&state.db, id, Method::Oidc(p.id), Stage::Full)
        .await
        .map_err(Why::failed)?;
    if by_email {
        detail["bound_by"] = json!("email");
    }
    audit::record(
        &state.db,
        Some(id),
        "login.oidc.ok",
        format!("app_user/{id}"),
        detail,
    )
    .await
    .map_err(Why::failed)?;
    Ok(Done::Login(token))
}

/// A link: only into the session that started it, still signed in (`full`) as the
/// same account, and only at a provider that serves the account. No email matching:
/// the subject is the account's because its owner just logged in as it.
pub async fn link(
    state: &AppState,
    ip: IpAddr,
    p: &Provider,
    link: Link,
    token: Option<String>,
    subject: &str,
) -> Result<Done, Why> {
    let token = token.filter(|t| link.of(t)).ok_or(Why::Expired)?;
    let actor = session::lookup(&state.db, &token)
        .await
        .map_err(Why::failed)?
        .ok_or(Why::Expired)?;
    if actor.user_id != link.user || actor.stage != Stage::Full {
        return Err(Why::Expired);
    }
    if !provider::serves(p.tenant_id, actor.tenant_id) {
        return Err(Why::Forbidden);
    }
    let id = actor.user_id;
    let mut detail = json!({ "provider_id": p.id, "subject": subject, "ip": ip.to_string(),
                             "via": "me" });
    let txn = crate::api::begin(&state.db).await.map_err(Why::failed)?;
    identity::lock_account(&txn, id)
        .await
        .map_err(Why::failed)?;
    let bound = identity::bind(&txn, id, p.id, subject)
        .await
        .map_err(Why::failed)?;
    let (action, result) = match bound {
        Ok(identity) => {
            detail["identity_id"] = json!(identity);
            ("user.identity.link", Ok(Done::Linked(p.id)))
        }
        Err(taken) => {
            let why = match taken {
                Taken::Elsewhere => Why::Taken,
                Taken::Here => Why::Exists,
            };
            detail["reason"] = json!(why.as_str());
            ("user.identity.link.failed", Err(why))
        }
    };
    audit::record(&txn, Some(id), action, format!("app_user/{id}"), detail)
        .await
        .map_err(Why::failed)?;
    txn.commit().await.map_err(|e| Why::failed(e.into()))?;
    result
}
