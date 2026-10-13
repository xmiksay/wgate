//! Rules (a tenant admin's: what members of their network may open, inside the
//! tenant's ceiling or to another network of theirs) and federations (the global
//! admin's: members of one tenant's network may open to another tenant's).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use ipnet::Ipv4Net;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use wgate_core::{Rule, RuleSet, covers, overlaps};
use wgate_db::entity::{ceiling, federation, rule};

use super::{ServiceBody, begin, from_db, one_i64, tenant_of_network, to_db};
use crate::audit;
use crate::auth::Actor;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct RuleOut {
    pub id: i64,
    pub network_id: i64,
    #[serde(flatten)]
    pub service: ServiceBody,
    /// An external destination, or else `target_network_id`.
    #[schema(value_type = Option<String>)]
    pub dst: Option<Ipv4Net>,
    pub target_network_id: Option<i64>,
    pub comment: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RuleCreate {
    #[serde(flatten)]
    pub service: ServiceBody,
    /// Exactly one of `dst` and `target_network_id`.
    #[schema(value_type = Option<String>)]
    pub dst: Option<Ipv4Net>,
    pub target_network_id: Option<i64>,
    #[serde(default)]
    pub comment: String,
}

fn rule_out(r: rule::Model) -> Result<RuleOut, ApiError> {
    Ok(RuleOut {
        id: r.id,
        network_id: r.network_id,
        service: ServiceBody::from_columns(&r.proto, r.port_from, r.port_to),
        dst: r.dst.map(from_db).transpose()?,
        target_network_id: r.target_network_id,
        comment: r.comment,
    })
}

#[utoipa::path(get, path = "/networks/{id}/rules", responses((status = 200, body = [RuleOut])))]
pub async fn rules(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<Json<Vec<RuleOut>>, ApiError> {
    actor.tenant(tenant_of_network(&s.db, id).await?)?;
    let rows = rule::Entity::find()
        .filter(rule::Column::NetworkId.eq(id))
        .order_by_asc(rule::Column::Id)
        .all(&s.db)
        .await?;
    Ok(Json(
        rows.into_iter().map(rule_out).collect::<Result<_, _>>()?,
    ))
}

/// An external rule must lie inside the tenant's ceiling: 422 with what is not
/// covered. A network target is one of the same tenant's.
#[utoipa::path(post, path = "/networks/{id}/rules", request_body = RuleCreate, responses((status = 201, body = RuleOut), (status = 422, body = crate::error::ErrorBody)))]
pub async fn add_rule(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
    Json(body): Json<RuleCreate>,
) -> Result<(StatusCode, Json<RuleOut>), ApiError> {
    let service = body.service.service()?;
    let (proto, port_from, port_to) = body.service.columns()?;
    let txn = begin(&s.db).await?;
    let tenant = tenant_of_network(&txn, id).await?;
    actor.tenant(tenant)?;
    match (body.dst, body.target_network_id) {
        (Some(dst), None) => {
            let dst = dst.trunc();
            if s.config.pool.iter().any(|p| overlaps(*p, dst)) {
                return Err(ApiError::invalid(format!(
                    "{dst} is tenant space: target one of your networks (or ask for a federation)"
                )));
            }
            let ceiling = tenant_ceiling(&txn, tenant).await?;
            if let Err(rest) = covers(&ceiling, &Rule::from_parts(dst, service)) {
                let uncovered: Vec<String> = rest.0.iter().map(ToString::to_string).collect();
                return Err(ApiError::Invalid {
                    message: "the tenant's ceiling does not cover the rule".into(),
                    detail: Some(json!({ "uncovered": uncovered })),
                });
            }
        }
        (None, Some(target)) => {
            if tenant_of_network(&txn, target).await? != tenant {
                return Err(ApiError::invalid(
                    "the target network is another tenant's: that takes a federation",
                ));
            }
        }
        _ => {
            return Err(ApiError::invalid(
                "exactly one of dst and target_network_id",
            ));
        }
    }
    let r = rule::ActiveModel {
        tenant_id: Set(tenant),
        network_id: Set(id),
        proto: Set(proto),
        port_from: Set(port_from),
        port_to: Set(port_to),
        dst: Set(body.dst.map(|d| to_db(d.trunc()))),
        target_network_id: Set(body.target_network_id),
        comment: Set(body.comment),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    audit::record(&txn, Some(actor.user_id), "rule.create", format!("rule/{}", r.id), json!({ "network_id": id, "service": body.service, "dst": body.dst.map(|d| d.to_string()), "target_network_id": body.target_network_id })).await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(rule_out(r)?)))
}

async fn tenant_ceiling<C: sea_orm::ConnectionTrait>(
    db: &C,
    tenant: i64,
) -> Result<RuleSet, ApiError> {
    let rows = ceiling::Entity::find()
        .filter(ceiling::Column::TenantId.eq(tenant))
        .all(db)
        .await?;
    let mut rules = vec![];
    for c in rows {
        let service = ServiceBody::from_columns(&c.proto, c.port_from, c.port_to).service()?;
        rules.push(Rule::from_parts(from_db(c.dst)?, service));
    }
    Ok(RuleSet::from_rules(&rules))
}

#[utoipa::path(delete, path = "/rules/{id}", responses((status = 204)))]
pub async fn remove_rule(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let txn = begin(&s.db).await?;
    actor.tenant(one_i64(&txn, "SELECT tenant_id AS v FROM rule WHERE id = $1", id).await?)?;
    rule::Entity::delete_by_id(id).exec(&txn).await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "rule.delete",
        format!("rule/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct Federation {
    pub id: i64,
    pub from_network_id: i64,
    pub to_network_id: i64,
    #[serde(flatten)]
    pub service: ServiceBody,
}

#[derive(Deserialize, ToSchema)]
pub struct FederationCreate {
    pub from_network_id: i64,
    pub to_network_id: i64,
    #[serde(flatten)]
    pub service: ServiceBody,
}

fn federation_out(f: federation::Model) -> Federation {
    Federation {
        id: f.id,
        from_network_id: f.from_network_id,
        to_network_id: f.to_network_id,
        service: ServiceBody::from_columns(&f.proto, f.port_from, f.port_to),
    }
}

#[utoipa::path(get, path = "/federations", responses((status = 200, body = [Federation])))]
pub async fn federations(
    State(s): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<Federation>>, ApiError> {
    actor.global()?;
    let rows = federation::Entity::find()
        .order_by_asc(federation::Column::Id)
        .all(&s.db)
        .await?;
    Ok(Json(rows.into_iter().map(federation_out).collect()))
}

/// Between networks of two different tenants (the schema refuses one tenant).
#[utoipa::path(post, path = "/federations", request_body = FederationCreate, responses((status = 201, body = Federation)))]
pub async fn add_federation(
    State(s): State<AppState>,
    actor: Actor,
    Json(body): Json<FederationCreate>,
) -> Result<(StatusCode, Json<Federation>), ApiError> {
    actor.global()?;
    let (proto, port_from, port_to) = body.service.columns()?;
    let txn = begin(&s.db).await?;
    let f = federation::ActiveModel {
        from_network_id: Set(body.from_network_id),
        to_network_id: Set(body.to_network_id),
        proto: Set(proto),
        port_from: Set(port_from),
        port_to: Set(port_to),
        ..Default::default()
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(actor.user_id),
        "federation.create",
        format!("federation/{}", f.id),
        json!({ "from": body.from_network_id, "to": body.to_network_id, "service": body.service }),
    )
    .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, Json(federation_out(f))))
}

#[utoipa::path(delete, path = "/federations/{id}", responses((status = 204)))]
pub async fn remove_federation(
    State(s): State<AppState>,
    actor: Actor,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    actor.global()?;
    let txn = begin(&s.db).await?;
    if federation::Entity::delete_by_id(id)
        .exec(&txn)
        .await?
        .rows_affected
        == 0
    {
        return Err(ApiError::NotFound);
    }
    audit::record(
        &txn,
        Some(actor.user_id),
        "federation.delete",
        format!("federation/{id}"),
        json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
