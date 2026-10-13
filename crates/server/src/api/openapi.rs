//! The API's OpenAPI document, generated from the handlers. `docs/openapi.json` is
//! its committed copy (`make golden`): a test fails when the two drift.

use axum::Json;
use utoipa::OpenApi;

use super::{info, networks, peers, rights, routes, tenants, users};
use crate::auth::Actor;

#[derive(OpenApi)]
#[openapi(
    info(title = "wgate", description = "Multi-tenant WireGuard gateway: portal API."),
    servers((url = "/api/v1")),
    paths(
        info::session, info::status, info::audit, info::free_ip, info::free_range,
        info::free_block, info::free_port,
        tenants::list, tenants::get, tenants::create, tenants::update, tenants::remove,
        tenants::blocks, tenants::add_block, tenants::remove_block,
        tenants::ceilings, tenants::add_ceiling, tenants::remove_ceiling,
        networks::list, networks::get, networks::create, networks::update, networks::remove,
        networks::inbound, networks::add_inbound, networks::remove_inbound,
        rights::rules, rights::add_rule, rights::remove_rule,
        rights::federations, rights::add_federation, rights::remove_federation,
        users::list, users::create, users::update, users::remove,
        users::devices, users::add_device, users::rename_device, users::remove_device,
        peers::list, peers::get, peers::create, peers::config, peers::revoke, peers::remove,
        routes::add_route, routes::remove_route,
    )
)]
struct Doc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    Doc::openapi()
}

/// `GET /api/v1/openapi.json` (signed in).
pub async fn spec(_actor: Actor) -> Json<utoipa::openapi::OpenApi> {
    Json(openapi())
}
