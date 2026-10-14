//! The API's OpenAPI document, generated from the handlers. `docs/openapi.json` is
//! its committed copy (`make golden`): a test fails when the two drift.

use axum::Json;
use utoipa::OpenApi;

use super::{
    credentials, devices, identities, info, me, me_totp, networks, peers, providers, rights,
    routes, tenants, users,
};
use crate::auth::{Actor, challenge, links, local};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "wgate",
        description = "Multi-tenant WireGuard gateway: portal API. The `/auth` paths are \
                       at the root, not under `/api/v1`."
    ),
    servers((url = "/api/v1")),
    paths(
        local::options, local::login, challenge::login, links::info, links::redeem,
        me::change_password, me_totp::setup, me_totp::confirm, me_totp::remove,
        me_totp::regenerate, identities::mine, identities::linkable, identities::link, identities::unlink_mine,
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
        credentials::invite, credentials::reset, credentials::totp_reset,
        identities::of_user, identities::add, identities::remove,
        providers::list, providers::get, providers::create, providers::update,
        providers::remove,
        devices::devices, devices::add_device, devices::rename_device, devices::remove_device,
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
