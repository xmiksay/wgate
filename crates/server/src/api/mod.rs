//! `/api/v1`. Every write runs in one READ COMMITTED transaction with its audit
//! entry; the schema's constraints decide what is taken or overlapping, the handlers
//! decide who may and what the rights allow.

mod clientconf;
pub(crate) mod credentials;
mod devices;
mod info;
mod me;
mod me_totp;
mod networks;
mod openapi;
mod peers;
mod rights;
mod routes;
mod tenants;
mod users;

use std::net::IpAddr;

use axum::Router;
use axum::routing::{delete, get, patch, post};
use ipnet::Ipv4Net;
use sea_orm::prelude::IpNetwork;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, IsolationLevel, Statement,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use wgate_core::{PortRange, Proto, Service};

pub use openapi::openapi;

use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/session", get(info::session))
        .route("/me/password", post(me::change_password))
        .route("/me/totp", delete(me_totp::remove))
        .route("/me/totp/setup", post(me_totp::setup))
        .route("/me/totp/confirm", post(me_totp::confirm))
        .route("/me/recovery-codes", post(me_totp::regenerate))
        .route("/status", get(info::status))
        .route("/audit", get(info::audit))
        .route("/openapi.json", get(openapi::spec))
        .route("/free-block", get(info::free_block))
        .route("/free-port", get(info::free_port))
        .route("/tenants", get(tenants::list).post(tenants::create))
        .route(
            "/tenants/{id}",
            get(tenants::get)
                .patch(tenants::update)
                .delete(tenants::remove),
        )
        .route("/tenants/{id}/free-range", get(info::free_range))
        .route(
            "/tenants/{id}/blocks",
            get(tenants::blocks).post(tenants::add_block),
        )
        .route("/blocks/{id}", delete(tenants::remove_block))
        .route(
            "/tenants/{id}/ceilings",
            get(tenants::ceilings).post(tenants::add_ceiling),
        )
        .route("/ceilings/{id}", delete(tenants::remove_ceiling))
        .route("/networks", get(networks::list).post(networks::create))
        .route(
            "/networks/{id}",
            get(networks::get)
                .patch(networks::update)
                .delete(networks::remove),
        )
        .route("/networks/{id}/free-ip", get(info::free_ip))
        .route(
            "/networks/{id}/inbound",
            get(networks::inbound).post(networks::add_inbound),
        )
        .route("/inbound/{id}", delete(networks::remove_inbound))
        .route(
            "/networks/{id}/rules",
            get(rights::rules).post(rights::add_rule),
        )
        .route("/rules/{id}", delete(rights::remove_rule))
        .route(
            "/federations",
            get(rights::federations).post(rights::add_federation),
        )
        .route("/federations/{id}", delete(rights::remove_federation))
        .route("/users", get(users::list).post(users::create))
        .route("/users/{id}", patch(users::update).delete(users::remove))
        .route("/users/{id}/invite", post(credentials::invite))
        .route("/users/{id}/reset", post(credentials::reset))
        .route("/users/{id}/totp-reset", post(credentials::totp_reset))
        .route("/devices", get(devices::devices).post(devices::add_device))
        .route(
            "/devices/{id}",
            patch(devices::rename_device).delete(devices::remove_device),
        )
        .route("/peers", get(peers::list).post(peers::create))
        .route("/peers/{id}", get(peers::get).delete(peers::remove))
        .route("/peers/{id}/config", post(peers::config))
        .route("/peers/{id}/revoke", post(peers::revoke))
        .route("/peers/{id}/routes", post(routes::add_route))
        .route("/routes/{id}", delete(routes::remove_route))
        // An unknown API path is the API's 404, never the UI's index.html.
        .fallback(async || ApiError::NotFound)
}

/// A write: READ COMMITTED (the schema refuses state writes at any other level).
pub(crate) async fn begin(db: &DatabaseConnection) -> Result<DatabaseTransaction, ApiError> {
    Ok(db
        .begin_with_config(Some(IsolationLevel::ReadCommitted), None)
        .await?)
}

/// Protocol and ports of a rule-like row.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ServiceBody {
    /// `tcp`, `udp` or `icmp`.
    pub proto: String,
    /// tcp/udp only, 1..=65535.
    pub port_from: Option<u16>,
    pub port_to: Option<u16>,
}

impl ServiceBody {
    fn service(&self) -> Result<Service, ApiError> {
        let proto = match self.proto.as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            "icmp" => Proto::Icmp,
            other => return Err(ApiError::invalid(format!("unknown protocol {other}"))),
        };
        let ports = match (self.port_from, self.port_to) {
            (None, None) => None,
            (Some(from), to) => Some(
                PortRange::new(from, to.unwrap_or(from))
                    .map_err(|e| ApiError::invalid(e.to_string()))?,
            ),
            (None, Some(_)) => return Err(ApiError::invalid("port_to without port_from")),
        };
        Service::new(proto, ports).map_err(|e| ApiError::invalid(e.to_string()))
    }

    /// (proto, port_from, port_to) as the schema stores them.
    fn columns(&self) -> Result<(String, Option<i32>, Option<i32>), ApiError> {
        let s = self.service()?;
        let ports = s.ports();
        Ok((
            s.proto().to_string(),
            ports.map(|p| i32::from(p.from())),
            ports.map(|p| i32::from(p.to())),
        ))
    }

    fn from_columns(proto: &str, port_from: Option<i32>, port_to: Option<i32>) -> Self {
        let port = |p: Option<i32>| p.and_then(|p| u16::try_from(p).ok());
        Self {
            proto: proto.to_owned(),
            port_from: port(port_from),
            port_to: port(port_to),
        }
    }
}

pub(crate) fn to_db(net: Ipv4Net) -> IpNetwork {
    // A valid Ipv4Net is a valid IpNetwork.
    IpNetwork::new(IpAddr::V4(net.addr()), net.prefix_len())
        .unwrap_or_else(|_| IpNetwork::from(IpAddr::V4(net.addr())))
}

/// A network's DNS servers (the schema holds IPv4 hosts only).
pub(crate) fn dns_hosts(dns: &[IpNetwork]) -> Vec<std::net::Ipv4Addr> {
    dns.iter()
        .filter_map(|d| match d {
            IpNetwork::V4(a) => Some(a.ip()),
            IpNetwork::V6(_) => None,
        })
        .collect()
}

pub(crate) fn from_db(net: IpNetwork) -> Result<Ipv4Net, ApiError> {
    match net {
        IpNetwork::V4(n) => {
            Ipv4Net::new(n.ip(), n.prefix()).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))
        }
        IpNetwork::V6(n) => Err(ApiError::Internal(anyhow::anyhow!(
            "IPv6 {n} in the database"
        ))),
    }
}

/// A network's tenant; `NotFound` if it does not exist.
async fn tenant_of_network<C: ConnectionTrait>(db: &C, id: i64) -> Result<i64, ApiError> {
    one_i64(db, "SELECT tenant_id AS v FROM network WHERE id = $1", id).await
}

/// A user's tenant (`None` for a global admin); `NotFound` if there is no such user.
async fn tenant_of_user<C: ConnectionTrait>(db: &C, id: i64) -> Result<Option<i64>, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT tenant_id FROM app_user WHERE id = $1",
            [id.into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(row.try_get("", "tenant_id")?)
}

/// The single bigint column `v` of a one-row query keyed by `id`.
async fn one_i64<C: ConnectionTrait>(db: &C, sql: &str, id: i64) -> Result<i64, ApiError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            [id.into()],
        ))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(row.try_get("", "v")?)
}
