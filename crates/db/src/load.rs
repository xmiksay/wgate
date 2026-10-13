//! Desired state from the database, for `core::compile`.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use sea_orm::prelude::IpNetwork;
use sea_orm::{
    AccessMode, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    IsolationLevel, QueryFilter, QuerySelect, TransactionTrait,
};
use wgate_core::{
    Claim, DesiredState, Federation, NetRule, Network, Peer, PortRange, Proto, Rule, RuleSet,
    Service, Slug, Tenant,
};

use crate::entity::{
    app_user, ceiling, device, federation, inbound, network, peer, peer_route, rule, tenant,
    tenant_block,
};

/// Configuration the desired state needs besides the database.
#[derive(Clone, Debug)]
pub struct Infra {
    pub pool: Vec<Ipv4Net>,
    pub routed_space: Vec<Ipv4Net>,
    pub reserved: Vec<Ipv4Net>,
    pub snat_source: Ipv4Addr,
    pub node_cidrs: Vec<Ipv4Net>,
}

/// The desired state, plus rows that could not be mapped and were left out. A bad
/// row fails closed alone: failing the whole load would block every change,
/// revocations included.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub state: DesiredState,
    /// The revision this state is; record it as applied, not a later one.
    pub revision: i64,
    pub warnings: Vec<String>,
}

/// Active rows only: disabled tenants/networks/users and revoked peers have no
/// access, so they are simply not part of the desired state.
///
/// Everything, the revision included, is read in one read-only snapshot: a change
/// committed halfway through (a revocation, a disabled user) must not be half seen
/// and then counted as applied.
pub async fn desired_state(db: &DatabaseConnection, infra: &Infra) -> Result<Loaded, DbErr> {
    let txn = db
        .begin_with_config(
            Some(IsolationLevel::RepeatableRead),
            Some(AccessMode::ReadOnly),
        )
        .await?;
    let loaded = load(&txn, infra).await?;
    txn.commit().await?;
    Ok(loaded)
}

async fn load<C: ConnectionTrait>(db: &C, infra: &Infra) -> Result<Loaded, DbErr> {
    let revision = crate::revision::current(db).await?;
    let mut warnings = Vec::new();
    let mut warn =
        |table: &str, id: i64, why: String| warnings.push(format!("{table} {id}: {why}"));

    let tenants = tenant::Entity::find()
        .filter(tenant::Column::DisabledAt.is_null())
        .all(db)
        .await?;
    let active_tenants: HashSet<i64> = tenants.iter().map(|t| t.id).collect();
    let mut blocks: HashMap<i64, Vec<Claim>> = HashMap::new();
    for b in tenant_block::Entity::find().all(db).await? {
        match v4(b.cidr) {
            Some(cidr) => blocks
                .entry(b.tenant_id)
                .or_default()
                .push(Claim { id: b.id, cidr }),
            None => warn("tenant_block", b.id, "not IPv4".into()),
        }
    }
    let mut ceilings: HashMap<i64, Vec<Rule>> = HashMap::new();
    for c in ceiling::Entity::find().all(db).await? {
        match to_rule(&c.proto, Some(c.dst), c.port_from, c.port_to) {
            Ok(r) => ceilings.entry(c.tenant_id).or_default().push(r),
            Err(e) => warn("ceiling", c.id, e),
        }
    }

    let networks = network::Entity::find()
        .filter(network::Column::DisabledAt.is_null())
        .all(db)
        .await?;
    let networks: Vec<network::Model> = networks
        .into_iter()
        .filter(|n| active_tenants.contains(&n.tenant_id))
        .collect();
    let mut rules: HashMap<i64, Vec<NetRule>> = HashMap::new();
    for r in rule::Entity::find().all(db).await? {
        let mapped = match (r.dst, r.target_network_id) {
            (Some(dst), None) => {
                to_rule(&r.proto, Some(dst), r.port_from, r.port_to).map(NetRule::External)
            }
            (None, Some(target)) => {
                to_service(&r.proto, r.port_from, r.port_to).map(|service| NetRule::To {
                    network: target,
                    service,
                })
            }
            _ => Err("needs exactly one of dst and target_network_id".into()),
        };
        match mapped {
            Ok(m) => rules.entry(r.network_id).or_default().push(m),
            Err(e) => warn("rule", r.id, e),
        }
    }
    let mut grants: HashMap<i64, Vec<Rule>> = HashMap::new();
    for g in inbound::Entity::find().all(db).await? {
        match to_rule(&g.proto, Some(g.source), g.port_from, g.port_to) {
            Ok(r) => grants.entry(g.network_id).or_default().push(r),
            Err(e) => warn("inbound", g.id, e),
        }
    }
    let mut state_networks = Vec::new();
    for n in &networks {
        let slug = n.slug.parse::<Slug>().map_err(|e| e.to_string());
        let port = u16::try_from(n.port).map_err(|e| e.to_string());
        match (slug, v4(n.cidr), port) {
            (Ok(slug), Some(cidr), Ok(port)) => state_networks.push(Network {
                id: n.id,
                tenant: n.tenant_id,
                slug,
                port,
                cidr,
                mesh: n.mesh,
                rules: rules.remove(&n.id).unwrap_or_default(),
                inbound: RuleSet::from_rules(&grants.remove(&n.id).unwrap_or_default()),
            }),
            (Err(e), _, _) | (_, _, Err(e)) => warn("network", n.id, e),
            (_, None, _) => warn("network", n.id, "not IPv4".into()),
        }
    }

    // user id → tenant (None = a global admin, who may hold peers anywhere).
    // Only the columns the agent role may read: no emails or OIDC subjects.
    let users: HashMap<i64, Option<i64>> = app_user::Entity::find()
        .select_only()
        .columns([app_user::Column::Id, app_user::Column::TenantId])
        .filter(app_user::Column::DisabledAt.is_null())
        .into_tuple::<(i64, Option<i64>)>()
        .all(db)
        .await?
        .into_iter()
        .collect();
    // device id → owner's tenant, for active owners.
    let devices: HashMap<i64, Option<i64>> = device::Entity::find()
        .select_only()
        .columns([device::Column::Id, device::Column::UserId])
        .into_tuple::<(i64, i64)>()
        .all(db)
        .await?
        .into_iter()
        .filter_map(|(id, user)| Some((id, *users.get(&user)?)))
        .collect();
    let active_networks: HashSet<i64> = state_networks.iter().map(|n| n.id).collect();
    let mut routes: HashMap<i64, Vec<Claim>> = HashMap::new();
    for r in peer_route::Entity::find().all(db).await? {
        match v4(r.cidr) {
            Some(cidr) => routes
                .entry(r.peer_id)
                .or_default()
                .push(Claim { id: r.id, cidr }),
            None => warn("peer_route", r.id, "not IPv4".into()),
        }
    }
    let mut peers = Vec::new();
    for p in peer::Entity::find()
        .filter(peer::Column::RevokedAt.is_null())
        .all(db)
        .await?
    {
        // Inactive owner or network: no access, nothing to report.
        let (Some(owner), true) = (
            devices.get(&p.device_id),
            active_networks.contains(&p.network_id),
        ) else {
            continue;
        };

        match v4(p.ip) {
            Some(ip) => peers.push(Peer {
                id: p.id,
                network: p.network_id,
                ip: ip.addr(),
                public_key: p.public_key,
                owner_tenant: *owner,
                routed: routes.remove(&p.id).unwrap_or_default(),
            }),
            None => warn("peer", p.id, "not IPv4".into()),
        }
    }

    let mut federations = Vec::new();
    for f in federation::Entity::find().all(db).await? {
        match to_service(&f.proto, f.port_from, f.port_to) {
            Ok(service) => federations.push(Federation {
                from: f.from_network_id,
                to: f.to_network_id,
                service,
            }),
            Err(e) => warn("federation", f.id, e),
        }
    }

    let state = DesiredState {
        pool: infra.pool.clone(),
        snat_source: infra.snat_source,
        node_cidrs: infra.node_cidrs.clone(),
        routed_space: infra.routed_space.clone(),
        reserved: infra.reserved.clone(),
        tenants: tenants
            .iter()
            .map(|t| Tenant {
                id: t.id,
                blocks: blocks.remove(&t.id).unwrap_or_default(),
                ceiling: RuleSet::from_rules(&ceilings.remove(&t.id).unwrap_or_default()),
            })
            .collect(),
        networks: state_networks,
        peers,
        federations,
    };
    Ok(Loaded {
        state,
        revision,
        warnings,
    })
}

/// For `inet` (a peer IP) the address part is the host address; `cidr` values have
/// no host bits (Postgres normalizes them).
fn v4(net: IpNetwork) -> Option<Ipv4Net> {
    match net {
        IpNetwork::V4(n) => Ipv4Net::new(n.ip(), n.prefix()).ok(),
        IpNetwork::V6(_) => None,
    }
}

fn to_service(proto: &str, from: Option<i32>, to: Option<i32>) -> Result<Service, String> {
    let proto: Proto = proto
        .parse()
        .map_err(|e: wgate_core::RuleError| e.to_string())?;
    let ports = match (from, to) {
        (None, None) => None,
        (Some(from), Some(to)) => {
            let port = |p: i32| u16::try_from(p).map_err(|_| format!("port {p} out of range"));
            Some(PortRange::new(port(from)?, port(to)?).map_err(|e| e.to_string())?)
        }
        _ => return Err("port_from and port_to must both be set or both be NULL".into()),
    };
    Service::new(proto, ports).map_err(|e| e.to_string())
}

fn to_rule(
    proto: &str,
    net: Option<IpNetwork>,
    from: Option<i32>,
    to: Option<i32>,
) -> Result<Rule, String> {
    let service = to_service(proto, from, to)?;
    let net = net.and_then(v4).ok_or("not IPv4")?;
    Rule::new(service.proto(), net, service.ports()).map_err(|e| e.to_string())
}
