//! The REST API against a real Postgres: CRUD, tenant boundaries, CSRF, ceilings,
//! inbound grants, cascades, errors and the audit trail.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::{Client, Env, sign_in};
use serde_json::{Value, json};

fn id(v: &Value) -> i64 {
    v["id"].as_i64().unwrap_or_else(|| panic!("no id in {v}"))
}

struct World {
    e: Env,
    global: Client,
    t1: i64,
    t2: i64,
    block1: i64,
    block2: i64,
}

async fn world() -> World {
    let e = common::env().await;
    let global = sign_in(&e, "g@example.org", "global_admin", None).await;
    let t1 = id(&global
        .create("/tenants", json!({ "slug": "acme", "name": "Acme" }))
        .await);
    let t2 = id(&global
        .create("/tenants", json!({ "slug": "other", "name": "Other" }))
        .await);
    let block1 = id(&global
        .create(
            &format!("/tenants/{t1}/blocks"),
            json!({ "cidr": "10.50.0.0/24" }),
        )
        .await);
    let block2 = id(&global
        .create(
            &format!("/tenants/{t2}/blocks"),
            json!({ "cidr": "10.50.1.0/24" }),
        )
        .await);
    World {
        e,
        global,
        t1,
        t2,
        block1,
        block2,
    }
}

fn network(tenant: i64, block: i64, slug: &str, cidr: &str, port: u16) -> Value {
    json!({ "tenant_id": tenant, "block_id": block, "slug": slug, "name": slug, "cidr": cidr, "port": port })
}

#[tokio::test]
async fn blocks_stay_in_the_pool_and_clear_of_each_other() {
    let w = world().await;
    let g = &w.global;
    let (s, v) = g
        .post(
            &format!("/tenants/{}/blocks", w.t1),
            json!({ "cidr": "192.168.0.0/24" }),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = g
        .post(
            &format!("/tenants/{}/blocks", w.t2),
            json!({ "cidr": "10.50.0.0/25" }),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    // Our words, never the database's.
    assert_eq!(v["error"], "conflict");
    assert!(!v.to_string().contains("constraint"), "{v}");
    // Under a missing tenant there is nothing, writes included.
    for (method, uri, body) in [
        (
            Method::POST,
            "/tenants/999/blocks",
            Some(json!({ "cidr": "10.50.9.0/24" })),
        ),
        (Method::GET, "/tenants/999/blocks", None),
        (
            Method::POST,
            "/tenants/999/ceilings",
            Some(json!({ "dst": "0.0.0.0/0", "proto": "icmp" })),
        ),
        (Method::GET, "/tenants/999/ceilings", None),
        (Method::GET, "/tenants/999/free-range?prefix=25", None),
    ] {
        let (s, _) = g.call(method.clone(), uri, body).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method} {uri}");
    }
}

#[tokio::test]
async fn a_tenant_admin_stays_inside_their_tenant() {
    let w = world().await;
    let a1 = sign_in(&w.e, "a@acme.test", "tenant_admin", Some(w.t1)).await;
    let n1 = id(&a1
        .create(
            "/networks",
            network(w.t1, w.block1, "acme", "10.50.0.0/25", 51801),
        )
        .await);
    let (s, _) = a1
        .post(
            "/networks",
            network(w.t2, w.block2, "theirs", "10.50.1.0/25", 51802),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Another tenant's block under one's own tenant: refused by the schema.
    let (s, v) = a1
        .post(
            "/networks",
            network(w.t1, w.block2, "sneaky", "10.50.1.0/25", 51803),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let n2 = id(&w
        .global
        .create(
            "/networks",
            network(w.t2, w.block2, "other", "10.50.1.0/25", 51802),
        )
        .await);
    let (_, list) = a1.get("/networks").await;
    let ids: Vec<i64> = list.as_array().unwrap().iter().map(id).collect();
    assert_eq!(ids, [n1]);
    for (method, uri) in [
        (Method::GET, format!("/networks/{n2}")),
        (Method::DELETE, format!("/networks/{n2}")),
        (Method::GET, format!("/tenants/{}", w.t2)),
        (Method::GET, "/audit".into()),
        (Method::GET, "/federations".into()),
    ] {
        let (s, _) = a1.call(method.clone(), &uri, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    let (s, _) = a1
        .post(
            "/users",
            json!({ "tenant_id": null, "email": "x@y", "role": "global_admin" }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = a1
        .post(
            "/users",
            json!({ "tenant_id": w.t2, "email": "x@y", "role": "user" }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    a1.create(
        "/users",
        json!({ "tenant_id": w.t1, "email": "u@acme.test", "role": "user" }),
    )
    .await;
}

#[tokio::test]
async fn writes_need_the_csrf_token() {
    let w = world().await;
    let (s, _) = w
        .global
        .call_with(
            Method::POST,
            "/tenants",
            Some(json!({ "slug": "x", "name": "x" })),
            false,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = w
        .global
        .call_with(Method::GET, "/tenants", None, false)
        .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn rules_stay_inside_the_ceiling_and_the_tenant() {
    let w = world().await;
    let g = &w.global;
    let n1 = id(&g
        .create(
            "/networks",
            network(w.t1, w.block1, "acme", "10.50.0.0/25", 51801),
        )
        .await);
    let n1b = id(&g
        .create(
            "/networks",
            network(w.t1, w.block1, "acme2", "10.50.0.128/25", 51803),
        )
        .await);
    let n2 = id(&g
        .create(
            "/networks",
            network(w.t2, w.block2, "other", "10.50.1.0/25", 51802),
        )
        .await);
    g.create(
        &format!("/tenants/{}/ceilings", w.t1),
        json!({ "dst": "172.16.16.0/24", "proto": "tcp", "port_from": 6443 }),
    )
    .await;
    let a1 = sign_in(&w.e, "a@acme.test", "tenant_admin", Some(w.t1)).await;
    let rules = format!("/networks/{n1}/rules");
    a1.create(
        &rules,
        json!({ "dst": "172.16.16.1/32", "proto": "tcp", "port_from": 6443 }),
    )
    .await;
    let (s, v) = a1
        .post(
            &rules,
            json!({ "dst": "172.16.16.0/23", "proto": "tcp", "port_from": 6443 }),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(
        v["detail"]["uncovered"],
        json!(["tcp 172.16.17.0-172.16.17.255 6443"])
    );
    let (s, _) = a1
        .post(&rules, json!({ "dst": "10.50.1.0/25", "proto": "icmp" }))
        .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "tenant space is no external destination"
    );
    let (s, _) = a1
        .post(&rules, json!({ "target_network_id": n2, "proto": "icmp" }))
        .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "another tenant: a federation's job"
    );
    a1.create(
        &rules,
        json!({ "target_network_id": n1b, "proto": "tcp", "port_from": 22 }),
    )
    .await;
    let (s, _) = a1
        .post(
            "/federations",
            json!({ "from_network_id": n1, "to_network_id": n2, "proto": "icmp" }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    g.create(
        "/federations",
        json!({ "from_network_id": n1, "to_network_id": n2, "proto": "icmp" }),
    )
    .await;
    let (s, _) = g
        .post(
            "/federations",
            json!({ "from_network_id": n1, "to_network_id": n1b, "proto": "icmp" }),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "one tenant: a rule's job"
    );
}

#[tokio::test]
async fn inbound_grants_warn_when_broad_and_stay_outside_the_pool() {
    let w = world().await;
    let g = &w.global;
    let n1 = id(&g
        .create(
            "/networks",
            network(w.t1, w.block1, "acme", "10.50.0.0/25", 51801),
        )
        .await);
    let uri = format!("/networks/{n1}/inbound");
    let v = g
        .create(
            &uri,
            json!({ "source": "10.244.0.0/16", "proto": "tcp", "port_from": 8080 }),
        )
        .await;
    assert_eq!(v["warnings"], json!([]));
    let v = g
        .create(&uri, json!({ "source": "192.0.0.0/8", "proto": "icmp" }))
        .await;
    assert_eq!(v["warnings"].as_array().unwrap().len(), 1);
    for source in ["10.50.1.0/24", "0.0.0.0/0"] {
        let (s, _) = g
            .post(&uri, json!({ "source": source, "proto": "icmp" }))
            .await;
        assert_eq!(
            s,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{source} overlaps the pool"
        );
    }
}

#[tokio::test]
async fn deleting_a_tenant_takes_everything_along_and_is_audited() {
    let w = world().await;
    let g = &w.global;
    let n1 = id(&g
        .create(
            "/networks",
            network(w.t1, w.block1, "acme", "10.50.0.0/25", 51801),
        )
        .await);
    let user = id(&g
        .create(
            "/users",
            json!({ "tenant_id": w.t1, "email": "u@acme.test", "role": "user" }),
        )
        .await);
    g.create("/devices", json!({ "user_id": user, "name": "laptop" }))
        .await;
    let (s, _) = g.delete(&format!("/tenants/{}", w.t1)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = g.get(&format!("/networks/{n1}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, audit) = g.get("/audit?limit=3").await;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["tenant.delete", "device.create", "user.create"]);
    let last = audit[2]["id"].as_i64().unwrap();
    let (_, older) = g.get(&format!("/audit?before={last}&limit=1")).await;
    assert_eq!(older[0]["action"], "network.create");
}

#[tokio::test]
async fn suggestions_point_at_free_space() {
    let w = world().await;
    let g = &w.global;
    let n1 = id(&g
        .create(
            "/networks",
            network(w.t1, w.block1, "acme", "10.50.0.0/25", 51801),
        )
        .await);
    let (_, v) = g.get(&format!("/networks/{n1}/free-ip")).await;
    assert_eq!(v["free"], "10.50.0.2");
    let (_, v) = g
        .get(&format!("/tenants/{}/free-range?prefix=25", w.t1))
        .await;
    assert_eq!(v["free"], "10.50.0.128/25");
    let (_, v) = g.get("/free-block?prefix=24").await;
    assert_eq!(v["free"], "10.50.2.0/24");
    let (_, v) = g.get("/free-port").await;
    assert_eq!(v["free"], 51800);
}
