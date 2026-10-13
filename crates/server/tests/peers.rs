//! Peers: server and pasted keys, configs and their rotation, routed LANs, revocation
//! and its notification.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{Client, Env, sign_in, sql};
use serde_json::{Value, json};

const PASTED: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const HUB: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

fn id(v: &Value) -> i64 {
    v["id"].as_i64().unwrap_or_else(|| panic!("no id in {v}"))
}

struct World {
    e: Env,
    g: Client,
    tenant: i64,
    network: i64,
    device: i64,
}

async fn world() -> World {
    let e = common::env().await;
    let g = sign_in(&e, "g@example.org", "global_admin", None).await;
    let tenant = id(&g
        .create("/tenants", json!({ "slug": "acme", "name": "Acme" }))
        .await);
    let block = id(&g
        .create(
            &format!("/tenants/{tenant}/blocks"),
            json!({ "cidr": "10.50.0.0/24" }),
        )
        .await);
    let network = id(&g
        .create(
            "/networks",
            json!({ "tenant_id": tenant, "block_id": block, "slug": "acme", "name": "Acme",
                    "cidr": "10.50.0.0/25", "port": 51801, "dns": ["10.50.0.1"] }),
        )
        .await);
    let user = id(&g
        .create(
            "/users",
            json!({ "tenant_id": tenant, "email": "u@acme.test", "role": "user" }),
        )
        .await);
    let device = id(&g
        .create("/devices", json!({ "user_id": user, "name": "laptop" }))
        .await);
    World {
        e,
        g,
        tenant,
        network,
        device,
    }
}

/// What the agent does once the network is up.
async fn publish_hub_key(w: &World) {
    sql(
        &w.e.db,
        &format!(
            "INSERT INTO hub_key (network_id, public_key) VALUES ({}, '{HUB}')",
            w.network
        ),
    )
    .await;
}

fn private_key(config: &str) -> Option<String> {
    config
        .lines()
        .find_map(|l| l.strip_prefix("PrivateKey = "))
        .map(str::to_owned)
}

#[tokio::test]
async fn a_server_key_is_shown_once_and_every_download_rotates_it() {
    let w = world().await;
    let created =
        w.g.create(
            "/peers",
            json!({ "device_id": w.device, "network_id": w.network, "ip": "10.50.0.2" }),
        )
        .await;
    // Before the hub publishes its key: no config yet, and why.
    assert!(created["config"].is_null(), "{created}");
    assert!(
        created["warnings"][0]
            .as_str()
            .unwrap()
            .contains("download it again")
    );
    assert_eq!(created["peer"]["key_source"], "server");
    let peer = id(&created["peer"]);
    let first_key = created["peer"]["public_key"].as_str().unwrap().to_owned();
    // A download with nothing to show keeps the working key.
    let (s, v) = w.g.post(&format!("/peers/{peer}/config"), json!({})).await;
    assert!(s == StatusCode::OK && v["config"].is_null(), "{v}");
    let (_, now) = w.g.get(&format!("/peers/{peer}")).await;
    assert_eq!(now["public_key"], first_key.as_str());

    publish_hub_key(&w).await;
    let (s, v) = w.g.post(&format!("/peers/{peer}/config"), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let config = v["config"]["config"].as_str().unwrap();
    let private = private_key(config).expect("a private key");
    assert!(wgate_core::is_wg_key(&private));
    assert!(config.contains(&format!("PublicKey = {HUB}")), "{config}");
    assert!(config.contains("Endpoint = 127.0.0.1:51801"), "{config}");
    assert!(config.contains("DNS = 10.50.0.1"), "{config}");
    assert!(config.contains("AllowedIPs = 10.50.0.1/32"), "{config}");
    assert!(v["config"]["qr_svg"].as_str().unwrap().starts_with("<?xml"));
    let (_, now) = w.g.get(&format!("/peers/{peer}")).await;
    let second_key = now["public_key"].as_str().unwrap().to_owned();
    assert_ne!(second_key, first_key, "rotated");
    // Again: another key, the previous config is dead.
    let (_, again) = w.g.post(&format!("/peers/{peer}/config"), json!({})).await;
    assert_ne!(
        private_key(again["config"]["config"].as_str().unwrap()).unwrap(),
        private
    );
    let (_, now) = w.g.get(&format!("/peers/{peer}")).await;
    assert_ne!(now["public_key"], second_key);
}

#[tokio::test]
async fn a_pasted_key_is_never_rotated() {
    let w = world().await;
    publish_hub_key(&w).await;
    let created = w
        .g
        .create(
            "/peers",
            json!({ "device_id": w.device, "network_id": w.network, "ip": "10.50.0.3", "public_key": PASTED }),
        )
        .await;
    let peer = id(&created["peer"]);
    let config = created["config"]["config"].as_str().unwrap();
    assert!(
        private_key(config).is_none() && config.contains("# PrivateKey"),
        "{config}"
    );
    let (_, v) = w.g.post(&format!("/peers/{peer}/config"), json!({})).await;
    assert!(private_key(v["config"]["config"].as_str().unwrap()).is_none());
    let (_, now) = w.g.get(&format!("/peers/{peer}")).await;
    assert_eq!(now["public_key"], PASTED);
    let (s, _) = w
        .g
        .post("/peers", json!({ "device_id": w.device, "network_id": w.network, "ip": "10.50.0.4", "public_key": "nope" }))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn revoking_notifies_the_agent_and_is_final() {
    let w = world().await;
    let created = w
        .g
        .create("/peers", json!({ "device_id": w.device, "network_id": w.network, "ip": "10.50.0.2", "public_key": PASTED }))
        .await;
    let peer = id(&created["peer"]);
    let mut listener = wgate_db::revision::listener(&w.e.url).await.unwrap();
    let (s, v) = w.g.post(&format!("/peers/{peer}/revoke"), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["revoked"], true);
    let note = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("notified within 5 s")
        .unwrap();
    assert_eq!(note.channel(), wgate_db::revision::CHANNEL);
    let (s, _) = w.g.post(&format!("/peers/{peer}/config"), json!({})).await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "no config for a revoked peer"
    );
}

#[tokio::test]
async fn routed_lans_stay_in_routed_space_and_clear_of_others_rights() {
    let w = world().await;
    let g = &w.g;
    let other = id(&g
        .create("/tenants", json!({ "slug": "other", "name": "Other" }))
        .await);
    g.create(
        &format!("/tenants/{other}/ceilings"),
        json!({ "dst": "192.168.7.0/24", "proto": "icmp" }),
    )
    .await;
    let created = g
        .create(
            "/peers",
            json!({ "device_id": w.device, "network_id": w.network, "ip": "10.50.0.2",
                                "public_key": PASTED, "routes": ["192.168.1.0/24"] }),
        )
        .await;
    let peer = id(&created["peer"]);
    assert_eq!(created["peer"]["routes"][0]["cidr"], "192.168.1.0/24");
    let routes = format!("/peers/{peer}/routes");
    for (cidr, why) in [
        ("8.8.8.0/24", "outside routed space"),
        ("172.16.16.0/24", "reserved"),
        ("192.168.7.0/24", "another tenant's ceiling"),
        ("192.168.1.0/25", "another active LAN"),
        ("10.50.200.0/24", "the pool"),
        ("172.19.9.0/25", "a node network"),
    ] {
        let (s, v) = g.post(&routes, json!({ "cidr": cidr })).await;
        assert!(
            s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::CONFLICT,
            "{why}: {s} {v}"
        );
    }
    // And the other way round: no grant of another tenant reaches the LAN.
    let (s, v) = g
        .post(
            &format!("/tenants/{other}/ceilings"),
            json!({ "dst": "192.168.0.0/16", "proto": "icmp" }),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let theirs = id(&g
        .create(
            &format!("/tenants/{other}/blocks"),
            json!({ "cidr": "10.50.1.0/24" }),
        )
        .await);
    let their_net = id(&g
        .create(
            "/networks",
            json!({ "tenant_id": other, "block_id": theirs, "slug": "other",
                                     "name": "Other", "cidr": "10.50.1.0/25", "port": 51802 }),
        )
        .await);
    let (s, v) = g
        .post(
            &format!("/networks/{their_net}/inbound"),
            json!({ "source": "192.168.1.0/24", "proto": "icmp" }),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    // The tenant's own ceiling may cover its own LAN.
    g.create(
        &format!("/tenants/{}/ceilings", w.tenant),
        json!({ "dst": "192.168.1.0/24", "proto": "icmp" }),
    )
    .await;
    let r = g.create(&routes, json!({ "cidr": "192.168.2.0/24" })).await;
    let (s, _) = g.delete(&format!("/routes/{}", id(&r))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_global_admins_peer_is_out_of_a_tenant_admins_reach() {
    let w = world().await;
    let mine = id(&w
        .g
        .create(
            "/devices",
            json!({ "user_id": w.g.user_id, "name": "admin laptop" }),
        )
        .await);
    let peer = id(&w
        .g
        .create(
            "/peers",
            json!({ "device_id": mine, "network_id": w.network, "ip": "10.50.0.9" }),
        )
        .await["peer"]);
    let a = sign_in(&w.e, "a@acme.test", "tenant_admin", Some(w.tenant)).await;
    for (method, uri) in [
        (Method::GET, format!("/peers/{peer}")),
        (Method::POST, format!("/peers/{peer}/config")),
        (Method::POST, format!("/peers/{peer}/revoke")),
        (Method::POST, format!("/peers/{peer}/routes")),
        (Method::DELETE, format!("/peers/{peer}")),
    ] {
        let body = (method == Method::POST).then(|| json!({ "cidr": "192.168.3.0/24" }));
        let (s, _) = a.call(method.clone(), &uri, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    // The agent's own words reach global admins only.
    sql(&w.e.db, "INSERT INTO agent_status (applied_revision, applied_at, error) VALUES (0, now(), 'wg-other: boom')").await;
    let (_, v) = a.get("/status").await;
    assert_eq!(
        (v["failing"].clone(), v["error"].clone()),
        (json!(true), Value::Null)
    );
    let (_, v) = w.g.get("/status").await;
    assert_eq!(v["error"], "wg-other: boom");
}
