//! A server-made private key never reaches the log. Its own test binary: the
//! subscriber is the global one, installed before any callsite registers (a scoped
//! one misses callsites whose interest other tests' threads already cached).
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::sign_in;
use serde_json::json;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_private_key_never_reaches_the_log() {
    let captured = Captured::default();
    let sink = captured.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .init();
    let e = common::env().await;
    let g = sign_in(&e, "g@example.org", "global_admin", None).await;
    let id = |v: &serde_json::Value| v["id"].as_i64().unwrap();
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
                    "cidr": "10.50.0.0/25", "port": 51801 }),
        )
        .await);
    common::sql(
        &e.db,
        &format!(
            "INSERT INTO hub_key (network_id, public_key)
             VALUES ({network}, 'HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=')"
        ),
    )
    .await;
    let user = id(&g
        .create(
            "/users",
            json!({ "tenant_id": tenant, "email": "u@acme.test", "role": "user" }),
        )
        .await);
    let device = id(&g
        .create("/devices", json!({ "user_id": user, "name": "laptop" }))
        .await);
    let mut keys = vec![];
    let created = g
        .create(
            "/peers",
            json!({ "device_id": device, "network_id": network, "ip": "10.50.0.2" }),
        )
        .await;
    keys.push(created["config"]["config"].as_str().unwrap().to_owned());
    let peer = id(&created["peer"]);
    let (_, rotated) = g.post(&format!("/peers/{peer}/config"), json!({})).await;
    keys.push(rotated["config"]["config"].as_str().unwrap().to_owned());
    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("INSERT INTO"),
        "the subscriber missed the queries"
    );
    for config in keys {
        let private = config
            .lines()
            .find_map(|l| l.strip_prefix("PrivateKey = "))
            .expect("a private key");
        assert!(!log.contains(private), "a private key was logged");
    }
}
