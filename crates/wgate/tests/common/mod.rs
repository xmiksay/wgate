//! One world per test: Postgres in Docker, the server router in process, the real
//! agent loop in a `hub` namespace, and WireGuard clients in namespaces of their own.
//!
//! ```text
//!  client ns ─ p0 198.51.100.n ─┐
//!                               br0 198.51.100.1 (the endpoint)   ┌ hub ┐
//!  node 172.19.9.11 ─ eth-node 172.19.9.10 (no route back: SNAT)  │     │
//!  pod 10.244.0.5   ─ eth-pod  10.244.0.1  (outside the pool)     │     │
//!  infra0 172.16.16.1 (wg0 stand-in; echo on 6443 and 22)         └─────┘
//! ```
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

pub mod api;
#[path = "../../../agent/tests/common/mod.rs"]
pub mod netns;
pub mod wg;

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use axum::http::Method;
use netns::py::{ECHO, PROBE, STREAM};
use netns::{Background, Netns};
use sea_orm::{Database, DatabaseConnection};
use serde_json::{Value, json};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use wgate_agent::System;
use wgate_server::AppState;

pub use api::{Client, id};

pub const ENDPOINT: &str = "198.51.100.1";
pub const NODE: &str = "172.19.9.11";
pub const POD: &str = "10.244.0.5";
pub const HUB_SERVICES: &str = "172.16.16.1";
const POOL: &str = "10.50.0.0/16";
const ROUTED: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const RESERVED: [&str; 2] = ["172.19.9.0/24", "172.16.16.0/24"];
const NODES: &str = "172.19.9.0/24";
const SNAT: &str = "172.19.9.10";

/// Aborts the agent task when the world goes.
struct Agent(tokio::task::JoinHandle<()>);

impl Drop for Agent {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Fields drop in order: the agent stops, the processes die, then the namespaces go.
pub struct World {
    _agent: Agent,
    _servers: Vec<Background>,
    pub hub: Netns,
    pub node: Netns,
    pub pod: Netns,
    pub db: DatabaseConnection,
    pub app: axum::Router,
    pub admin: Client,
    hosts: AtomicU8,
    _keys: tempfile::TempDir,
    _pg: ContainerAsync<Postgres>,
}

/// A client namespace (a peer's device) with an echo server on 7000.
pub struct Host {
    _echo: Background,
    pub ns: Netns,
}

/// Exit 0 when a TCP echo round trip works within a second.
pub fn tcp_ok(from: &Netns, host: &str, port: u16) -> bool {
    from.succeeds(&["python3", "-c", PROBE, host, &port.to_string()])
}

pub fn ping_ok(from: &Netns, host: &str) -> bool {
    from.succeeds(&["ping", "-c", "1", "-W", "2", host])
}

/// One echo connection, "ok" every 100 ms for a minute; returns once it is up.
pub fn stream(from: &Netns, host: &str, port: u16) -> Background {
    let s = from.spawn(&["python3", "-c", STREAM, host, &port.to_string(), "60"]);
    assert_eq!(s.expect_line("stream is up"), "ok");
    s
}

/// When each line of `s` arrived, up to `until` (lines already queued included).
pub fn lines_until(s: &Background, until: Instant) -> Vec<Instant> {
    let mut at = vec![];
    while let Ok((t, _)) = s
        .lines
        .recv_timeout(until.saturating_duration_since(Instant::now()))
    {
        at.push(t);
    }
    at
}

/// The longest silence of a stream between `from` and `until`.
pub fn longest_gap(from: Instant, until: Instant, at: &[Instant]) -> Duration {
    let mut prev = from;
    let mut gap = Duration::ZERO;
    for t in at.iter().chain([&until]) {
        gap = gap.max(t.saturating_duration_since(prev));
        prev = prev.max(*t);
    }
    gap
}

fn veth(hub: &Netns, ns: &Netns, iface: &str) {
    hub.exec(
        &[
            "ip", "link", "add", iface, "type", "veth", "peer", "name", "p0", "netns", &ns.0,
        ],
        None,
    );
    ns.exec(&["ip", "link", "set", "lo", "up"], None);
    ns.exec(&["ip", "link", "set", "p0", "up"], None);
}

/// Echo servers on `ports`, up when this returns.
pub fn echo(ns: &Netns, ports: &[&str]) -> Background {
    let mut argv = vec!["python3", "-c", ECHO];
    argv.extend(ports);
    let server = ns.spawn(&argv);
    assert_eq!(server.expect_line("echo server").trim(), "ready");
    server
}

impl World {
    pub async fn new() -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "warn".into()),
            )
            .with_test_writer()
            .try_init();
        let pg = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .expect("start postgres (is Docker running?)");
        let port = pg.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let db = Database::connect(&url).await.expect("connect");
        wgate_db::migrate(&db).await.expect("migrate");

        let hub = Netns::new("hub");
        for argv in [
            &["sysctl", "-qw", "net.ipv4.ip_forward=1"][..],
            &["ip", "link", "set", "lo", "up"],
            // A fixed MAC: by default a bridge takes its lowest port's, so a client
            // joining later would leave the others' ARP entries stale.
            &[
                "ip",
                "link",
                "add",
                "br0",
                "address",
                "02:00:00:00:00:01",
                "type",
                "bridge",
            ],
            &["ip", "addr", "add", "198.51.100.1/24", "dev", "br0"],
            &["ip", "link", "set", "br0", "up"],
            &["ip", "link", "add", "infra0", "type", "dummy"],
            &["ip", "addr", "add", "172.16.16.1/32", "dev", "infra0"],
            &["ip", "link", "set", "infra0", "up"],
        ] {
            hub.exec(argv, None);
        }
        let side = |tag: &str, iface: &str, hub_addr: &str, addr: &str, gw: Option<&str>| {
            let ns = Netns::new(tag);
            veth(&hub, &ns, iface);
            hub.exec(&["ip", "addr", "add", hub_addr, "dev", iface], None);
            hub.exec(&["ip", "link", "set", iface, "up"], None);
            ns.exec(&["ip", "addr", "add", addr, "dev", "p0"], None);
            if let Some(gw) = gw {
                ns.exec(&["ip", "route", "add", "default", "via", gw], None);
            }
            ns
        };
        let node = side("node", "eth-node", "172.19.9.10/24", "172.19.9.11/24", None);
        let pod = side(
            "pod",
            "eth-pod",
            "10.244.0.1/24",
            "10.244.0.5/24",
            Some("10.244.0.1"),
        );
        let servers = vec![
            echo(&hub, &["6443", "22"]),
            echo(&node, &["8080"]),
            echo(&pod, &["7000"]),
        ];

        let net = |s: &str| s.parse().expect("cidr");
        let keys = tempfile::tempdir().expect("keys dir");
        let agent = wgate_agent::Config {
            database_url: url.clone(),
            pool: vec![net(POOL)],
            routed_space: ROUTED.map(net).to_vec(),
            reserved: RESERVED.map(net).to_vec(),
            snat_source: SNAT.parse().expect("addr"),
            node_cidrs: vec![net(NODES)],
            keys_dir: keys.path().join("keys"),
            state_file: keys.path().join("state.json"),
            reconcile_interval_secs: 60,
        };
        let mut server: wgate_server::Config =
            toml::from_str(include_str!("../../../server/server.example.toml")).unwrap();
        server.database_url = url;
        server.public_url = "http://portal.test".parse().unwrap();
        server.endpoint_host = ENDPOINT.into();
        server.pool = agent.pool.clone();
        server.routed_space = agent.routed_space.clone();
        server.reserved = agent.reserved.clone();
        server.snat_source = agent.snat_source;
        server.node_cidrs = agent.node_cidrs.clone();
        let app = wgate_server::router(AppState::new(db.clone(), server).unwrap());
        let admin = api::sign_in(&db, &app, "root@wgate.test", "global_admin", None).await;
        let runner = System::in_netns(&hub.0);
        let task = tokio::spawn(async move {
            if let Err(e) = wgate_agent::run(agent, runner).await {
                panic!("agent: {e:#}");
            }
        });
        Self {
            _agent: Agent(task),
            _servers: servers,
            hub,
            node,
            pod,
            db,
            app,
            admin,
            hosts: AtomicU8::new(2),
            _keys: keys,
            _pg: pg,
        }
    }

    /// Waits until the agent applied the current revision, without an error.
    pub async fn settle(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (_, s) = self.admin.get("/status").await;
            let (rev, applied) = (s["revision"].as_i64(), s["applied_revision"].as_i64());
            if applied >= rev && applied.is_some() {
                assert!(!s["failing"].as_bool().unwrap(), "the agent failed: {s}");
                return;
            }
            assert!(Instant::now() < deadline, "the agent did not catch up: {s}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// A tenant with one block: (tenant, block).
    pub async fn tenant(&self, slug: &str, block: &str) -> (i64, i64) {
        let t = id(&self
            .admin
            .create("/tenants", json!({ "slug": slug, "name": slug }))
            .await);
        let b = self
            .admin
            .create(&format!("/tenants/{t}/blocks"), json!({ "cidr": block }))
            .await;
        (t, id(&b))
    }

    /// A network, up on the hub when this returns.
    pub async fn network(&self, tenant: (i64, i64), slug: &str, cidr: &str, port: u16) -> i64 {
        let body = json!({ "tenant_id": tenant.0, "block_id": tenant.1, "slug": slug,
                           "name": slug, "cidr": cidr, "port": port });
        let n = id(&self.admin.create("/networks", body).await);
        self.settle().await;
        n
    }

    /// A tenant user's device.
    pub async fn device(&self, tenant: i64, name: &str) -> i64 {
        let email = format!("{name}@t{tenant}.test");
        let body = json!({ "tenant_id": tenant, "email": email, "role": "user" });
        let user = id(&self.admin.create("/users", body).await);
        id(&self
            .admin
            .create("/devices", json!({ "user_id": user, "name": name }))
            .await)
    }

    /// A peer with a server-made key, applied by the hub: (peer, its config).
    pub async fn peer(
        &self,
        device: i64,
        network: i64,
        ip: &str,
        routes: &[&str],
    ) -> (i64, String) {
        let body =
            json!({ "device_id": device, "network_id": network, "ip": ip, "routes": routes });
        let v = self.admin.create("/peers", body).await;
        let peer = id(&v["peer"]);
        let config = match v["config"]["config"].as_str() {
            Some(c) => c.to_owned(),
            None => {
                // The hub key is not published yet: once it is, a download (which
                // rotates the key) has the config.
                self.settle().await;
                let v = self
                    .admin
                    .expect(
                        axum::http::StatusCode::OK,
                        Method::POST,
                        &format!("/peers/{peer}/config"),
                        Some(json!({})),
                    )
                    .await;
                v["config"]["config"].as_str().expect("a config").to_owned()
            }
        };
        self.settle().await;
        (peer, config)
    }

    /// A client namespace for `config`, on the underlay and up.
    pub fn host(&self, tag: &str, config: &str) -> Host {
        let n = self.hosts.fetch_add(1, Ordering::Relaxed);
        let ns = Netns::new(tag);
        let iface = format!("ul{n}");
        veth(&self.hub, &ns, &iface);
        self.hub
            .exec(&["ip", "link", "set", &iface, "master", "br0", "up"], None);
        ns.exec(
            &[
                "ip",
                "addr",
                "add",
                &format!("198.51.100.{n}/24"),
                "dev",
                "p0",
            ],
            None,
        );
        wg::up(&ns, config);
        Host {
            _echo: echo(&ns, &["7000"]),
            ns,
        }
    }

    /// A peer and its client namespace.
    pub async fn peer_host(&self, tag: &str, device: i64, network: i64, ip: &str) -> (i64, Host) {
        let (peer, config) = self.peer(device, network, ip, &[]).await;
        (peer, self.host(tag, &config))
    }

    /// `POST` as the global admin, then wait for the agent.
    pub async fn admin_create(&self, uri: &str, body: Value) -> Value {
        let v = self.admin.create(uri, body).await;
        self.settle().await;
        v
    }
}
