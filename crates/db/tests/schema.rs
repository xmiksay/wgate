//! Address ownership and column checks against a real Postgres (Docker).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{BASE, KEY, ok, pg, refused};
use sea_orm::ConnectionTrait;

#[tokio::test]
async fn ranges_are_exclusive() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    // Blocks, networks and routes never overlap, whoever claims them.
    refused(
        &pg.db,
        "INSERT INTO tenant_block (tenant_id, cidr) VALUES (2, '10.50.0.128/25')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO network (tenant_id, block_id, slug, name, cidr, port) VALUES (1, 1, 'other', 'x', '10.50.0.64/26', 51802)",
    )
    .await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip)
                 VALUES (1, 1, 1, '{KEY}', '10.50.0.2');
             INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')"
        ),
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.0.0/23')",
    )
    .await;
}

#[tokio::test]
async fn columns_are_checked() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let network = |slug: &str, cidr: &str, port: u32| {
        format!(
            "INSERT INTO network (tenant_id, block_id, slug, name, cidr, port) VALUES (1, 1, '{slug}', 'x', '{cidr}', {port})"
        )
    };
    refused(&pg.db, &network("-bad", "10.50.0.128/28", 51802)).await;
    refused(&pg.db, &network("waytoolongslug", "10.50.0.128/28", 51802)).await;
    refused(&pg.db, &network("p20", "10.50.0.128/28", 51820)).await;
    refused(&pg.db, &network("p99", "10.50.0.128/28", 51900)).await;
    refused(&pg.db, &network("p01", "10.50.0.128/28", 51801)).await;
    refused(&pg.db, &network("tiny", "10.50.0.128/31", 51802)).await;
    ok(&pg.db, &network("ok", "10.50.0.128/28", 51802)).await;

    let rule = |proto: &str, from: &str, to: &str, dst: &str, target: &str| {
        format!(
            "INSERT INTO rule (tenant_id, network_id, proto, port_from, port_to, dst, target_network_id)
             VALUES (1, 1, '{proto}', {from}, {to}, {dst}, {target})"
        )
    };
    ok(
        &pg.db,
        &rule("tcp", "6443", "6443", "'172.16.16.1/32'", "NULL"),
    )
    .await;
    ok(&pg.db, &rule("icmp", "NULL", "NULL", "NULL", "1")).await;
    refused(&pg.db, &rule("icmp", "1", "2", "'172.16.16.1/32'", "NULL")).await;
    refused(
        &pg.db,
        &rule("tcp", "NULL", "NULL", "'172.16.16.1/32'", "NULL"),
    )
    .await;
    refused(&pg.db, &rule("tcp", "0", "80", "'172.16.16.1/32'", "NULL")).await;
    refused(&pg.db, &rule("tcp", "90", "80", "'172.16.16.1/32'", "NULL")).await;
    refused(&pg.db, &rule("sctp", "1", "2", "'172.16.16.1/32'", "NULL")).await;
    refused(&pg.db, &rule("tcp", "1", "2", "'172.16.16.1/32'", "1")).await;
    refused(&pg.db, &rule("tcp", "1", "2", "NULL", "NULL")).await;

    // Roles: global admins have no tenant, everyone else has one.
    refused(
        &pg.db,
        "INSERT INTO app_user (tenant_id, email, role) VALUES (1, 'x@y', 'global_admin')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO app_user (email, role) VALUES ('x@y', 'user')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO app_user (tenant_id, email, role) VALUES (1, 'A@NEXIAL.CZ', 'user')",
    )
    .await;
    // One account per email across wgate: not in another tenant, nor as an admin.
    refused(
        &pg.db,
        "INSERT INTO app_user (tenant_id, email, role) VALUES (2, 'a@nexial.cz', 'user')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO app_user (email, role) VALUES ('A@nexial.cz', 'global_admin')",
    )
    .await;
}

#[tokio::test]
async fn tenants_may_share_an_identity_provider() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        "INSERT INTO oidc_provider (tenant_id, name, issuer, client_id, client_secret) VALUES
            (1, 'Google', 'https://accounts.google.com', 'a', '\\x01'),
            (2, 'Google', 'https://accounts.google.com', 'b', '\\x01'),
            (NULL, 'Google', 'https://accounts.google.com', 'admin', '\\x01'),
            (NULL, 'Keycloak', 'https://kc.example.org/realms/x', 'y', '\\x01')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO oidc_provider (tenant_id, name, issuer, client_id, client_secret)
         VALUES (NULL, 'GOOGLE', 'https://x', 'y', '\\x01')",
    )
    .await;
}

#[tokio::test]
async fn tenant_blocks_are_ipv4() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    refused(
        &pg.db,
        "INSERT INTO tenant_block (tenant_id, cidr) VALUES (1, 'fd00::/64')",
    )
    .await;
}

#[tokio::test]
async fn networks_stay_inside_their_tenants_blocks() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let network = |tenant: u32, block: u32, cidr: &str| {
        format!(
            "INSERT INTO network (tenant_id, block_id, slug, name, cidr, port) VALUES ({tenant}, {block}, 'n2', 'x', '{cidr}', 51802)"
        )
    };
    // In tenant 2's block, and in no block at all.
    refused(&pg.db, &network(1, 1, "10.50.1.0/28")).await;
    refused(&pg.db, &network(1, 2, "10.50.1.0/28")).await;
    refused(&pg.db, &network(1, 1, "10.50.9.0/28")).await;
    ok(&pg.db, &network(2, 2, "10.50.1.0/28")).await;
    // Blocks never change; removing one takes its networks along.
    refused(
        &pg.db,
        "UPDATE tenant_block SET cidr = '10.50.1.128/25' WHERE tenant_id = 2",
    )
    .await;
    ok(&pg.db, "DELETE FROM tenant_block WHERE tenant_id = 2").await;
    let left = pg
        .db
        .query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT count(*) AS n FROM network WHERE tenant_id = 2",
        ))
        .await
        .expect("query")
        .expect("row");
    assert_eq!(left.try_get::<i64>("", "n").expect("n"), 0);
}

#[tokio::test]
async fn deleting_a_tenant_cascades_through_everything() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES (1, 1, 1, '{KEY}', '10.50.0.2');
             INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')"
        ),
    )
    .await;
    ok(&pg.db, "DELETE FROM tenant WHERE id = 1").await;
}

#[tokio::test]
async fn rules_stay_inside_their_tenant() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        "INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port)
             VALUES (2, 2, 2, 'krcmar', 'Krcmar', '10.50.1.0/24', 51802)",
    )
    .await;
    let rule = |tenant: u32, network: u32, target: u32| {
        format!(
            "INSERT INTO rule (tenant_id, network_id, proto, port_from, port_to, target_network_id)
             VALUES ({tenant}, {network}, 'tcp', 22, 22, {target})"
        )
    };
    refused(&pg.db, &rule(1, 1, 2)).await;
    refused(&pg.db, &rule(2, 1, 2)).await;
    ok(&pg.db, &rule(1, 1, 1)).await;
}

#[tokio::test]
async fn federations_link_two_tenants() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        "INSERT INTO tenant_block (id, tenant_id, cidr) VALUES (3, 1, '10.50.2.0/24');
         INSERT INTO network (id, tenant_id, block_id, slug, name, cidr, port) VALUES
             (2, 2, 2, 'krcmar', 'Krcmar', '10.50.1.0/24', 51802),
             (3, 1, 3, 'nexial2', 'Nexial 2', '10.50.2.0/24', 51803)",
    )
    .await;
    let federation = |from: u32, to: u32| {
        format!(
            "INSERT INTO federation (from_network_id, to_network_id, proto, port_from, port_to)
             VALUES ({from}, {to}, 'tcp', 443, 443)"
        )
    };
    refused(&pg.db, &federation(1, 1)).await;
    refused(&pg.db, &federation(1, 3)).await;
    ok(&pg.db, &federation(1, 2)).await;
}

#[tokio::test]
async fn routed_lans_and_tenant_blocks_never_overlap() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        &format!(
            "INSERT INTO peer (id, device_id, network_id, public_key, ip) VALUES (1, 1, 1, '{KEY}', '10.50.0.2');
             INSERT INTO peer_route (peer_id, cidr) VALUES (1, '192.168.1.0/24')"
        ),
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO peer_route (peer_id, cidr) VALUES (1, '10.50.0.0/16')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO tenant_block (id, tenant_id, cidr) VALUES (9, 1, '192.168.0.0/16')",
    )
    .await;
    // Once the route is gone (revoked), the range is free for a block.
    ok(&pg.db, "UPDATE peer SET revoked_at = now()").await;
    ok(
        &pg.db,
        "INSERT INTO tenant_block (id, tenant_id, cidr) VALUES (9, 1, '192.168.0.0/16')",
    )
    .await;
}

#[tokio::test]
async fn only_an_active_server_key_rotates_and_dns_takes_hosts() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    let other = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";
    ok(
        &pg.db,
        &format!(
            "INSERT INTO device (id, user_id, name) VALUES (2, 1, 'phone');
             INSERT INTO peer (id, device_id, network_id, public_key, key_source, ip)
                 VALUES (1, 1, 1, '{KEY}', 'server', '10.50.0.2/32'),
                        (2, 2, 1, '{other}', 'pasted', '10.50.0.3/32')"
        ),
    )
    .await;
    let rotated = "000000000000000000000000000000000000000001A=";
    ok(
        &pg.db,
        &format!("UPDATE peer SET public_key = '{rotated}' WHERE id = 1"),
    )
    .await;
    // A pasted key is the user's: never rotated; nor is a revoked peer's, nor the source.
    refused(
        &pg.db,
        &format!("UPDATE peer SET public_key = '{rotated}' WHERE id = 2"),
    )
    .await;
    refused(&pg.db, "UPDATE peer SET key_source = 'server' WHERE id = 2").await;
    ok(&pg.db, "UPDATE peer SET revoked_at = now() WHERE id = 1").await;
    refused(
        &pg.db,
        &format!("UPDATE peer SET public_key = '{KEY}' WHERE id = 1"),
    )
    .await;
    ok(
        &pg.db,
        "UPDATE network SET dns = '{10.50.0.1, 1.1.1.1}' WHERE id = 1",
    )
    .await;
    refused(
        &pg.db,
        "UPDATE network SET dns = '{10.50.0.0/24}' WHERE id = 1",
    )
    .await;
    refused(&pg.db, "UPDATE network SET dns = '{::1}' WHERE id = 1").await;
}
