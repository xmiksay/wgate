//! Address ownership and column checks against a real Postgres (Docker).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{BASE, KEY, ok, pg, refused};

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
}

#[tokio::test]
async fn tenants_may_share_an_identity_provider() {
    let pg = pg("").await;
    ok(&pg.db, BASE).await;
    ok(
        &pg.db,
        "INSERT INTO oidc_provider (tenant_id, issuer, client_id) VALUES
            (1, 'https://accounts.google.com', 'a'), (2, 'https://accounts.google.com', 'b'),
            (NULL, 'https://accounts.google.com', 'admin')",
    )
    .await;
    refused(
        &pg.db,
        "INSERT INTO oidc_provider (tenant_id, issuer, client_id) VALUES (NULL, 'https://x', 'y')",
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
    // A block cannot be removed under its networks, and blocks never change.
    refused(&pg.db, "DELETE FROM tenant_block WHERE tenant_id = 2").await;
    refused(
        &pg.db,
        "UPDATE tenant_block SET cidr = '10.50.1.128/25' WHERE tenant_id = 2",
    )
    .await;
    ok(&pg.db, "DELETE FROM network WHERE tenant_id = 2").await;
    ok(&pg.db, "DELETE FROM tenant_block WHERE tenant_id = 2").await;
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
