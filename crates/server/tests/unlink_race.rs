//! Two unlinks of an account's last two ways in, at once: one must be refused. Both
//! are held on the account's row lock until each waits for it, so they really race.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::idp;
use common::login::{self, one, tenant};
use common::oidc::{self as flow, provider, who};
use common::{sign_in, sql};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement, TransactionTrait};

const SECRET: &str = "client-secret";

#[tokio::test]
async fn two_unlinks_at_once_leave_a_way_in() {
    let (ia, ig) = (idp::start("a", SECRET).await, idp::start("g", SECRET).await);
    let e = common::env().await;
    let g = sign_in(&e, "g@x.test", "global_admin", None).await;
    let t = tenant(&e.db, "acme").await;
    let pa = provider(&g, &ia, Some(t), "Acme SSO", false).await;
    let pg = provider(&g, &ig, None, "Google", false).await;
    // No password: the two identities are its only ways in.
    let n = one(
        &e.db,
        &format!(
            "INSERT INTO app_user (tenant_id, email, role) VALUES ({t}, 'n@acme.test', 'user')
             RETURNING id"
        ),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    sql(
        &e.db,
        &format!(
            "INSERT INTO identity (user_id, provider_id, subject) VALUES
                 ({n}, {pa}, 'a'), ({n}, {pg}, 'g')"
        ),
    )
    .await;
    // Two sessions of the account, one through each.
    let via_a = flow::login(&e.app, &ia, pa, who("a", "", false))
        .await
        .unwrap();
    let via_g = flow::login(&e.app, &ig, pg, who("g", "", false))
        .await
        .unwrap();
    let (ca, cg) = (
        login::client(&e.app, &via_a).await,
        login::client(&e.app, &via_g).await,
    );
    let (_, ids) = ca.get("/me/identities").await;
    let id_of = |p: i64| {
        ids.as_array()
            .unwrap()
            .iter()
            .find(|i| i["provider_id"] == p)
            .unwrap()["id"]
            .as_i64()
            .unwrap()
    };
    let (ida, idg) = (id_of(pa), id_of(pg));

    // Someone else holds the account's row: both unlinks queue behind it.
    let holder = Database::connect(&e.url).await.unwrap();
    let txn = holder.begin().await.unwrap();
    txn.execute_unprepared(&format!(
        "SELECT id FROM app_user WHERE id = {n} FOR UPDATE"
    ))
    .await
    .unwrap();
    let ra = tokio::spawn(async move { ca.delete(&format!("/me/identities/{ida}")).await });
    let rg = tokio::spawn(async move { cg.delete(&format!("/me/identities/{idg}")).await });
    let waiting = async {
        loop {
            let row =
                e.db.query_one_raw(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT count(*) AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock'",
                ))
                .await
                .unwrap()
                .unwrap();
            if row.try_get::<i64>("", "n").unwrap() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("both unlinks wait for the account");
    txn.rollback().await.unwrap();

    let mut got = [ra.await.unwrap().0, rg.await.unwrap().0];
    got.sort();
    assert_eq!(
        got,
        [StatusCode::NO_CONTENT, StatusCode::UNPROCESSABLE_ENTITY]
    );
    let left = one(
        &e.db,
        &format!("SELECT count(*) AS n FROM identity WHERE user_id = {n}"),
    )
    .await;
    assert_eq!(left["n"], 1, "a way in is left");
}
