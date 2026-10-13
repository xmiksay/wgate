//! The agent loop: reconcile on every `wgate_changed` notification and on a timer.

use std::sync::Arc;

use anyhow::Context;
use sea_orm::{Database, DatabaseConnection};
use tokio::time::MissedTickBehavior;
use wgate_core::compile;
use wgate_db::revision::{self, ListenError, Listener};

use crate::config::Config;
use crate::reconcile::reconcile;
use crate::runner::Runner;

pub async fn run<R: Runner + Send + Sync + 'static>(
    config: Config,
    runner: R,
) -> anyhow::Result<()> {
    let db = Database::connect(&config.database_url)
        .await
        .context("connect to the database")?;
    let runner = Arc::new(runner);
    let mut listener: Option<Listener> = None;
    let mut tick = tokio::time::interval(config.interval());
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        if listener.is_none() {
            // Without it the timer still reconciles; changes just wait for the tick.
            match revision::listener(&config.database_url).await {
                Ok(l) => listener = Some(l),
                Err(e) => tracing::warn!(error = %e, "LISTEN failed; relying on the timer"),
            }
        }
        tokio::select! {
            _ = tick.tick() => {}
            note = next(&mut listener) => {
                if let Err(e) = note {
                    tracing::warn!(error = %e, "LISTEN connection lost");
                    listener = None;
                }
            }
        }
        // A database outage leaves the kernel as it is: the VPN keeps running.
        if let Err(e) = reconcile_once(&db, &config, runner.clone()).await {
            tracing::error!(error = format!("{e:#}"), "reconcile failed");
        }
    }
}

async fn next(listener: &mut Option<Listener>) -> Result<(), ListenError> {
    match listener {
        Some(l) => l.recv().await.map(drop),
        None => std::future::pending().await,
    }
}

/// One load → compile → apply → report round.
pub async fn reconcile_once<R: Runner + Send + Sync + 'static>(
    db: &DatabaseConnection,
    config: &Config,
    runner: Arc<R>,
) -> anyhow::Result<()> {
    let loaded = wgate_db::desired_state(db, &config.infra())
        .await
        .context("load the desired state")?;
    let compiled = compile(&loaded.state);
    let mut problems: Vec<String> = loaded.warnings.clone();
    problems.extend(
        compiled
            .invalid_blocks
            .iter()
            .map(|id| format!("tenant_block {id}: invalid")),
    );
    problems.extend(
        compiled
            .invalid_networks
            .iter()
            .map(|id| format!("network {id}: invalid")),
    );
    problems.extend(
        compiled
            .skipped
            .iter()
            .map(|(id, p)| format!("peer {id}: {p:?}")),
    );
    problems.extend(
        compiled
            .dropped_routes
            .iter()
            .map(|(id, p)| format!("peer_route {id}: {p:?}")),
    );

    let keys_dir = config.keys_dir.clone();
    let outcome = tokio::task::spawn_blocking(move || reconcile(&*runner, &compiled, &keys_dir))
        .await
        .context("reconcile task")?;
    for (network, key) in &outcome.hub_keys {
        wgate_db::agent::set_hub_key(db, *network, key)
            .await
            .context("record a hub key")?;
    }
    problems.extend(outcome.errors);
    for p in &problems {
        tracing::warn!(problem = %p, "not applied");
    }
    let error = (!problems.is_empty()).then(|| problems.join("\n"));
    wgate_db::agent::record_status(db, loaded.revision, error.as_deref())
        .await
        .context("record the agent status")?;
    tracing::info!(
        revision = loaded.revision,
        problems = problems.len(),
        "applied"
    );
    Ok(())
}
