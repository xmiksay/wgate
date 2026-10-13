//! The agent loop: reconcile on every `wgate_changed` notification and on a timer.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use sea_orm::{Database, DatabaseConnection};
use tokio::time::MissedTickBehavior;
use wgate_core::{Id, compile};
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
    let mut published = HashMap::new();
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
            // The timer rewrites every hub key: a row lost meanwhile comes back.
            _ = tick.tick() => published.clear(),
            note = next(&mut listener) => {
                if let Err(e) = note {
                    tracing::warn!(error = %e, "LISTEN connection lost");
                    listener = None;
                }
            }
        }
        // A database outage leaves the kernel as it is: the VPN keeps running.
        if let Err(e) = reconcile_once(&db, &config, runner.clone(), &mut published).await {
            tracing::error!(error = format!("{e:#}"), "reconcile failed");
        }
    }
}

/// Waits for a notification. A lost connection (`try_recv` → `None`; sqlx then
/// reconnects) also wakes us: notifications sent meanwhile are gone, so reconcile now
/// rather than at the next tick. Whatever else is already queued is drained (for at
/// most a second), so a burst of changes costs one reconcile.
async fn next(listener: &mut Option<Listener>) -> Result<(), ListenError> {
    let Some(l) = listener else {
        return std::future::pending().await;
    };
    l.try_recv().await?;
    // Bounded: a steady stream of changes must not hold every reconcile off.
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    while tokio::time::Instant::now() < until
        && let Ok(Ok(Some(_))) = tokio::time::timeout(Duration::from_millis(50), l.try_recv()).await
    {
    }
    Ok(())
}

/// One load → compile → apply → report round. `published` remembers the hub keys
/// already written, so an unchanged key costs no write.
pub async fn reconcile_once<R: Runner + Send + Sync + 'static>(
    db: &DatabaseConnection,
    config: &Config,
    runner: Arc<R>,
    published: &mut HashMap<Id, String>,
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
    problems.extend(outcome.errors);
    for (network, key) in outcome.hub_keys {
        if published.get(&network) == Some(&key) {
            continue;
        }
        // A network deleted meanwhile (its row is gone) must not cost the status.
        match wgate_db::agent::set_hub_key(db, network, &key).await {
            Ok(()) => {
                published.insert(network, key);
            }
            Err(e) => problems.push(format!("network {network}: hub key: {e}")),
        }
    }
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
