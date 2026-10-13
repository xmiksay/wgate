use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Multi-tenant WireGuard gateway")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Portal: REST API + UI (unprivileged)
    Server {
        #[arg(
            long,
            env = "WGATE_SERVER_CONFIG",
            default_value = "/etc/wgate/server.toml"
        )]
        config: std::path::PathBuf,
    },
    /// Global admins
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
        /// Postgres URL (as for `migrate`)
        #[arg(long, env = "WGATE_DATABASE_URL", hide_env_values = true)]
        database_url: String,
    },
    /// Reconciler: wg interfaces, peers and `table inet wgate` (CAP_NET_ADMIN)
    Agent {
        #[arg(
            long,
            env = "WGATE_AGENT_CONFIG",
            default_value = "/etc/wgate/agent.toml"
        )]
        config: std::path::PathBuf,
    },
    /// Apply database migrations (as the owner role, before the units restart)
    Migrate {
        /// Postgres URL; direct to Postgres, not through pgbouncer
        #[arg(long, env = "WGATE_DATABASE_URL", hide_env_values = true)]
        database_url: String,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Make <email> a global admin (or enable one again); they log in with it
    Grant { email: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // sqlx logs every statement at info.
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Server { config } => {
            wgate_server::serve(wgate_server::Config::load(&config)?).await
        }
        Command::Admin {
            command: AdminCommand::Grant { email },
            database_url,
        } => {
            let db = sea_orm::Database::connect(&database_url)
                .await
                .context("connect to the database")?;
            let id = wgate_server::grant_admin(&db, &email).await?;
            tracing::info!(user = id, %email, "global admin granted");
            Ok(())
        }
        Command::Agent { config } => {
            let config = wgate_agent::Config::load(&config)?;
            wgate_agent::run(config, wgate_agent::System::default()).await
        }
        Command::Migrate { database_url } => migrate(&database_url).await,
    }
}

async fn migrate(database_url: &str) -> anyhow::Result<()> {
    let applied = wgate_db::migrate_url(database_url)
        .await
        .context("apply migrations")?;
    tracing::info!(?applied, "migrations up to date");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }
}
