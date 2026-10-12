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
    Server,
    /// Reconciler: wg interfaces, peers and `table inet wgate` (CAP_NET_ADMIN)
    Agent,
    /// Apply database migrations
    Migrate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let name = match Cli::parse().command {
        Command::Server => "server",
        Command::Agent => "agent",
        Command::Migrate => "migrate",
    };
    anyhow::bail!("`wgate {name}` is not implemented yet")
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
