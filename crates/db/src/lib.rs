//! Postgres: SeaORM entities, migrations, the state revision + NOTIFY, and loading
//! the desired state. Shared by the server (writes) and the agent (reads).

pub mod agent;
pub mod entity;
mod load;
pub mod migration;
pub mod revision;

pub use load::{Infra, Loaded, desired_state};
pub use migration::{migrate, migrate_url};
