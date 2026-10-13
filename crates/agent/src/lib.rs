//! Privileged reconciler: wg interfaces/peers and `table inet wgate`, network by
//! network, from the desired state in the database.

pub mod config;
mod keys;
mod nftmap;
mod private;
mod reconcile;
mod routes;
pub mod run;
pub mod runner;
mod state;
mod wg;

pub use config::Config;
pub use reconcile::{Outcome, reconcile, reconcile_after};
pub use run::{Memory, apply_saved, reconcile_once, run};
pub use runner::{Runner, System};
