//! The one source list the shielded pool is built from.
//!
//! Two suites deploy the same contract. When each kept its own list they
//! drifted: the deposit suite went on compiling a pool without the transact
//! libraries, so it was testing a contract that no longer existed. A suite
//! that deploys the pool must deploy the pool, not a subset of it, so the
//! list lives here and both suites call this.

use std::path::PathBuf;

/// Every FunC source of the shielded pool, in dependency order, ending with
/// the contract itself.
pub fn pool_sources() -> Vec<PathBuf> {
    let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont");
    [
        "shielded/domains.fc",
        "shielded/empty-roots.fc",
        "shielded/notes.fc",
        "shielded/tree.fc",
        "shielded/imt.fc",
        "shielded/auth.fc",
        "shielded/payload.fc",
        "shielded/domain.fc",
        "shielded/anchors.fc",
        "shielded/state.fc",
        "shielded/transact.fc",
        "shielded/groth16.fc",
        "shielded/payout.fc",
        "shielded/recovery.fc",
        "tos-shielded-pool-v1.fc",
    ]
    .into_iter()
    .map(|name| PathBuf::from(format!("{library}/{name}")))
    .collect()
}
