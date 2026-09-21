/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Builds the genesis state and writes the frozen manifest.
//!
//! Usage: `genesis <repo root> <output manifest> [<source commit> <source blob>]`
//!
//! The parameters are `development_parameters`, which lives in the library
//! because the on-chain fixture deploys the same state to a real node, and a
//! second copy of the constants would be a second deployment.

use std::path::PathBuf;

use shielded_pool_genesis::manifest::{self, Provenance};
use shielded_pool_genesis::{build, development_parameters};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let root =
        PathBuf::from(args.next().ok_or("usage: genesis <repo root> <output> [commit blob]")?);
    let output =
        PathBuf::from(args.next().ok_or("usage: genesis <repo root> <output> [commit blob]")?);
    let source_commit = args.next().unwrap_or_else(|| "unknown".to_string());
    let source_blob = args.next().unwrap_or_else(|| "unknown".to_string());

    let genesis = build(development_parameters(&root)?)?;

    let rendered = manifest::render(&genesis, &Provenance { source_commit, source_blob }, None)?;
    std::fs::write(&output, &rendered)?;
    eprintln!("state hash {}", hex(&manifest::cell_hash(&genesis.state)));
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
