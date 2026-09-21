/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Prints the byte ranges a phase-1 slice occupies, as JSON.
//!
//!     phase1-ranges <exponent>
//!
//! The fetcher reads them from here rather than recomputing them. Two copies
//! of this arithmetic would be two chances to get it wrong, and this is the
//! copy with the published file size behind it.

use std::process::ExitCode;

use shielded_pool_ceremony::layout;

fn run() -> shielded_pool_ceremony::Result<String> {
    let exponent: u32 =
        std::env::args().nth(1).and_then(|argument| argument.parse().ok()).ok_or_else(|| {
            shielded_pool_ceremony::Error::Layout("usage: phase1-ranges <exponent>".into())
        })?;
    let ranges = layout::slice_ranges(layout::CHALLENGE_POWER, exponent)?;
    let entries: Vec<serde_json::Value> = ranges
        .iter()
        .map(|range| {
            serde_json::json!({
                "name": range.name,
                "offset": range.offset,
                "length": range.length,
                "points": range.points,
            })
        })
        .collect();
    Ok(serde_json::to_string_pretty(&entries)?)
}

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
