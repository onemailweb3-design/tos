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
//! The parameters below are the development deployment's. Production values
//! are a separate decision -- the fee follows from section 14.2's measured
//! floor and the denominations are a product matter -- and changing any of
//! them changes the state hash, which is the whole point of freezing it.

use std::path::PathBuf;

use shielded_pool_genesis::manifest::{self, Provenance};
use shielded_pool_genesis::{build, Parameters};

/// Development values. Section 14.2's measured floor for a bounded recovery is
/// 205,313,600 at the current fee schedule, so this clears it; production must
/// choose with explicit headroom and its own measurement.
const RESERVE_FLOOR: u128 = 5_000_000_000;
/// Re-derived on 2026-09-21 when the basechain prices were aligned with TON
/// mainnet's live values. Section 14.2's floor -- the payout's forward fee
/// plus a whole bounded recovery at the bounce ceiling -- is 19,552,270,
/// measured by `shielded_payout_sandbox`. This is that with a 2.56x margin,
/// rounded to a hundredth of a TOS.
///
/// The floor moved again when the Poseidon2 tariff came down and the bounce
/// ceiling with it, from 20,218,937 to this. The fee did not need to follow:
/// 2.47x became 2.56x, which is still the margin it was set for.
///
/// The old 250,000,000 was 2.06x the floor it was set against; the same
/// number against the new floor would have been 12.4x, and the fee would have
/// become two thirds of what a withdrawal costs its sender.
const WITHDRAWAL_FEE: u128 = 50_000_000;
const DENOMINATIONS: [u128; 4] =
    [1_000_000_000, 10_000_000_000, 100_000_000_000, 1_000_000_000_000];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let root =
        PathBuf::from(args.next().ok_or("usage: genesis <repo root> <output> [commit blob]")?);
    let output =
        PathBuf::from(args.next().ok_or("usage: genesis <repo root> <output> [commit blob]")?);
    let source_commit = args.next().unwrap_or_else(|| "unknown".to_string());
    let source_blob = args.next().unwrap_or_else(|| "unknown".to_string());

    // The profile copy, read as bytes and normalised to LF exactly as section
    // 13.1 specifies. Reading it rather than taking a hash on trust is what
    // makes the manifest checkable.
    let profile_path = root.join("doc/shielded-pool-v1-profile.md");
    let profile_bytes = std::fs::read(&profile_path)
        .map_err(|error| format!("{}: {error}", profile_path.display()))?;
    let profile_bytes = normalise(&profile_bytes);

    let poseidon_manifest_bytes = std::fs::read(root.join("crypto/poseidon2/manifest.bin"))?;

    // The development verifying key. Section 19 gate 5 requires a production
    // ceremony to replace it before activation, and the manifest says which
    // one it used.
    let fixture = std::fs::read_to_string(
        root.join("tools/shielded-pool-circuit/fixtures/groth16-development.json"),
    )?;
    let verifying_key = extract_vk(&fixture)?;

    let genesis = build(Parameters {
        profile_bytes,
        poseidon_manifest_bytes,
        verifying_key,
        reserve_floor: RESERVE_FLOOR,
        withdrawal_fee: WITHDRAWAL_FEE,
        denominations: DENOMINATIONS.to_vec(),
    })?;

    let rendered = manifest::render(&genesis, &Provenance { source_commit, source_blob }, None)?;
    std::fs::write(&output, &rendered)?;
    eprintln!("state hash {}", hex(&manifest::cell_hash(&genesis.state)));
    eprintln!("wrote {}", output.display());
    Ok(())
}

/// Section 13.1: line endings normalised to LF, nothing else touched.
fn normalise(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            index += 1;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// The 1248-byte stream out of the fixture, without pulling in a JSON parser
/// for one field.
fn extract_vk(fixture: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let at = fixture.find("\"hex\"").ok_or("no verifying key in the fixture")?;
    let rest = &fixture[at..];
    let open = rest.find(':').ok_or("malformed fixture")?;
    let quoted = &rest[open..];
    let first = quoted.find('"').ok_or("malformed fixture")?;
    let tail = &quoted[first + 1..];
    let end = tail.find('"').ok_or("malformed fixture")?;
    let hex = &tail[..end];
    (0..hex.len() / 2)
        .map(|index| {
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|error| format!("verifying key hex: {error}").into())
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
