/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The slice actually fetched from the published transcript.
//!
//! Every other test here builds its own powers-of-tau from secrets it chose,
//! which is what lets them be broken on purpose -- and means none of them has
//! ever seen the real thing. This one has.
//!
//! **Ignored by default, and on purpose.** The artifact is eighteen megabytes
//! of somebody else's ceremony and is not in the repository, so a test that
//! ran unconditionally would either fail for everyone who has not fetched it
//! or, worse, skip quietly and pass. A test that passes while doing nothing is
//! the failure this repository's `CLAUDE.md` opens with. So: fetch it, then
//!
//!     cargo test --release --test the_real_slice -- --ignored
//!
//! Fetching:
//!
//!     uv run python scripts/shielded-pool-phase1-slice.py --out artifacts/phase1

use std::path::PathBuf;

use shielded_pool_ceremony::{lagrange, slice, verify};

const EXPONENT: u32 = 15;

/// The slice fetched on 2026-09-21, by the hash of its bytes.
///
/// Pinned so that "the real slice verifies" is a statement about a specific
/// eighteen megabytes and not about whatever happens to be on disk. A
/// different transcript, or the same one re-published, moves this.
const SLICE_SHA256: &str = "d161614630b0504bd02075a9f57e7ca18d24f0c7c911c5cda5a686e91b8ced75";

/// The 64 bytes the challenge file opens with: the transcript's own name for
/// itself, and what a deployment is held against the ceremony's attestations
/// by.
const TRANSCRIPT_HASH: &str = concat!(
    "6e3f4b98e6c205d0efa5abc917dd03e28864016df380936fa4e9865595c5d698",
    "63eff93e8badf8e6b8c8cbfd5ab3a415ef7ba50b86e124bd9bfcd3f9aab67124"
);

fn artifact() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    (root.join("artifacts/phase1/phase1-2m15.bin"), root.join("artifacts/phase1/phase1-2m15.json"))
}

fn load() -> (Vec<u8>, slice::Provenance) {
    let (bin, json) = artifact();
    let bytes = std::fs::read(&bin).unwrap_or_else(|error| {
        panic!(
            "{}: {error}\n\nFetch it first:\n  uv run python \
             scripts/shielded-pool-phase1-slice.py --out artifacts/phase1",
            bin.display()
        )
    });
    let record: slice::Provenance = serde_json::from_slice(
        &std::fs::read(&json).unwrap_or_else(|error| panic!("{}: {error}", json.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", json.display()));
    (bytes, record)
}

#[test]
#[ignore = "needs artifacts/phase1; see the module comment"]
fn the_fetched_slice_is_the_one_that_was_checked() {
    let (bytes, record) = load();
    assert_eq!(bytes.len(), 18_874_464, "the slice is not the size the layout gives");
    assert_eq!(
        record.slice_sha256, SLICE_SHA256,
        "this is not the slice these hashes were recorded from"
    );
    assert_eq!(record.transcript_hash, TRANSCRIPT_HASH, "a different transcript");
    assert_eq!(record.source_url, "https://trusted-setup.filecoin.io/phase1/challenge_19");
}

#[test]
#[ignore = "needs artifacts/phase1; see the module comment"]
fn the_fetched_slice_is_a_powers_of_tau_string() {
    let (bytes, record) = load();
    let parsed = slice::parse(&bytes, &record, EXPONENT).expect("the real slice must parse");
    assert_eq!(parsed.tau_g1.len(), 65_535);
    assert_eq!(parsed.tau_g2.len(), 32_768);
    verify::verify(&parsed, [0x5au8; 32]).expect("the real slice must verify");
}

/// And it can fail on the real thing, which is the only version of this claim
/// worth making.
///
/// Two *genuine* powers from the transcript, swapped. Every point is still a
/// point, still in the prime-order subgroup, and the sections still hash to
/// their record -- a corruption that survives everything except the pairing
/// checks. A flipped bit would be caught earlier and more cheaply by blst
/// refusing a point that is no longer on the curve, which proves the decoder
/// rather than the mathematics.
#[test]
#[ignore = "needs artifacts/phase1; see the module comment"]
fn two_real_powers_swapped_are_refused() {
    let (bytes, mut record) = load();
    let mut tampered = bytes.clone();
    let (i, j) = (40_000usize, 40_001usize);
    tampered[96 * i..96 * (i + 1)].copy_from_slice(&bytes[96 * j..96 * (j + 1)]);
    tampered[96 * j..96 * (j + 1)].copy_from_slice(&bytes[96 * i..96 * (i + 1)]);

    // Re-hash, so the cheap checks pass and only the mathematics can refuse.
    let rehashed = slice::describe(
        &tampered,
        &record.source_url,
        &record.transcript_hash,
        record.source_power,
        record.slice_power,
    )
    .expect("a record for the tampered bytes");
    record = rehashed;

    let parsed = slice::parse(&tampered, &record, EXPONENT)
        .expect("swapped genuine points still parse, which is the point");
    let error =
        verify::verify(&parsed, [0x5au8; 32]).expect_err("two powers out of order must be refused");
    assert!(
        format!("{error}").contains("not consecutive powers of one tau"),
        "refused for the wrong reason: {error}"
    );
}

/// The digest of the reference string phase 2 will start from.
///
/// The transform is a function of the slice, so this is determined by the
/// hashes above and by nothing else. It is pinned because a phase-2 transcript
/// has to record which reference string it built on, and twenty megabytes is
/// not a thing to record.
const SRS_DIGEST: &str = "b30791cf1925a9184e90d9088acbc8299ae172fd3ef9958d892065368325baba";

/// The real 2^15 Lagrange basis, computed from the real slice and checked
/// against it.
///
/// About five seconds to transform 131,839 points and a second and a half to
/// check the result -- which is why this is a step in the ceremony rather than
/// an artifact to store.
#[test]
#[ignore = "needs artifacts/phase1; see the module comment"]
fn the_real_slice_becomes_the_lagrange_basis_it_should() {
    let (bytes, record) = load();
    let parsed = slice::parse(&bytes, &record, EXPONENT).expect("the real slice must parse");
    let srs = lagrange::transform(&parsed).expect("the transform");

    assert_eq!(srs.degree(), 32_768, "the basis is not the circuit's domain");
    assert_eq!(srs.h.len(), 32_767, "the h query is not n-1 long");
    lagrange::verify(&parsed, &srs, [0xa5u8; 32]).expect("the real transform must verify");
    assert_eq!(
        lagrange::digest(&srs),
        SRS_DIGEST,
        "the reference string phase 2 would start from has moved"
    );
}

/// And the checks bite on the real thing too.
///
/// Two elements of the real basis swapped **in both groups**: the sum is
/// unchanged, the two groups still agree with each other, every point is
/// genuine and in the right subgroup. Only going back to the powers it was
/// built from can see it.
#[test]
#[ignore = "needs artifacts/phase1; see the module comment"]
fn a_permuted_real_basis_is_refused() {
    let (bytes, record) = load();
    let parsed = slice::parse(&bytes, &record, EXPONENT).expect("the real slice must parse");
    let mut srs = lagrange::transform(&parsed).expect("the transform");

    srs.coeffs_g1.swap(11_111, 22_222);
    srs.coeffs_g2.swap(11_111, 22_222);

    let error = lagrange::verify(&parsed, &srs, [0xa5u8; 32])
        .expect_err("a permuted real basis must be refused");
    assert!(
        format!("{error}").contains("disagrees with the powers it was built from"),
        "refused for the wrong reason: {error}"
    );
}
