/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The path from bytes on disk to points in memory, without the network.
//!
//! Fetching the real slice takes a long time and needs a working gateway;
//! neither is a reason for the parser to be untested. A slice built from
//! secrets chosen here has exactly the shape of a fetched one -- the same five
//! sections, the same widths, the same encoding -- so everything between the
//! file and the pairing checks can be exercised against it.
//!
//! What this cannot do is check the *offsets*, because a constructed slice
//! never came from a file. `layout`'s tests carry that: the section arithmetic
//! has to reproduce the transcript's published size, and the ranges have to
//! land inside it and end exactly at its last byte.

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use shielded_pool_ceremony::verify::{slice_from_known_secrets, verify};
use shielded_pool_ceremony::{layout, points, slice};

/// The smallest power the slice arithmetic is defined for that still has more
/// than one point in every section.
const EXPONENT: u32 = 4;
const SOURCE: &str = "https://example.invalid/not-a-transcript";
const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000";

fn built() -> (Vec<u8>, slice::Provenance) {
    let mut rng = ChaCha20Rng::from_seed([19u8; 32]);
    let built = slice_from_known_secrets(
        1usize << EXPONENT,
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
    );
    let bytes = slice::to_bytes(&built);
    let record = slice::describe(&bytes, SOURCE, DIGEST, layout::CHALLENGE_POWER, EXPONENT)
        .expect("a provenance record");
    (bytes, record)
}

#[test]
fn a_slice_survives_the_round_trip_and_verifies() {
    let (bytes, record) = built();
    let parsed = slice::parse(&bytes, &record, EXPONENT).expect("the slice must parse");
    assert_eq!(parsed.degree(), 1usize << EXPONENT);
    assert_eq!(parsed.tau_g1.len(), 2 * (1usize << EXPONENT) - 1);
    verify(&parsed, [3u8; 32]).expect("a round-tripped slice must verify");

    // And the bytes really are the concatenation of the ranges, with nothing
    // added -- which is what lets anyone reproduce the file from a transcript
    // with five reads.
    let expected: u64 = record.ranges.iter().map(|range| range.length).sum();
    assert_eq!(bytes.len() as u64, expected, "the slice file has framing in it");
}

#[test]
fn a_flipped_bit_anywhere_in_the_file_is_caught_before_parsing() {
    let (mut bytes, record) = built();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    let error = slice::parse(&bytes, &record, EXPONENT).expect_err("a changed byte must be caught");
    let message = format!("{error}");
    assert!(
        message.contains("does not hash to what its record says"),
        "caught by the wrong check: {message}"
    );
}

#[test]
fn a_record_for_a_different_power_is_refused() {
    let (bytes, mut record) = built();
    record.slice_power = EXPONENT + 1;
    let error =
        slice::parse(&bytes, &record, EXPONENT).expect_err("a record for another slice is refused");
    assert!(format!("{error}").contains("the circuit needs"), "wrong check: {error}");
}

#[test]
fn a_record_whose_offsets_are_not_the_layouts_is_refused() {
    let (bytes, mut record) = built();
    // The failure that would otherwise be silent: right lengths, right
    // hashes, wrong place in the transcript.
    record.ranges[2].offset += 96;
    let error = slice::parse(&bytes, &record, EXPONENT).expect_err("moved offsets are refused");
    assert!(format!("{error}").contains("the layout says offset"), "wrong check: {error}");
}

#[test]
fn a_record_describing_a_file_of_another_size_is_refused() {
    let (bytes, mut record) = built();
    record.source_bytes = layout::CHALLENGE_BYTES - 1;
    let error = slice::parse(&bytes, &record, EXPONENT).expect_err("another file is refused");
    assert!(format!("{error}").contains("different file"), "wrong check: {error}");
}

/// A point on the curve but outside the prime-order subgroup is the one a
/// hostile transcript would use, because it passes every check that only
/// looks at the curve equation.
#[test]
fn a_point_outside_the_prime_order_subgroup_is_refused() {
    let rogue = points::a_point_outside_the_subgroup();
    let encoded = points::g1_to_uncompressed(&rogue);
    let error =
        points::g1_from_uncompressed(&encoded).expect_err("a small-order point must be refused");
    assert!(
        format!("{error}").contains("subgroup") || format!("{error}").contains("blst refused"),
        "refused for the wrong reason: {error}"
    );
}

#[test]
fn an_unreduced_coordinate_is_refused() {
    // The modulus itself, which is congruent to zero and would be silently
    // reduced by a decoder using `from_be_bytes_mod_order` alone. Two byte
    // strings for one point is the ambiguity a canonical encoding removes.
    let mut bytes = [0u8; 96];
    let modulus = hex::decode(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    )
    .expect("the BLS12-381 base field modulus");
    bytes[..48].copy_from_slice(&modulus);
    let error =
        points::g1_from_uncompressed(&bytes).expect_err("an unreduced coordinate must be refused");
    let message = format!("{error}");
    assert!(
        message.contains("not reduced") || message.contains("blst refused"),
        "refused for the wrong reason: {message}"
    );
}
