/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Where in a 72-gibibyte phase-1 challenge file this circuit's parameters are.
//!
//! The phase-1 transcript is a powers-of-tau accumulator for circuits up to
//! 2^27 constraints. This circuit needs 2^15, and the accumulator's sections
//! are each stored in ascending power order, so what we need is a *prefix of
//! every section* rather than a prefix of the file. Five ranges, about
//! eighteen megabytes, out of seventy-two gibibytes.
//!
//! Getting these offsets wrong is the worst kind of error available here: the
//! bytes would parse, the points would be on the curve and in the subgroup,
//! and the verification below would fail with nothing to say about why. So
//! two independent facts are checked rather than assumed.
//!
//! **The total.** The layout implies an exact file size, and the server
//! publishes one. They agree to the byte: 77,309,411,488. That pins the
//! element counts, the uncompressed point widths and the 64-byte prefix.
//!
//! **The order.** A total is the same whatever order the sections are in, so
//! it pins nothing about which comes first. The order below is the one
//! `Accumulator::serialize` writes -- tau_g1, tau_g2, alpha_tau_g1,
//! beta_tau_g1, beta_g2 -- and `verify` is what actually catches an order
//! mistake, because sections read in the wrong order are not powers of the
//! same tau and no pairing check holds.

use crate::error::{Error, Result};

/// An uncompressed G1 point in the IETF encoding: big-endian x then y.
pub const G1_UNCOMPRESSED: u64 = 96;
/// An uncompressed G2 point: the two Fp2 coordinates, c1 before c0.
pub const G2_UNCOMPRESSED: u64 = 192;

/// The BLAKE2b digest of the previous transcript entry, which the ceremony
/// binary writes ahead of the accumulator. It is not part of the accumulator's
/// own serialization; it is what chains one challenge to the last.
pub const TRANSCRIPT_HASH_BYTES: u64 = 64;

/// The published phase-1 transcript and the size it must have.
///
/// The size is not decoration. It is the one number that says the file at that
/// URL is the accumulator this layout describes, and it is checked before a
/// single byte is used.
pub const CHALLENGE_URL: &str = "https://trusted-setup.filecoin.io/phase1/challenge_19";
pub const CHALLENGE_BYTES: u64 = 77_309_411_488;
/// The exponent the published transcript was run to: circuits up to 2^27.
pub const CHALLENGE_POWER: u32 = 27;

/// One contiguous run of bytes to read out of the challenge file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    /// What this run holds, for the provenance record and for error messages.
    pub name: &'static str,
    pub offset: u64,
    pub length: u64,
    /// How many curve points, and which group they are in.
    pub points: u64,
    pub point_bytes: u64,
}

impl Range {
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }
}

/// Every section of the accumulator at the transcript's own power, in the
/// order they are written. Used to derive offsets, and to check the total.
fn sections(power: u32) -> [(&'static str, u64, u64); 5] {
    // `TAU_POWERS_LENGTH` in the ceremony's own terms. A QAP of degree n needs
    // tau^0..tau^(2n-2) in G1 -- the numerator of the quotient polynomial
    // reaches degree 2n-2 -- and only tau^0..tau^(n-1) in G2.
    let n: u64 = 1u64 << power;
    [
        ("tau_g1", 2 * n - 1, G1_UNCOMPRESSED),
        ("tau_g2", n, G2_UNCOMPRESSED),
        ("alpha_tau_g1", n, G1_UNCOMPRESSED),
        ("beta_tau_g1", n, G1_UNCOMPRESSED),
        ("beta_g2", 1, G2_UNCOMPRESSED),
    ]
}

/// The size the layout says a challenge file at `power` must have.
pub fn challenge_size(power: u32) -> u64 {
    sections(power)
        .iter()
        .fold(TRANSCRIPT_HASH_BYTES, |total, (_, count, width)| total + count * width)
}

/// The five ranges holding a degree-`2^wanted` prefix of a transcript run to
/// `2^power`.
///
/// Each section is a prefix of the corresponding section in the file, and the
/// sections sit at offsets fixed by the *transcript's* power, not by ours --
/// which is the whole reason this cannot be done by reading the first N bytes.
pub fn slice_ranges(power: u32, wanted: u32) -> Result<Vec<Range>> {
    if wanted > power {
        return Err(Error::Layout(format!(
            "this circuit needs a domain of 2^{wanted} and the transcript was run to 2^{power}; \
             a larger circuit needs a larger ceremony, not a different slice"
        )));
    }
    let want: u64 = 1u64 << wanted;
    let mut ranges = Vec::with_capacity(5);
    let mut offset = TRANSCRIPT_HASH_BYTES;
    for (name, count, width) in sections(power) {
        // How many of this section's elements a degree-2^wanted QAP needs.
        let take = match name {
            "tau_g1" => 2 * want - 1,
            "beta_g2" => 1,
            _ => want,
        };
        if take > count {
            return Err(Error::Layout(format!(
                "{name}: the slice wants {take} elements and the transcript has {count}"
            )));
        }
        ranges.push(Range { name, offset, length: take * width, points: take, point_bytes: width });
        offset += count * width;
    }
    Ok(ranges)
}

/// The bytes a slice at `wanted` occupies once fetched: the ranges end to end,
/// with nothing added. The fetched file is literally those bytes in order, so
/// that it stays a copy of parts of the transcript rather than a re-encoding
/// of them.
pub fn slice_size(power: u32, wanted: u32) -> Result<u64> {
    Ok(slice_ranges(power, wanted)?.iter().map(|range| range.length).sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout implies a file size and the server publishes one. This is
    /// the check that says the two describe the same object.
    #[test]
    fn the_layout_reproduces_the_published_file_size() {
        assert_eq!(
            challenge_size(CHALLENGE_POWER),
            CHALLENGE_BYTES,
            "the section layout no longer produces the size the transcript is published with, \
             so every offset derived from it is wrong"
        );
    }

    /// And it has to be able to disagree, or the assertion above is arithmetic
    /// agreeing with itself.
    #[test]
    fn a_layout_at_the_wrong_power_does_not_match() {
        assert_ne!(challenge_size(CHALLENGE_POWER - 1), CHALLENGE_BYTES);
        assert_ne!(challenge_size(CHALLENGE_POWER + 1), CHALLENGE_BYTES);
    }

    #[test]
    fn the_ranges_lie_inside_the_file_and_do_not_overlap() {
        let ranges = slice_ranges(CHALLENGE_POWER, 15).expect("ranges");
        assert_eq!(ranges.len(), 5);
        let mut previous_end = TRANSCRIPT_HASH_BYTES;
        for range in &ranges {
            assert!(
                range.offset >= previous_end,
                "{} starts at {} inside the previous section",
                range.name,
                range.offset
            );
            assert!(
                range.end() <= CHALLENGE_BYTES,
                "{} runs to {} past the end of the file",
                range.name,
                range.end()
            );
            assert_eq!(range.length, range.points * range.point_bytes);
            previous_end = range.end();
        }
    }

    /// The last section is the one whose offset depends on every other
    /// section's size, so it is where an arithmetic slip would land.
    #[test]
    fn beta_g2_is_the_last_point_in_the_file() {
        let ranges = slice_ranges(CHALLENGE_POWER, 15).expect("ranges");
        let beta = ranges.last().expect("five ranges");
        assert_eq!(beta.name, "beta_g2");
        assert_eq!(beta.end(), CHALLENGE_BYTES, "beta_g2 must be the file's last 192 bytes");
    }

    #[test]
    fn a_slice_is_about_eighteen_megabytes() {
        let size = slice_size(CHALLENGE_POWER, 15).expect("size");
        assert_eq!(size, 18_874_464);
        assert!(size * 4000 < CHALLENGE_BYTES, "the slice should be a tiny fraction of the file");
    }

    #[test]
    fn a_circuit_larger_than_the_transcript_is_refused() {
        assert!(slice_ranges(CHALLENGE_POWER, CHALLENGE_POWER + 1).is_err());
    }
}
