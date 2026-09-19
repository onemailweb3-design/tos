/*
 * Copyright (C) 2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! The Rust half of the vote-carrier lock.
//!
//! The C++ half produces `test/pq-native/n3-carrier-vectors.tsv` and reads it back; the
//! contracts parse what it describes. A vote built to a layout the contract does not read
//! is refused after the sender has paid for the message, so the three sides are held to
//! one recorded set of bytes rather than to each other's source.

use chain_block::{Cell, read_single_root_boc, write_boc};
use contracts::{config_contract, elector};
use std::collections::HashMap;

const SIGNATURE_BYTES: usize = 2420;
const QUERY_ID: u64 = 0x1234_5678_90AB_CDEF;

/// The same pattern the generator writes: nothing verifies it, the point is the shape.
fn pattern_signature() -> Vec<u8> {
    (0..SIGNATURE_BYTES).map(|i| (i % 251) as u8).collect()
}

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn recorded() -> HashMap<String, (String, String)> {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../test/pq-native/n3-carrier-vectors.tsv");
    let text = std::fs::read_to_string(path).expect("the shared carrier vectors");
    let mut cases = HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "malformed vector line");
        assert!(
            cases
                .insert(fields[0].to_string(), (fields[1].to_string(), fields[2].to_string()))
                .is_none(),
            "duplicate case {}",
            fields[0]
        );
    }
    assert!(!cases.is_empty(), "the carrier vectors are empty");
    cases
}

fn built() -> Vec<(&'static str, Cell)> {
    let signature = pattern_signature();
    vec![
        (
            "config-vote",
            config_contract::messages::signed_vote(QUERY_ID, 7, &fill(0xE5), &signature).unwrap(),
        ),
        (
            "complaint-vote",
            elector::messages::signed_complaint_vote(
                QUERY_ID,
                7,
                1_789_434_000,
                &fill(0xF6),
                &signature,
            )
            .unwrap(),
        ),
        (
            "config-vote-other-query",
            config_contract::messages::signed_vote(QUERY_ID - 1, 7, &fill(0xE5), &signature)
                .unwrap(),
        ),
        (
            "config-vote-other-index",
            config_contract::messages::signed_vote(QUERY_ID, 8, &fill(0xE5), &signature).unwrap(),
        ),
        (
            "config-vote-other-proposal",
            config_contract::messages::signed_vote(QUERY_ID, 7, &fill(0xE6), &signature).unwrap(),
        ),
        (
            "complaint-vote-other-index",
            elector::messages::signed_complaint_vote(
                QUERY_ID,
                8,
                1_789_434_000,
                &fill(0xF6),
                &signature,
            )
            .unwrap(),
        ),
        (
            "complaint-vote-other-election",
            elector::messages::signed_complaint_vote(
                QUERY_ID,
                7,
                1_789_434_001,
                &fill(0xF6),
                &signature,
            )
            .unwrap(),
        ),
        (
            "complaint-vote-other-complaint",
            elector::messages::signed_complaint_vote(
                QUERY_ID,
                7,
                1_789_434_000,
                &fill(0xF7),
                &signature,
            )
            .unwrap(),
        ),
    ]
}

#[test]
fn builds_exactly_the_carriers_the_other_implementation_builds() {
    let mut cases = recorded();
    for (name, cell) in built() {
        let (hash, boc) = cases.remove(name).unwrap_or_else(|| panic!("no recorded case {name}"));
        assert_eq!(
            cell.repr_hash().as_hex_string().to_uppercase(),
            hash.to_uppercase(),
            "{name}: the root hash differs from the recorded one"
        );
        // The recorded bytes, read by this side. What is locked is the tree, not the
        // envelope it travels in: the two libraries frame a bag of cells differently --
        // one appends a checksum, the other does not -- and the contract is handed the
        // tree. A side that cannot read the other's bytes at all is the failure that
        // matters, and it fails here.
        let from_recorded = read_single_root_boc(hex::decode(&boc).expect("the recorded bytes"))
            .unwrap_or_else(|e| panic!("{name}: cannot read the recorded carrier: {e}"));
        assert_eq!(
            from_recorded.repr_hash(),
            cell.repr_hash(),
            "{name}: the recorded bytes are a different message"
        );
        // And what this side writes is readable in turn, as the same tree.
        let written = write_boc(&cell).expect("serialise the carrier");
        let round_tripped = read_single_root_boc(&written).expect("read back what we wrote");
        assert_eq!(
            round_tripped.repr_hash(),
            cell.repr_hash(),
            "{name}: this side cannot read back its own carrier"
        );
    }
    assert!(
        cases.is_empty(),
        "the file records carriers this side does not build: {:?}",
        cases.keys().collect::<Vec<_>>()
    );
}

/// Each recorded "other" case differs from its base in exactly one field. Two of them
/// being the same message would mean a field this side does not put on the wire.
#[test]
fn no_two_carriers_are_the_same_message() {
    let mut seen = HashMap::new();
    for (name, cell) in built() {
        let hash = cell.repr_hash().as_hex_string();
        if let Some(other) = seen.insert(hash, name) {
            panic!("{name} and {other} are the same message");
        }
    }
}
