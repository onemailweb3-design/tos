/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! An append costs more as the pool fills, and every gas ceiling measured
//! against a fresh pool has to answer for the difference.
//!
//! Section 5's frontier hashes twelve nodes per append whatever the index, so
//! the Poseidon2 count -- the part the tariff prices -- does not move. What
//! moves is the dictionary work: level `l` reads slots `0..digit_l`, and the
//! digits are the leaf index in base seven. At index 2 that is one slot a
//! level; at index 3,954,653,485 it is 79 slots in total. A harness that
//! deposits twice and withdraws once measures the cheapest append the
//! contract has, and calls the result a maximum.

use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;

/// The largest digit sum any legal index has: one, then eleven sixes.
const WORST_INDEX: u64 = 2 * 1_977_326_743 - 1;

/// Indices the withdrawal harness actually appends at.
const HARNESS_INDEX: u64 = 2;

#[test]
fn an_append_costs_more_as_the_tree_fills() {
    let probe = FrontierProbe::deploy().expect("deploy the frontier probe");

    assert_eq!(probe.digit_sum(0).expect("digit sum"), 0, "index zero has no digits set");
    assert_eq!(
        probe.digit_sum(WORST_INDEX).expect("digit sum"),
        67,
        "no legal index has a larger digit sum, so none reads more slots"
    );

    let at_genesis = probe.append_gas(0).expect("append at genesis");
    let at_harness = probe.append_gas(HARNESS_INDEX).expect("append where the harness measures");
    let at_worst = probe.append_gas(WORST_INDEX).expect("append at the worst index");

    for (name, index) in [
        ("genesis", 0u64),
        ("one", 1),
        ("harness", HARNESS_INDEX),
        ("million", 1_000_000),
        ("billion", 1_000_000_000),
        ("worst", WORST_INDEX),
    ] {
        eprintln!(
            "append at {name} (index {index}, digit sum {}): {} gas",
            probe.digit_sum(index).expect("digit sum"),
            probe.append_gas(index).expect("append gas"),
        );
    }

    // The probe is worth believing only if it can tell the two apart. If a
    // change ever makes the append index-independent this assertion is the
    // thing that says so, and the ceilings can then stop carrying a margin
    // for it.
    assert!(
        at_worst > at_harness,
        "the probe reports the same cost at index {HARNESS_INDEX} and index {WORST_INDEX} \
         ({at_harness} gas): either the append stopped depending on the index, or the \
         probe is not measuring the append"
    );
    assert!(at_harness >= at_genesis, "a later index cannot read fewer slots");

    // What the withdrawal's three appends leave unmeasured, which is the part
    // a ceiling frozen against a fresh pool has to absorb.
    let per_append = at_worst - at_harness;
    eprintln!(
        "a transact's three appends cost up to {} gas more than the harness measures",
        per_append * 3
    );
}
