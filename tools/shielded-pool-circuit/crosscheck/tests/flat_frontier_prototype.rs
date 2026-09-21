/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What the commitment tree would cost in a container that fits its access.
//!
//! An append writes one slot a level and reads the slots below it, walking
//! levels zero to eleven in order. Nothing about that wants a sparse
//! dictionary, and the dictionary is what it costs: a write is 5,233 gas
//! against 2,800 for the permutation it carries.
//!
//! This prototypes the alternative -- a level-ordered chain of cells, read and
//! rebuilt in the order the fold walks -- and measures the same fold against
//! both. It is a measurement, not a proposal: changing the store is a change
//! to section 13 of the profile, and therefore to the genesis hash and the
//! deployment address.

use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;

/// The index with the largest digit sum any pool can reach.
const WORST_INDEX: u64 = 2 * 1_977_326_743 - 1;
/// Section 5's twelve levels, and the frozen tariff.
const DEPTH: i64 = 12;
const POSEIDON2: i64 = 2_800;

#[test]
fn a_level_ordered_store_against_the_dictionary() {
    let probe = FrontierProbe::deploy().expect("deploy the frontier probe");

    eprintln!("{:<18}{:>12}{:>12}{:>12}", "index", "dictionary", "flat", "saved");
    let mut total_saved = 0;
    for (name, index) in
        [("genesis", 0u64), ("harness", 2), ("a million", 1_000_000), ("worst", WORST_INDEX)]
    {
        let dict = probe.append_gas(index).expect("dictionary append");
        let flat = probe.flat_append_gas(index).expect("flat append");
        eprintln!("{name:<18}{dict:>12}{flat:>12}{:>12}", dict - flat);
        if index == 2 {
            total_saved = dict - flat;
        }
    }

    // What the hashing costs, which neither layout can avoid: it is the floor
    // both are being measured against.
    eprintln!();
    eprintln!("the {DEPTH} permutations either way: {}", DEPTH * POSEIDON2);

    let dict = probe.append_gas(2).expect("dictionary append");
    let flat = probe.flat_append_gas(2).expect("flat append");
    eprintln!("a transact does three appends, so the difference is {}", 3 * (dict - flat));

    // The claim, and it is not the one this prototype was written to make.
    //
    // A level-ordered store is not simply cheaper. It is *constant* -- about
    // 116,000 gas whatever the leaf index -- where the dictionary runs from
    // 108,923 at genesis to 172,571 at the worst index. So it is dearer for a
    // young pool and much cheaper for an old one, and they cross somewhere
    // around a hundred thousand notes.
    //
    // What decides the question is that a sender pre-pays the ceiling, and a
    // ceiling has to cover the worst age the pool can reach. Under the
    // dictionary every sender pays for a maturity most of them will never
    // see. Under a constant store there is no maturity to pay for.
    let worst_dict = probe.append_gas(WORST_INDEX).expect("dictionary append");
    let worst_flat = probe.flat_append_gas(WORST_INDEX).expect("flat append");
    let young_dict = probe.append_gas(2).expect("dictionary append");
    let young_flat = probe.flat_append_gas(2).expect("flat append");

    assert!(
        worst_flat < worst_dict,
        "the level-ordered store no longer wins at the worst index ({worst_flat} against \
         {worst_dict}), which is the only place the ceilings are set from"
    );
    assert!(
        young_flat > young_dict,
        "the level-ordered store is now cheaper at index 2 as well ({young_flat} against \
         {young_dict}); it reads and writes all seven slots a level whatever the digit, so if \
         that has stopped costing anything the prototype is not the one described here"
    );
    // Constant to within a few per cent across the whole index range, which is
    // the property, not the average.
    let spread = (worst_flat - young_flat).abs() * 100 / young_flat;
    eprintln!("the flat store varies by {spread}% from genesis to the worst index");
    assert!(spread < 5, "the flat store is no longer constant: {spread}% across the range");
}
