/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Whether the commitment tree's overhead wants an instruction or a container.
//!
//! An append costs 119,098 gas near genesis of which 42,000 is hashing, and
//! 180,671 at the worst index of which the same 42,000 is hashing. The rest
//! is the frontier store, which is a HashmapE with seven-bit keys.
//!
//! The keys are `level * 7 + position`, so the key space is exactly 0..83:
//! dense, contiguous and known when the contract is compiled. A sparse
//! dictionary is what you reach for when the keys are sparse. This measures
//! what that choice costs before anyone proposes an instruction to work
//! around it, because an instruction is consensus code and a container is not.

use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;

/// The worst legal leaf index, whose digits are one then eleven sixes.
const WORST_INDEX: u64 = 2 * 1_977_326_743 - 1;
/// Section 5: twelve levels, arity seven.
const DEPTH: i64 = 12;
/// The frozen Poseidon2 tariff.
const POSEIDON2: i64 = 3_500;

fn slope(probe: &FrontierProbe, f: impl Fn(u64) -> i64, low: u64, high: u64) -> i64 {
    let _ = probe;
    (f(high) - f(low)) / (high as i64 - low as i64)
}

#[test]
fn what_the_frontier_store_costs_to_read_and_write() {
    let probe = FrontierProbe::deploy().expect("deploy the frontier probe");

    // Against a nearly empty store and against a full one, because a
    // dictionary's cost grows with what is in it and an array's does not.
    for (name, index) in [("near genesis", 2u64), ("the worst index", WORST_INDEX)] {
        let read = slope(&probe, |n| probe.dict_read_gas(index, n).expect("reads"), 1, 101);
        let write = slope(&probe, |n| probe.dict_write_gas(index, n).expect("writes"), 1, 101);
        eprintln!("{name:<16} one dictionary read {read:>5} gas, one write {write:>5} gas");
    }

    let flat = slope(&probe, |n| probe.flat_read_gas(n).expect("flat reads"), 1, 101);
    eprintln!("{:<16} one flat-chain read {flat:>5} gas", "dense container");

    // What an append is made of, at the two ends of the index range.
    let read = slope(&probe, |n| probe.dict_read_gas(2, n).expect("reads"), 1, 101);
    let write = slope(&probe, |n| probe.dict_write_gas(2, n).expect("writes"), 1, 101);
    let worst_read =
        slope(&probe, |n| probe.dict_read_gas(WORST_INDEX, n).expect("reads"), 1, 101);

    for (name, index, reads) in
        [("near genesis", 2u64, DEPTH + 2), ("the worst index", WORST_INDEX, DEPTH + 67)]
    {
        let measured = probe.append_gas(index).expect("append");
        let r = if index == 2 { read } else { worst_read };
        let dict = reads * r + DEPTH * write;
        let hashing = DEPTH * POSEIDON2;
        eprintln!();
        eprintln!("an append {name}: {measured} gas");
        eprintln!("  hashing, {DEPTH} permutations        {hashing:>8}");
        eprintln!("  {reads:>2} dictionary reads at {r:<5}      {:>8}", reads * r);
        eprintln!("  {DEPTH:>2} dictionary writes at {write:<5}     {:>8}", DEPTH * write);
        eprintln!("  everything else                 {:>8}", measured - hashing - dict);
    }

    assert!(read > 0 && write > 0, "the probe reports no cost for a dictionary operation");
    // The claim: a dictionary write is the expensive half, and it is expensive
    // because of what it is, not because of how many there are.
    assert!(
        write > read,
        "a write ({write}) is no longer dearer than a read ({read}), so the container's cost \
         has changed shape and the arithmetic above should be redone"
    );
}
