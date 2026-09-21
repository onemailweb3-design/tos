/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What a FRI verifier would cost in this VM, from its two inner loops.
//!
//! The proof-size measurement settled one half of the proof-system question
//! and left the other open: a STARK proof for this circuit is 88 KB at 128
//! bits of proven security, which the chain can carry, but nobody has
//! written a FRI verifier in FunC and `groth16.fc` is 120 lines. This
//! estimates the verifier from the loops it is made of rather than guessing.
//!
//! The counts below are for the parameters the size probe found reach 128
//! bits of PROVEN security on this circuit: trace 8 x 2^12, blowup 16, 60
//! queries, folding factor 8, cubic extension. That puts the low-degree
//! extension on 2^16 points and gives three FRI layers.

use shielded_pool_circuit_crosscheck::stark_sketch_probe::StarkSketch;

/// What a withdrawal costs today, and the ceiling frozen above it.
const GROTH16_VERIFY_GAS: i64 = 204_493;
const WITHDRAWAL_GAS: i64 = 1_730_942;
const TRANSACT_CEILING: i64 = 2_170_000;
/// What this workchain grants one transaction.
const WORKCHAIN_GAS_LIMIT: i64 = 30_000_000;

/// 60 queries at 128 bits of proven security.
const QUERIES: i64 = 60;
/// The trace and constraint commitments sit on the 2^16 LDE domain; the
/// three FRI layers fold it by eight each time.
const PATH_DEPTHS: [usize; 5] = [16, 16, 13, 10, 7];

#[test]
fn what_a_fri_verifier_would_cost() {
    let probe = StarkSketch::deploy().expect("deploy the sketch");
    eprintln!("the sketch is {} lines of FunC, against 120 for groth16.fc", probe.source_lines);

    // Per-level cost, read off the slope rather than assumed.
    let shallow = probe.merkle_path_gas(4).expect("a four-level path");
    let deep = probe.merkle_path_gas(16).expect("a sixteen-level path");
    let per_level = (deep - shallow) / 12;
    eprintln!("a Merkle path: {shallow} gas at depth 4, {deep} at depth 16 -> {per_level} a level");
    assert!(per_level > 0, "the path cost does not grow with depth, so it is not being walked");

    let fold = probe.fold_gas().expect("one folding step");
    eprintln!("one FRI folding step over eight cubic-extension values: {fold} gas");

    let one = probe.ext_mul_gas(1).expect("one multiplication");
    let many = probe.ext_mul_gas(101).expect("a hundred and one");
    let per_mul = (many - one) / 100;
    eprintln!("one cubic-extension multiplication, as first written: {per_mul} gas");
    let fast_one = probe.ext_mul_fast_gas(1).expect("one");
    let fast_many = probe.ext_mul_fast_gas(21).expect("twenty-one");
    let per_mul_fast = (fast_many - fast_one) / 20;
    eprintln!("the same with the shift-based reduction every Goldilocks library uses: {per_mul_fast} gas");
    // Worth recording rather than quietly dropping: the standard trick is
    // slower here. TVM charges by stack operation, not by arithmetic width,
    // so one `muldivmod` over 257-bit integers beats a dozen shifts, masks
    // and branches. An optimisation carried over from a CPU target is not
    // an optimisation on this VM.
    assert!(
        per_mul_fast > per_mul,
        "the shift-based reduction is now the cheaper one ({per_mul_fast} against {per_mul}), \
         so the estimate below should be redone with it"
    );

    // What the two loops come to for the whole verification.
    let paths_per_query: i64 = PATH_DEPTHS.iter().map(|d| *d as i64).sum();
    let merkle = QUERIES * paths_per_query * per_level;
    // Three layers folded per query.
    let folding = QUERIES * 3 * fold;
    eprintln!();
    eprintln!("60 queries x {paths_per_query} levels x {per_level} gas = {merkle} gas of Merkle paths");
    eprintln!("60 queries x 3 layers x {fold} gas = {folding} gas of folding");
    let loops = merkle + folding;
    eprintln!("the two inner loops together: {loops} gas");
    eprintln!();
    eprintln!("a Merkle level breaks down as: SHA256 of 64 bytes is 2 gas, creating the cell to");
    eprintln!("hold the pair is 500, loading cells is 100 each. The hashing is not the cost.");
    eprintln!();
    eprintln!("for comparison: Groth16 verifies in {GROTH16_VERIFY_GAS} gas");
    eprintln!("a whole withdrawal is {WITHDRAWAL_GAS} gas, ceiling {TRANSACT_CEILING}");
    eprintln!("this workchain grants {WORKCHAIN_GAS_LIMIT} gas a transaction");

    // The claim this test exists to pin. It is deliberately loose: the
    // inner loops are not the whole verifier, and what matters for the
    // decision is the order of magnitude against the network's limit.
    assert!(
        loops < WORKCHAIN_GAS_LIMIT,
        "the inner loops alone ({loops} gas) exceed what a transaction may burn, which would \
         settle the question without writing the rest"
    );
}
