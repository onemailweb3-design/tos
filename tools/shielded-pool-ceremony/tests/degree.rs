/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The one number the whole ceremony is built on.
//!
//! Every byte offset in the phase-1 slice is a function of the circuit's QAP
//! domain. If the circuit grows past 32,768 the domain becomes 2^16, the
//! slice doubles, and the ranges move -- so a slice fetched before the growth
//! is not merely too small, it is the wrong bytes, and nothing downstream
//! would say so. A fetched slice carries the exponent it was taken at and is
//! refused against a circuit that has outgrown it, which is what makes this a
//! gate rather than a note.

use shielded_pool_ceremony::{layout, shape, Shape};
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::scenario;

/// The exponent the deployment's phase-1 slice is taken at.
///
/// Pinned on purpose: this is the number a fetched artifact is checked
/// against, so it has to be a declaration the circuit is measured against and
/// not a value derived from whatever the circuit happens to be today.
const SLICE_EXPONENT: u32 = 15;

fn measured() -> Shape {
    let (_pool, public, witness) = scenario::valid_withdrawal().expect("a withdrawal");
    shape(ShieldedTransactionCircuit::new(public, witness)).expect("the circuit's shape")
}

#[test]
fn the_circuit_still_fits_the_slice_the_ceremony_is_planned_for() {
    let shape = measured();
    eprintln!(
        "constraints {}, instance {}, witness {} -> QAP degree {} -> 2^{}",
        shape.constraints,
        shape.instance_variables,
        shape.witness_variables,
        shape.qap_degree(),
        shape.domain_exponent(),
    );
    assert_eq!(
        shape.domain_exponent(),
        SLICE_EXPONENT,
        "the circuit's QAP domain is now 2^{} and the ceremony is planned around 2^{SLICE_EXPONENT}. \
         This is not a tuning constant: every byte range in `layout` is derived from the exponent, \
         so a slice already fetched is the wrong bytes rather than too few of them.",
        shape.domain_exponent()
    );
    assert!(
        shape.qap_degree() <= 1 << SLICE_EXPONENT,
        "a QAP degree of {} does not fit a domain of {}",
        shape.qap_degree(),
        1usize << SLICE_EXPONENT
    );
}

/// The headroom, stated rather than left to be discovered. A circuit change
/// that eats it is a change that moves the ceremony.
#[test]
fn how_much_the_circuit_can_grow_before_the_ceremony_changes() {
    let shape = measured();
    let room = (1usize << SLICE_EXPONENT) - shape.qap_degree();
    eprintln!(
        "the circuit uses {} of a {} domain; {room} to spare before the slice doubles",
        shape.qap_degree(),
        1usize << SLICE_EXPONENT
    );
    assert!(room > 0, "the circuit exactly fills its domain, so any addition moves the ceremony");
}

/// A transfer and a withdrawal are the same circuit with different witnesses,
/// so they had better generate the same constraint system. If they did not,
/// "the circuit's degree" would not be a well-defined thing to build a
/// ceremony on.
#[test]
fn both_transaction_kinds_have_the_same_shape() {
    let (_pool, public, witness) = scenario::valid_transfer().expect("a transfer");
    let transfer =
        shape(ShieldedTransactionCircuit::new(public, witness)).expect("the transfer's shape");
    assert_eq!(
        transfer,
        measured(),
        "a transfer and a withdrawal synthesise different constraint systems, so one proving \
         key cannot serve both"
    );
}

#[test]
fn the_slice_the_exponent_implies_is_the_one_the_layout_produces() {
    let ranges = layout::slice_ranges(layout::CHALLENGE_POWER, SLICE_EXPONENT).expect("ranges");
    let degree = 1u64 << SLICE_EXPONENT;
    assert_eq!(ranges[0].points, 2 * degree - 1, "tau_g1 must reach degree 2n-2");
    for range in &ranges[1..4] {
        assert_eq!(range.points, degree, "{} must hold n points", range.name);
    }
    assert_eq!(ranges[4].points, 1);
}
