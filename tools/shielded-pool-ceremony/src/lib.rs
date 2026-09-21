/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Groundwork for the shielded pool's Groth16 ceremony.
//!
//! Section 17 and section 20 say the development keys come from a fixed seed,
//! so the toxic waste is known and no key this repository produces may verify
//! a real transaction. Production keys come from a two-phase ceremony: a
//! circuit-independent powers-of-tau, which already exists and is reused, and
//! a circuit-specific phase 2, which has to be ours.
//!
//! What lives here is everything about that ceremony which does not need
//! participants:
//!
//! * [`Shape`] -- the QAP domain this circuit needs, measured from the circuit
//!   rather than written down, because every byte of the phase-1 slice is
//!   located by it;
//! * [`layout`] -- which published ceremony a deployment inherits, and where in
//!   its file the slice is, with arithmetic that has to agree with the
//!   published file size before any offset is trusted;
//! * [`lagrange`] -- the basis change between a verified slice and something a
//!   setup can consume, and the `h` query that goes with it;
//! * [`points`] -- transcript bytes into curve points, with this chain's own
//!   BLS library deciding what a point is;
//! * [`verify`] -- the pairing checks that say the slice is a powers-of-tau
//!   string and not merely a list of valid points.
//!
//! **The phase-2 multi-party computation is being built, and is not here
//! yet.** `ark-groth16` 0.5 has no MPC module -- checked in its source, not
//! assumed -- and the two mature implementations, Filecoin's `phase2` and
//! gnark's `mpcsetup`, both want the circuit expressed in their own constraint
//! system; a second implementation of an 18,107-constraint circuit is a worse
//! risk than it sounds. So it is being written against arkworks, in stages,
//! each one with a check that can fail rather than an argument that sounds
//! right.
//!
//! What the first stage established is already load-bearing. The setup's
//! evaluation domain is `constraints + instance_variables` and not, as
//! [`Shape::qap_degree`] used to compute, `max(constraints, variables)` --
//! both round to 2^15 for this circuit, so nothing downstream was wrong, but
//! the headroom was. And the key's dimensions line up with what [`lagrange`]
//! produces: the `h` query is 32,767 long and so is the transform's, because
//! they are the same object.

pub mod error;
pub mod lagrange;
pub mod layout;
pub mod phase2;
pub mod points;
pub mod slice;
pub mod verify;

pub use error::{Error, Result};

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::field::Fr;

/// The R1CS shape the ceremony has to cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub constraints: usize,
    pub instance_variables: usize,
    pub witness_variables: usize,
}

impl Shape {
    /// The QAP degree: **constraints plus instance variables**.
    ///
    /// Not `max(constraints, variables)`, which is what this computed until it
    /// was checked against the setup that actually consumes it. The extra
    /// instance terms are the input-consistency rows: `instance_map_with_evaluation`
    /// gives each instance variable its own Lagrange coefficient at index
    /// `num_constraints + i`, so the domain has to reach past the constraints
    /// by exactly the number of inputs.
    ///
    /// For this circuit both formulas round to 2^15, so the phase-1 slice was
    /// right either way -- but the headroom was not, and the headroom is the
    /// number somebody adding constraints will read.
    ///
    /// `the_domain_is_the_one_the_setup_uses` holds this against a key
    /// arkworks actually built, rather than against a reading of its source.
    pub fn qap_degree(&self) -> usize {
        self.constraints + self.instance_variables
    }

    /// The power of two the domain rounds up to, which is the exponent the
    /// phase-1 slice is taken at.
    pub fn domain_exponent(&self) -> u32 {
        let degree = self.qap_degree();
        let mut exponent = 0u32;
        while (1usize << exponent) < degree {
            exponent += 1;
        }
        exponent
    }
}

/// Synthesises the circuit and reports its shape.
///
/// Measured, never configured. If the circuit grows past 32,768 the slice
/// moves to a different set of byte ranges and every fetched byte is the wrong
/// one, so this is the number the rest of the ceremony is derived from.
pub fn shape(circuit: ShieldedTransactionCircuit) -> Result<Shape> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(|error| Error::Layout(format!("synthesising the circuit: {error}")))?;
    Ok(Shape {
        constraints: cs.num_constraints(),
        instance_variables: cs.num_instance_variables(),
        witness_variables: cs.num_witness_variables(),
    })
}
