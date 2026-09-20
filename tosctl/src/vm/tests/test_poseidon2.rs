/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The Poseidon2 instruction pair in the Rust VM, against the same generated
//! vectors the C++ VM is checked with. The permutation itself is tested in
//! `chain_block`; what is checked here is the instruction: its stack contract,
//! the version it starts at, what it refuses, and what it costs.

use chain_block::{
    poseidon2_kat::{HASH7, PERM8},
    poseidon2_params::MODULUS_BE,
    ExceptionCode,
};
use tos_vm::stack::{integer::IntegerData, Stack, StackItem};

mod common;
use common::*;

const ACTIVE_VERSION: u32 = 17;
/// The development tariff, the cost of a 24-bit instruction, and the implicit
/// return. Written as specification literals, not read from the implementation.
const EXPECTED_GAS: i64 = 3000 + 34 + 5;

fn stack_of(values: &[[u8; 32]]) -> Stack {
    let mut stack = Stack::new();
    for value in values {
        stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(value)));
    }
    stack
}

fn field(value: &[u8; 32]) -> StackItem {
    StackItem::int(IntegerData::from_unsigned_bytes_be(value))
}

/// The eight-lane state with one lane replaced, so a rejection can be attributed
/// to a lane rather than to the shape of the stack.
fn stack_with_lane(values: &[[u8; 32]; 8], lane: usize, item: StackItem) -> Stack {
    let mut stack = Stack::new();
    for (index, value) in values.iter().enumerate() {
        stack.push(if index == lane { item.clone() } else { field(value) });
    }
    stack
}

#[test]
fn every_pinned_permutation_vector_runs_in_the_vm() {
    for (name, input, output) in PERM8 {
        test_case("POSEIDON2_PERM8")
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input))
            .expect_success_extended(Some(name))
            .expect_stack_extended(&stack_of(&output), Some(name));
    }
}

#[test]
fn every_pinned_hash_vector_runs_in_the_vm() {
    for (name, state, output) in HASH7 {
        test_case("POSEIDON2_HASH7")
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&state))
            .expect_success_extended(Some(name))
            .expect_stack_extended(Stack::new().push(field(&output)), Some(name));
    }
}

#[test]
fn hash7_is_lane_zero_of_the_permutation_and_no_other_lane() {
    let (_, input, output) = PERM8[0];
    test_case("POSEIDON2_HASH7")
        .with_block_version(ACTIVE_VERSION)
        .with_stack(stack_of(&input))
        .expect_success()
        .expect_stack(Stack::new().push(field(&output[0])));
    for lane in 1..8 {
        assert_ne!(output[0], output[lane], "lane {lane} coincides with the hash output");
    }
}

#[test]
fn neither_instruction_exists_before_its_version() {
    let (_, input, _) = PERM8[0];
    for version in 0..ACTIVE_VERSION {
        for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
            test_case(code)
                .with_block_version(version)
                .with_stack(stack_of(&input))
                .expect_failure_extended(
                    ExceptionCode::InvalidOpcode,
                    Some(&format!("{code} at version {version}")),
                );
        }
    }
    for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        test_case(code)
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input))
            .expect_success();
    }
}

#[test]
fn anything_that_is_not_already_a_field_element_is_refused() {
    let (_, input, _) = PERM8[0];
    let mut largest = MODULUS_BE;
    largest[31] -= 1; // the modulus ends in 0x01, so this cannot borrow

    for lane in 0..8 {
        for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
            for (label, item) in [
                ("the modulus", field(&MODULUS_BE)),
                ("2^256-1", field(&[0xff; 32])),
                ("a negative value", StackItem::int(IntegerData::minus_one())),
            ] {
                test_case(code)
                    .with_block_version(ACTIVE_VERSION)
                    .with_stack(stack_with_lane(&input, lane, item))
                    .expect_failure_extended(
                        ExceptionCode::RangeCheckError,
                        Some(&format!("{label} accepted in lane {lane} by {code}")),
                    );
            }
            // The value immediately below the modulus must still be legal.
            test_case(code)
                .with_block_version(ACTIVE_VERSION)
                .with_stack(stack_with_lane(&input, lane, field(&largest)))
                .expect_success_extended(Some(&format!("largest field element in lane {lane}")));
        }
    }
}

#[test]
fn a_nan_operand_is_refused() {
    let (_, input, _) = PERM8[0];
    for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        test_case(format!("PUSHNAN\n{code}"))
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input[..7]))
            .expect_failure(ExceptionCode::RangeCheckError);
    }
}

#[test]
fn a_short_stack_underflows_and_a_wrong_type_is_a_type_error() {
    let (_, input, _) = PERM8[0];
    for depth in 0..8 {
        for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
            test_case(code)
                .with_block_version(ACTIVE_VERSION)
                .with_stack(stack_of(&input[..depth]))
                .expect_failure_extended(
                    ExceptionCode::StackUnderflow,
                    Some(&format!("{code} with {depth} operands")),
                );
        }
    }
    for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        let mut stack = stack_of(&input[..7]);
        stack.push(StackItem::None);
        test_case(code)
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack)
            .expect_failure(ExceptionCode::TypeCheckError);
    }
}

#[test]
fn both_instructions_cost_the_tariff() {
    let (_, input, _) = PERM8[0];
    for code in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        test_case(code)
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input))
            .expect_success()
            .expect_gas_used(EXPECTED_GAS);
        test_case(code)
            .with_block_version(ACTIVE_VERSION)
            .with_stack(stack_of(&input))
            .with_gas_limit(EXPECTED_GAS - 1)
            .expect_failure(ExceptionCode::OutOfGas);
    }
    // A refused operand is still charged: probing must not be cheaper.
    test_case("POSEIDON2_PERM8")
        .with_block_version(ACTIVE_VERSION)
        .with_stack(stack_with_lane(&input, 7, field(&MODULUS_BE)))
        .with_gas_limit(3000 - 1)
        .expect_failure(ExceptionCode::OutOfGas);
}
