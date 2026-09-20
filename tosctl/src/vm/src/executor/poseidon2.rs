// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! The Poseidon2 t=8 instruction pair, mirroring `crypto/vm/poseidon2ops.cpp`.
//! The permutation itself lives in `chain_block::poseidon2`, beside the frozen
//! parameters it reads; what is here is the stack contract, the version gate,
//! the tariff, and the refusal of anything that is not already a field element.

use super::{
    engine::{storage::fetch_stack, Engine},
    gas::gas_state::Gas,
    types::Instruction,
};
use crate::stack::{integer::IntegerData, StackItem};
use chain_block::{fail, poseidon2, ExceptionCode, Result, Status};

pub(super) const MIN_VERSION: u32 = 17;
/// Development tariff, matching `poseidon2_perm8_gas_price` in the C++ VM. A
/// production price replaces both at once.
pub(super) const GAS_PRICE: i64 = 3000;

const STATE_WIDTH: usize = 8;

/// Fail closed. A negative value, one that does not fit in 256 unsigned bits,
/// and one at or above the modulus are all refused rather than reduced: a
/// silent reduction would let two different stack values hash the same.
fn field_bytes(value: &IntegerData) -> Result<poseidon2::FieldBytes> {
    if value.is_nan() {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 input is not a number");
    }
    if value.is_neg() {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 input is negative");
    }
    let bytes = value.as_u256()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    if !poseidon2::is_canonical(&out) {
        fail!(ExceptionCode::RangeCheckError, "Poseidon2 input is not below the field modulus");
    }
    Ok(out)
}

/// Both instructions consume a whole state and differ only in what they return.
fn permute_stack_state(
    engine: &mut Engine,
    name: &'static str,
) -> Result<[poseidon2::FieldBytes; STATE_WIDTH]> {
    // Before activation the opcode does not exist. The metering matches the
    // older instruction's: from v4 the invalid-instruction charge can exhaust
    // gas before exception dispatch, earlier versions charge it regardless.
    if engine.block_version() < MIN_VERSION {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    engine.load_instruction(Instruction::new(name))?;
    if engine.cc.stack.depth() < STATE_WIDTH {
        fail!(ExceptionCode::StackUnderflow);
    }
    // Charged before the operands are inspected, so probing for a valid field
    // element is never cheaper than doing the work.
    engine.try_use_gas(GAS_PRICE)?;
    fetch_stack(engine, STATE_WIDTH)?;
    let mut state = [[0u8; 32]; STATE_WIDTH];
    for index in 0..STATE_WIDTH {
        // var(0) is the top of the stack, which is the last lane of the state.
        state[STATE_WIDTH - 1 - index] = field_bytes(engine.cmd.var(index).as_integer()?)?;
    }
    Ok(poseidon2::permute(&state))
}

pub(super) fn execute_poseidon2_perm8(engine: &mut Engine) -> Status {
    let result = permute_stack_state(engine, "POSEIDON2_PERM8")?;
    for value in result.iter() {
        engine.cc.stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(value)));
    }
    Ok(())
}

pub(super) fn execute_poseidon2_hash7(engine: &mut Engine) -> Status {
    // The domain constant sits in lane 0 and the result is lane 0: no capacity
    // element and no padding rule beyond that.
    let result = permute_stack_state(engine, "POSEIDON2_HASH7")?;
    engine.cc.stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(&result[0])));
    Ok(())
}
