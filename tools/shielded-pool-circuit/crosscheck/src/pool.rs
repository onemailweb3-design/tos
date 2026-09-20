/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The real pool contract in the VM, driven by real messages.
//!
//! This is not a probe. It is the contract that would ship, deployed from the
//! same source list, given the development verifying key, and sent the
//! messages a wallet would send. What it exists for is the one thing no test
//! on the chain side can do on its own: put a proof in front of it that
//! actually verifies.

use ark_ff::{BigInteger, PrimeField};
use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::field::Fr;
use tos_sandbox::{compile_func, Blockchain, MessageBuilder, SendResult};

use crate::{library_dir, stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

pub const OP_DEPOSIT: u32 = 0x5348_5001;
pub const OP_TRANSACT: u32 = 0x5348_5002;

/// Section 13.2.
const MAGIC: u32 = 0x5350_5631;
const VERSION: u16 = 1;
const EPOCH_NONE: u32 = 0xffff_ffff;
const RESERVE_FLOOR: u64 = 5 * TOS;
/// The one configured denomination, and the fee section 14.2 fixes.
pub const DENOMINATION: u64 = TOS;
pub const WITHDRAWAL_FEE: u64 = 250_000_000;

/// A field element as its 32 big-endian wire bytes.
pub fn be(value: Fr) -> [u8; 32] {
    let digits = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(&digits);
    out
}

/// A field element as the decimal string a get-method prints.
pub fn dec(value: Fr) -> String {
    let mut digits = vec![0u8];
    for byte in be(value) {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let next = u32::from(*digit) * 256 + carry;
            *digit = (next % 10) as u8;
            carry = next / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// Coins are a VarUInteger 16: four bits of byte length, then the bytes.
pub fn store_coins(builder: &mut BuilderData, amount: u128) -> Result<()> {
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let length = bytes.len() - first;
    builder
        .append_bits(length, 4)
        .map_err(|error| CrossCheckError::Sandbox(format!("coin length: {error}")))?;
    if length > 0 {
        builder
            .append_raw(&bytes[first..], length * 8)
            .map_err(|error| CrossCheckError::Sandbox(format!("coin bytes: {error}")))?;
    }
    Ok(())
}

fn cell_of(builder: BuilderData) -> Result<Cell> {
    builder.into_cell().map_err(|error| CrossCheckError::Sandbox(format!("cell: {error}")))
}

fn empty_ring_holder() -> Result<Cell> {
    let mut builder = BuilderData::new();
    builder
        .append_bit_zero()
        .map_err(|error| CrossCheckError::Sandbox(format!("ring holder: {error}")))?;
    cell_of(builder)
}

/// The development verifying key, as the fixture records it.
pub fn development_vk_bytes() -> Result<Vec<u8>> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/groth16-development.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| CrossCheckError::Fixture(format!("{}: {error}", path.display())))?;
    let fixture: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| CrossCheckError::Fixture(format!("fixture json: {error}")))?;
    let hex = fixture["verifying_key"]["hex"]
        .as_str()
        .ok_or_else(|| CrossCheckError::Fixture("no verifying key in the fixture".to_string()))?;
    (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|error| CrossCheckError::Fixture(format!("vk hex: {error}")))
        })
        .collect()
}

fn config_store() -> Result<Cell> {
    let mut chain = BuilderData::new();
    store_coins(&mut chain, u128::from(DENOMINATION))?;
    let mut builder = BuilderData::new();
    for tag in [0x11u8, 0x22, 0x33] {
        builder
            .append_raw(&[tag; 32], 256)
            .map_err(|error| CrossCheckError::Sandbox(format!("config hash: {error}")))?;
    }
    store_coins(&mut builder, u128::from(WITHDRAWAL_FEE))?;
    builder
        .append_u8(1)
        .map_err(|error| CrossCheckError::Sandbox(format!("denomination count: {error}")))?;
    builder
        .checked_append_reference(cell_of(chain)?)
        .map_err(|error| CrossCheckError::Sandbox(format!("denominations: {error}")))?;
    cell_of(builder)
}

fn genesis_state(commitment_root: Fr, nullifier_root: Fr) -> Result<Cell> {
    let mut builder = BuilderData::new();
    builder
        .append_u32(MAGIC)
        .and_then(|b| b.append_u16(VERSION))
        .map_err(|error| CrossCheckError::Sandbox(format!("state header: {error}")))?;
    builder
        .append_raw(&be(commitment_root), 256)
        .and_then(|b| b.append_u64(0))
        .and_then(|b| b.append_raw(&be(nullifier_root), 256))
        .and_then(|b| b.append_u64(1))
        .and_then(|b| b.append_u32(EPOCH_NONE))
        .map_err(|error| CrossCheckError::Sandbox(format!("state roots: {error}")))?;
    store_coins(&mut builder, 0)?;
    store_coins(&mut builder, u128::from(RESERVE_FLOOR))?;
    let mut anchors = BuilderData::new();
    anchors
        .checked_append_reference(empty_ring_holder()?)
        .and_then(|b| b.checked_append_reference(empty_ring_holder()?))
        .map_err(|error| CrossCheckError::Sandbox(format!("anchors: {error}")))?;
    builder
        .checked_append_reference(empty_ring_holder()?)
        .and_then(|b| b.checked_append_reference(cell_of(anchors)?))
        .and_then(|b| b.checked_append_reference(config_store()?))
        .and_then(|b| {
            b.checked_append_reference(crate::wire::byte_chain(&development_vk_bytes()?)?)
        })
        .map_err(|error| CrossCheckError::Sandbox(format!("state refs: {error}")))?;
    cell_of(builder)
}

/// The shielded pool, deployed.
pub struct Pool {
    pub bc: Blockchain,
    pub addr: MsgAddressInt,
    payer: tos_sandbox::Treasury,
}

/// Every FunC source the pool is built from, in dependency order.
fn pool_sources() -> Vec<std::path::PathBuf> {
    let library = library_dir();
    let contract = library.join("../tos-shielded-pool-v1.fc");
    let mut sources = vec![stdlib_path()];
    for name in [
        "domains.fc",
        "empty-roots.fc",
        "notes.fc",
        "tree.fc",
        "imt.fc",
        "auth.fc",
        "payload.fc",
        "domain.fc",
        "anchors.fc",
        "state.fc",
        "transact.fc",
        "groth16.fc",
        "payout.fc",
        "recovery.fc",
    ] {
        sources.push(library.join(name));
    }
    sources.push(contract);
    sources
}

impl Pool {
    pub fn deploy(commitment_root: Fr, nullifier_root: Fr) -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("relay", 1_000_000 * TOS)?;
        let code = compile_func(&pool_sources())?;
        let si =
            StateInit::with_code_and_data(code, genesis_state(commitment_root, nullifier_root)?);
        let addr_hash = si
            .write_to_new_cell()
            .and_then(|builder| builder.into_cell())
            .map_err(|error| CrossCheckError::Sandbox(format!("state init: {error}")))?
            .hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash)
            .map_err(|error| CrossCheckError::Sandbox(format!("address: {error}")))?;
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 100 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )?
        .expect_success();
        Ok(Self { bc, addr, payer })
    }

    /// The pool's own account id, which the execution domain is built from.
    pub fn account(&self) -> Result<[u8; 32]> {
        let bytes = self.addr.address().get_bytestring(0);
        let mut out = [0u8; 32];
        if bytes.len() != 32 {
            return Err(CrossCheckError::Sandbox("an account id that is not 32 bytes".to_string()));
        }
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    pub fn get(&self, method: &str) -> Result<String> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, vec![])
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!("{method} exited {}", result.exit_code)));
        }
        let top = result
            .stack
            .last()
            .ok_or_else(|| CrossCheckError::Vm(format!("{method} returned nothing")))?;
        Ok(top
            .as_integer()
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?
            .to_string())
    }

    pub fn send(&mut self, value: u64, body: Cell) -> Result<SendResult> {
        let msg = MessageBuilder::internal(self.payer.address(), &self.addr, value)
            .bounce(true)
            .body(body)
            .build();
        Ok(self.bc.send_message(msg)?)
    }

    /// The exit code and the gas it took to get there.
    pub fn run(&mut self, value: u64, body: Cell) -> Result<(i32, i64)> {
        let result = self.send(value, body)?;
        match result.read_primary_description().compute_ph {
            chain_block::TrComputePhase::Vm(vm) => Ok((
                vm.exit_code,
                vm.gas_used
                    .to_string()
                    .parse()
                    .map_err(|error| CrossCheckError::Vm(format!("gas used: {error}")))?,
            )),
            chain_block::TrComputePhase::Skipped(s) => {
                Err(CrossCheckError::Vm(format!("compute skipped: {:?}", s.reason)))
            }
        }
    }

    /// Section 12.1's deposit body.
    pub fn deposit_body(amount: u64, owner_commitment: Fr, payload: Cell) -> Result<Cell> {
        let mut builder = BuilderData::new();
        builder
            .append_u32(OP_DEPOSIT)
            .and_then(|b| b.append_u64(1))
            .map_err(|error| CrossCheckError::Sandbox(format!("deposit header: {error}")))?;
        store_coins(&mut builder, u128::from(amount))?;
        builder
            .append_raw(&be(owner_commitment), 256)
            .and_then(|b| b.checked_append_reference(payload))
            .map_err(|error| CrossCheckError::Sandbox(format!("deposit body: {error}")))?;
        cell_of(builder)
    }
}

/// `addr_none$00`, the only recipient a transfer may name.
pub fn addr_none(builder: &mut BuilderData) -> Result<()> {
    builder
        .append_bits(0, 2)
        .map_err(|error| CrossCheckError::Sandbox(format!("addr_none: {error}")))?;
    Ok(())
}

/// A cell holding only references, which is what the frozen bundles are.
pub fn refs_only(cells: &[Cell]) -> Result<Cell> {
    let mut builder = BuilderData::new();
    for cell in cells {
        builder
            .checked_append_reference(cell.clone())
            .map_err(|error| CrossCheckError::Sandbox(format!("bundle: {error}")))?;
    }
    cell_of(builder)
}
