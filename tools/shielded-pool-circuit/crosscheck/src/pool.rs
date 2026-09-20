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

/// The parameters a test pool is deployed with.
///
/// This goes through `shielded-pool-genesis` rather than assembling a state
/// cell here. A hand-built fixture agrees with itself; what has to be true is
/// that the state these tests deploy and the state a deployment ships are the
/// same object, built by the same code. `genesis_vs_vm.rs` holds that
/// generator against the contract's own `state_genesis`.
fn parameters(denominations: &[u64]) -> Result<shielded_pool_genesis::Parameters> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let profile = std::fs::read(root.join("doc/shielded-pool-v1-profile.md"))
        .map_err(|error| CrossCheckError::Fixture(format!("the profile copy: {error}")))?;
    let poseidon = std::fs::read(root.join("crypto/poseidon2/manifest.bin"))
        .map_err(|error| CrossCheckError::Fixture(format!("the Poseidon2 manifest: {error}")))?;
    Ok(shielded_pool_genesis::Parameters {
        profile_bytes: profile,
        poseidon_manifest_bytes: poseidon,
        verifying_key: development_vk_bytes()?,
        reserve_floor: u128::from(RESERVE_FLOOR),
        withdrawal_fee: u128::from(WITHDRAWAL_FEE),
        denominations: denominations.iter().map(|amount| u128::from(*amount)).collect(),
    })
}

fn genesis_state(denominations: &[u64]) -> Result<Cell> {
    let genesis = shielded_pool_genesis::build(parameters(denominations)?)
        .map_err(|error| CrossCheckError::Fixture(format!("the genesis state: {error}")))?;
    Ok(genesis.state)
}

/// The shielded pool, deployed.
pub struct Pool {
    pub bc: Blockchain,
    pub addr: MsgAddressInt,
    payer: tos_sandbox::Treasury,
}

/// Every FunC source the pool is built from, in dependency order.
pub fn pool_sources() -> Vec<std::path::PathBuf> {
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
    /// The pool as every test but the dust measurement wants it: one
    /// denomination.
    ///
    /// The roots are not arguments. Section 13.2 derives both of them -- an
    /// empty commitment tree and a nullifier tree holding only the head
    /// sentinel -- so a caller that could choose them could deploy a pool that
    /// no prover agrees with.
    pub fn deploy() -> Result<Self> {
        Self::deploy_with_denominations(&[DENOMINATION])
    }

    pub fn deploy_with_denominations(denominations: &[u64]) -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("relay", 1_000_000 * TOS)?;
        let code = compile_func(&pool_sources())?;
        let si = StateInit::with_code_and_data(code, genesis_state(denominations)?);
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

    /// Move the pool to the state a mature one would hold: `index` leaves
    /// appended, and both anchor rings at the given occupancy.
    ///
    /// Nothing else changes -- the same code, the same verifying key, the
    /// same configuration and the same balance. What changes is the three
    /// places whose cost depends on how long the pool has been running, and
    /// the point is to send the contract a real message once they do.
    ///
    /// The commitment root is left as it was. A deposit does not read it, and
    /// inventing one that matched the substituted frontier would mean
    /// reimplementing the tree here to no purpose.
    pub fn age_to(&mut self, index: u64, frontier: Cell, anchors: Cell) -> Result<()> {
        let mut account = self
            .bc
            .get_account(&self.addr)
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no account".to_string()))?
            .clone();
        let data = account
            .get_data()
            .ok_or_else(|| CrossCheckError::Sandbox("the pool has no data".to_string()))?;

        let mut slice = chain_block::SliceData::load_cell(data.clone())
            .map_err(|error| CrossCheckError::Sandbox(format!("state slice: {error}")))?;
        if slice.remaining_references() != 4 {
            return Err(CrossCheckError::Sandbox(
                "the state cell does not have the four references section 13 fixes".to_string(),
            ));
        }
        // magic, version, commitment root: copied. Then the index, replaced.
        let head = slice
            .get_next_bits(32 + 16 + 256)
            .map_err(|error| CrossCheckError::Sandbox(format!("state head: {error}")))?;
        let old_index = slice
            .get_next_int(64)
            .map_err(|error| CrossCheckError::Sandbox(format!("state index: {error}")))?;
        if old_index >= index {
            return Err(CrossCheckError::Fixture(format!(
                "aging to {index} would move the pool backwards from {old_index}"
            )));
        }
        let tail_bits = slice.remaining_bits();
        let tail = slice
            .get_next_bits(tail_bits)
            .map_err(|error| CrossCheckError::Sandbox(format!("state tail: {error}")))?;

        let mut builder = BuilderData::new();
        builder
            .append_raw(&head, 32 + 16 + 256)
            .and_then(|b| b.append_u64(index))
            .and_then(|b| b.append_raw(&tail, tail_bits))
            .map_err(|error| CrossCheckError::Sandbox(format!("aged state bits: {error}")))?;

        // The frontier store is section 13's maybe-ref holder, not the
        // dictionary itself.
        let mut holder = BuilderData::new();
        holder
            .append_bit_one()
            .and_then(|b| b.checked_append_reference(frontier))
            .map_err(|error| CrossCheckError::Sandbox(format!("frontier holder: {error}")))?;
        let holder = cell_of(holder)?;

        let config = data
            .reference(2)
            .map_err(|error| CrossCheckError::Sandbox(format!("config ref: {error}")))?;
        let vk = data
            .reference(3)
            .map_err(|error| CrossCheckError::Sandbox(format!("vk ref: {error}")))?;
        for reference in [holder, anchors, config, vk] {
            builder
                .checked_append_reference(reference)
                .map_err(|error| CrossCheckError::Sandbox(format!("aged state ref: {error}")))?;
        }

        if !account.set_data(cell_of(builder)?) {
            return Err(CrossCheckError::Sandbox("the pool refused new data".to_string()));
        }
        self.bc.set_account(self.addr.clone(), account);
        Ok(())
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
