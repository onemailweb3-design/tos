/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 13.2: the state a shielded pool is deployed with.
//!
//! There is no admin key and no upgrade path in this design, so the genesis
//! state is the deployment. Its hash is the contract's address, and every
//! number in it -- the fee, the denominations, the three hashes that pin the
//! profile, the parameters and the verifying key -- is fixed for good at the
//! moment it is built.
//!
//! Which is why this is a generator with a frozen manifest rather than a
//! fixture. A hand-built state agrees with itself; what has to be true is that
//! the state a test deploys and the state a deployment ships are the same
//! object, and that neither has drifted from the documents they claim to pin.

use ark_ff::{BigInteger, PrimeField};
use chain_block::{BuilderData, Cell, IBitstring, Serializable};
use sha2::{Digest, Sha256};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{imt, tree};

pub mod manifest;

/// Section 13.1.
pub const STATE_MAGIC: u32 = 0x5350_5631;
pub const STATE_VERSION: u16 = 1;
/// Section 13.2: "not yet recorded", and not a very late epoch.
pub const EPOCH_NONE: u32 = 0xffff_ffff;
/// Section 13.1: at most sixteen sorted unique positive amounts.
pub const MAX_DENOMINATIONS: usize = 16;
/// Section 10.1.
pub const VK_BYTES: usize = 1248;

#[derive(Debug)]
pub enum Error {
    Parameter(String),
    Encoding(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parameter(message) => write!(f, "parameter: {message}"),
            Error::Encoding(message) => write!(f, "encoding: {message}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn encoding<E: std::fmt::Display>(error: E) -> Error {
    Error::Encoding(error.to_string())
}

/// What a deployment chooses. Everything else in the state is derived.
#[derive(Clone, Debug)]
pub struct Parameters {
    /// The exact bytes of `doc/shielded-pool-v1-profile.md`, LF-normalised.
    pub profile_bytes: Vec<u8>,
    /// The exact bytes of `crypto/poseidon2/manifest.bin`.
    pub poseidon_manifest_bytes: Vec<u8>,
    /// The canonical 1248-byte verifying key stream of section 10.1.
    pub verifying_key: Vec<u8>,
    /// Section 14.3, positive.
    pub reserve_floor: u128,
    /// Section 14.2, positive and immutable for the deployment.
    pub withdrawal_fee: u128,
    /// Sorted, unique, positive, at most sixteen.
    pub denominations: Vec<u128>,
}

/// `profile_hash`, the exact document anchor of section 13.1.
///
/// A changed normative profile changes this, which changes the config store,
/// which changes the state hash, which changes the deployment address. That is
/// the point: the document cannot drift away from the deployment quietly.
pub fn profile_hash(profile_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TOS-SHIELDED-PROFILE-DOC-v1\0");
    hasher.update(profile_bytes);
    hasher.finalize().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// A field element as its 32 canonical big-endian bytes.
pub fn fr_be32(value: Fr) -> [u8; 32] {
    let digits = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(&digits);
    out
}

/// Coins are a VarUInteger 16: four bits of byte length, then the bytes.
fn store_coins(builder: &mut BuilderData, amount: u128) -> Result<()> {
    let bytes = amount.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    let length = bytes.len() - first;
    builder.append_bits(length, 4).map_err(encoding)?;
    if length > 0 {
        builder.append_raw(&bytes[first..], length * 8).map_err(encoding)?;
    }
    Ok(())
}

fn finish(builder: BuilderData) -> Result<Cell> {
    builder.into_cell().map_err(encoding)
}

/// Section 3's canonical byte chain: 127 bytes per cell until the last.
pub fn byte_chain(bytes: &[u8]) -> Result<Cell> {
    if bytes.is_empty() {
        return Err(Error::Encoding("an empty byte chain".to_string()));
    }
    let chunks: Vec<&[u8]> = bytes.chunks(127).collect();
    let mut cell: Option<Cell> = None;
    for chunk in chunks.iter().rev() {
        let mut builder = BuilderData::new();
        builder.append_raw(chunk, chunk.len() * 8).map_err(encoding)?;
        if let Some(next) = cell {
            builder.checked_append_reference(next).map_err(encoding)?;
        }
        cell = Some(finish(builder)?);
    }
    cell.ok_or_else(|| Error::Encoding("an empty byte chain".to_string()))
}

/// Section 13.1: a strictly ascending chain, one amount per cell.
fn denomination_chain(amounts: &[u128]) -> Result<Cell> {
    let mut chain: Option<Cell> = None;
    for amount in amounts.iter().rev() {
        let mut builder = BuilderData::new();
        store_coins(&mut builder, *amount)?;
        if let Some(next) = chain {
            builder.checked_append_reference(next).map_err(encoding)?;
        }
        chain = Some(finish(builder)?);
    }
    chain.ok_or_else(|| Error::Encoding("an empty denomination list".to_string()))
}

/// `config_store` of section 13.1.
pub fn config_store(parameters: &Parameters) -> Result<Cell> {
    let mut builder = BuilderData::new();
    builder.append_raw(&profile_hash(&parameters.profile_bytes), 256).map_err(encoding)?;
    builder.append_raw(&sha256(&parameters.poseidon_manifest_bytes), 256).map_err(encoding)?;
    builder.append_raw(&sha256(&parameters.verifying_key), 256).map_err(encoding)?;
    store_coins(&mut builder, parameters.withdrawal_fee)?;
    let count = u8::try_from(parameters.denominations.len())
        .map_err(|_| Error::Parameter("more than 255 denominations".to_string()))?;
    builder.append_u8(count).map_err(encoding)?;
    builder
        .checked_append_reference(denomination_chain(&parameters.denominations)?)
        .map_err(encoding)?;
    finish(builder)
}

/// Section 5.3's frontier store at genesis: twelve levels in order, seven
/// slots each, every slot zero, three field elements to a cell.
///
/// This was an absent `Maybe ^Cell` until 2026-09-21, when the store stopped
/// being a dictionary. Nothing reads a zero here: an append takes the level's
/// empty root for every slot above its digit, and at index zero every digit
/// is zero.
fn frontier_genesis() -> Result<Cell> {
    let zero = [0u8; 32];
    let mut chain: Option<Cell> = None;
    for level in (0..12usize).rev() {
        let last = level == 11;
        let mut third = BuilderData::new();
        third.append_raw(&zero, 256).map_err(encoding)?;
        let third = finish(third)?;

        let mut second = BuilderData::new();
        for _ in 0..3 {
            second.append_raw(&zero, 256).map_err(encoding)?;
        }
        second.checked_append_reference(third).map_err(encoding)?;
        let second = finish(second)?;

        let mut node = BuilderData::new();
        for _ in 0..3 {
            node.append_raw(&zero, 256).map_err(encoding)?;
        }
        node.checked_append_reference(second).map_err(encoding)?;
        if !last {
            let next = chain.take().ok_or_else(|| {
                Error::Encoding("a frontier level below the last has no successor".to_string())
            })?;
            node.checked_append_reference(next).map_err(encoding)?;
        }
        chain = Some(finish(node)?);
    }
    chain.ok_or_else(|| Error::Encoding("an empty frontier chain".to_string()))
}

/// Section 13's holder for the frontier reference: a `Maybe ^Cell` that is
/// present and points at the level chain. The holder is still a maybe because
/// a state cell can arrive from outside with the frontier absent, and the
/// contract has to be able to read that in order to refuse it.
fn frontier_store(frontier: Cell) -> Result<Cell> {
    let mut builder = BuilderData::new();
    builder.append_bit_one().map_err(encoding)?;
    builder.checked_append_reference(frontier).map_err(encoding)?;
    finish(builder)
}

fn empty_holder() -> Result<Cell> {
    let mut builder = BuilderData::new();
    builder.append_bit_zero().map_err(encoding)?;
    finish(builder)
}

/// Section 6.1: the two rings, each in its own holder.
pub fn anchors_empty() -> Result<Cell> {
    let mut builder = BuilderData::new();
    builder.checked_append_reference(empty_holder()?).map_err(encoding)?;
    builder.checked_append_reference(empty_holder()?).map_err(encoding)?;
    finish(builder)
}

/// Every parameter section 13.2 constrains, checked before anything is built.
/// A state that would be refused by the contract is not a state worth having a
/// manifest for.
fn validate(parameters: &Parameters) -> Result<()> {
    if parameters.reserve_floor == 0 {
        return Err(Error::Parameter("the reserve floor must be positive".to_string()));
    }
    if parameters.withdrawal_fee == 0 {
        return Err(Error::Parameter("the withdrawal fee must be positive".to_string()));
    }
    if parameters.denominations.is_empty() {
        return Err(Error::Parameter("the denomination list is empty".to_string()));
    }
    if parameters.denominations.len() > MAX_DENOMINATIONS {
        return Err(Error::Parameter(format!(
            "{} denominations, more than the {MAX_DENOMINATIONS} allowed",
            parameters.denominations.len()
        )));
    }
    let mut previous = 0u128;
    for amount in &parameters.denominations {
        if *amount == 0 {
            return Err(Error::Parameter("a denomination of zero".to_string()));
        }
        if *amount <= previous {
            return Err(Error::Parameter(
                "the denominations are not strictly ascending".to_string(),
            ));
        }
        previous = *amount;
    }
    if parameters.verifying_key.len() != VK_BYTES {
        return Err(Error::Parameter(format!(
            "a {}-byte verifying key, not {VK_BYTES}",
            parameters.verifying_key.len()
        )));
    }
    Ok(())
}

/// The genesis state, and everything that went into it.
pub struct Genesis {
    pub state: Cell,
    pub commitment_root: Fr,
    pub nullifier_root: Fr,
    pub parameters: Parameters,
}

/// Section 13.2, built once and pinned.
pub fn build(parameters: Parameters) -> Result<Genesis> {
    validate(&parameters)?;

    // Both roots are derived, never configured: an empty commitment tree and
    // a nullifier tree holding only the head sentinel.
    let commitment_root = tree::Frontier::new().empty_root();
    let nullifier_root = imt::State::genesis().root();

    let mut builder = BuilderData::new();
    builder
        .append_u32(STATE_MAGIC)
        .and_then(|b| b.append_u16(STATE_VERSION))
        .and_then(|b| b.append_raw(&fr_be32(commitment_root), 256))
        .and_then(|b| b.append_u64(0))
        .and_then(|b| b.append_raw(&fr_be32(nullifier_root), 256))
        .and_then(|b| b.append_u64(1))
        .and_then(|b| b.append_u32(EPOCH_NONE))
        .map_err(encoding)?;
    store_coins(&mut builder, 0)?;
    store_coins(&mut builder, parameters.reserve_floor)?;
    builder
        .checked_append_reference(frontier_store(frontier_genesis()?)?)
        .and_then(|b| b.checked_append_reference(anchors_empty()?))
        .and_then(|b| b.checked_append_reference(config_store(&parameters)?))
        .and_then(|b| b.checked_append_reference(byte_chain(&parameters.verifying_key)?))
        .map_err(encoding)?;

    Ok(Genesis { state: finish(builder)?, commitment_root, nullifier_root, parameters })
}

/// The deployment address, given the compiled contract code.
pub fn address(code: &Cell, state: &Cell) -> Result<[u8; 32]> {
    let init = chain_block::StateInit::with_code_and_data(code.clone(), state.clone());
    let hash =
        init.write_to_new_cell().and_then(|builder| builder.into_cell()).map_err(encoding)?.hash(0);
    let bytes = hash.as_slice();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
