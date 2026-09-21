/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The bytes a real node needs in order to hold a shielded pool.
//!
//! Every gas figure, every root and every refusal in this project was measured
//! in a sandbox executor. That executor is the same code a validator runs, but
//! running it is not the same as running a chain: nothing here has ever been
//! through block production, a real message queue, real forward fees or a real
//! account balance.
//!
//! This writes the deployment out so that it can be. It is deliberately not a
//! second implementation of anything: the code comes from `pool_sources()`, the
//! state from `shielded_pool_genesis::development_parameters`, the deposit body
//! from `Pool::deposit_body`, and the commitment root the chain is expected to
//! reach afterwards from the circuit's own reference tree -- so the on-chain
//! check is a prediction made before the message is sent, not a read-back.
//!
//! Usage: `onchain-fixture <repo root> <output directory>`

use std::path::{Path, PathBuf};

use chain_block::{write_boc, Cell, Serializable, StateInit};
use ark_ff::AdditiveGroup;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::wire::{output_data_hash, OUTPUT_DATA_BYTES};
use shielded_pool_circuit::{notes, tree};
use shielded_pool_circuit_crosscheck::pool::{dec, pool_sources, Pool, DENOMINATION};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use tos_sandbox::compile_func;

/// Section 14.1's deposit ceiling, which is what a depositor funds -- not what
/// the path will use. Kept next to the contract's own constant by
/// `shielded_pool_sandbox.rs`, which fails if the two stop agreeing.
const DEPOSIT_GAS_CEILING: u64 = 220_000;

/// This chain's ConfigParam 21, as the VM applies it: a flat 6,667 for the
/// first hundred gas, then 4,369,067 per 65,536 gas, the division rounded up.
fn compute_fee(gas: u64) -> u64 {
    const FLAT_LIMIT: u64 = 100;
    const FLAT_PRICE: u64 = 6_667;
    const GAS_PRICE: u64 = 4_369_067;
    if gas <= FLAT_LIMIT {
        FLAT_PRICE
    } else {
        FLAT_PRICE + ((gas - FLAT_LIMIT) * GAS_PRICE).div_ceil(65_536)
    }
}

/// The one owner this fixture deposits to. A fixed seed, because the point is
/// that two runs of this program produce the same bytes.
const OWNER_NF_KEY: u64 = 0x5348_5f4f_574e_4552;
const NOTE_SECRET: u64 = 0x5348_5f53_4543_5245;
const PQ_KEY_HASH: u64 = 0x5348_5f50_515f_4b45;
const PAYLOAD_SEED: u8 = 0x5a;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    eprintln!("wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn write_cell(path: &Path, cell: &Cell) -> Result<(), Box<dyn std::error::Error>> {
    write(path, &write_boc(cell)?)
}

/// Deploys the pool in the sandbox executor and sends it one deposit, exactly
/// as the chain harness will, and returns the gas the executor charged.
fn sandbox_deposit_gas(
    code: &Cell,
    state: &Cell,
    deposit: &Cell,
    value: u64,
) -> Result<i64, Box<dyn std::error::Error>> {
    use tos_sandbox::{Blockchain, MessageBuilder};

    const ACTIVE_VERSION: u32 = 18;
    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
    bc.set_workchain(0);
    let payer = bc.treasury("depositor", 1_000_000 * DENOMINATION)?;

    let init = StateInit::with_code_and_data(code.clone(), state.clone());
    let hash = init.write_to_new_cell().and_then(|builder| builder.into_cell())?.hash(0);
    let address = chain_block::MsgAddressInt::with_params(0, hash)?;
    bc.send_message(
        MessageBuilder::internal(payer.address(), &address, 100 * DENOMINATION)
            .bounce(false)
            .state_init(init)
            .body(Cell::default())
            .build(),
    )?
    .expect_success();

    let result = bc.send_message(
        MessageBuilder::internal(payer.address(), &address, value)
            .bounce(true)
            .body(deposit.clone())
            .build(),
    )?;
    result.expect_success();
    match result.read_primary_description().compute_ph {
        chain_block::TrComputePhase::Vm(phase) => Ok(phase
            .gas_used
            .to_string()
            .parse()
            .map_err(|error| format!("the gas the sandbox charged: {error}"))?),
        chain_block::TrComputePhase::Skipped(_) => {
            Err("the deposit skipped its compute phase".into())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(args.next().ok_or("usage: onchain-fixture <repo root> <out dir>")?);
    let out = PathBuf::from(args.next().ok_or("usage: onchain-fixture <repo root> <out dir>")?);
    std::fs::create_dir_all(&out).map_err(|error| format!("{}: {error}", out.display()))?;

    // The contract, compiled from the same source list every suite compiles.
    let code = compile_func(&pool_sources())?;

    // The state the frozen manifest names. Not a fixture: the generator's own
    // parameters, read out of the repository.
    let genesis = shielded_pool_genesis::build(shielded_pool_genesis::development_parameters(
        &root,
    )?)?;
    let state = genesis.state.clone();

    // The address, which is the hash of the two together. A deployment that
    // differs anywhere lands somewhere else, which is the design.
    let init = StateInit::with_code_and_data(code.clone(), state.clone());
    let address = init.write_to_new_cell().and_then(|builder| builder.into_cell())?.hash(0);

    // One deposit, and what the tree must hold afterwards. The owner
    // commitment and the payload are the depositor's; the note, the leaf index
    // and the root are the contract's to compute, and the values below are
    // this program's independent prediction of them.
    let payload: Vec<u8> = (0..OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ PAYLOAD_SEED).collect();
    let data_hash = output_data_hash(&payload);
    let owner = notes::owner_commitment(
        notes::owner_nf_key_hash(Fr::from(OWNER_NF_KEY)),
        Fr::from(PQ_KEY_HASH),
        Fr::from(NOTE_SECRET),
    );
    let deposit = Pool::deposit_body(DENOMINATION, owner, byte_chain(&payload)?)?;

    let body = notes::note_body_commitment(owner, Fr::from(u128::from(DENOMINATION)), data_hash);
    let leaf = notes::note_commitment(body, Fr::ZERO);
    let mut frontier = tree::Frontier::new();
    let (leaf_index, commitment_root) = frontier.append(leaf)?;

    write_cell(&out.join("code.boc"), &code)?;
    write_cell(&out.join("data.boc"), &state)?;
    write_cell(&out.join("deposit.boc"), &deposit)?;

    // The same deposit, against the same state, in the sandbox executor.
    //
    // Every gas figure this project quotes comes from that executor, on the
    // understanding that it is the code a validator runs. The understanding
    // has never been checked. Recording what it charges here lets the on-chain
    // harness compare the two for one identical message, which is the only way
    // the claim can be wrong in a way anybody would notice.
    let message_value = DENOMINATION + compute_fee(DEPOSIT_GAS_CEILING);
    let sandbox_gas = sandbox_deposit_gas(&code, &state, &deposit, message_value)?;
    eprintln!("the sandbox charges {sandbox_gas} gas for this deposit");

    // Everything the harness has to know, and nothing it could have guessed.
    let fixture = format!(
        concat!(
            "{{\n",
            "  \"note\": \"Generated by tools/shielded-pool-circuit/crosscheck onchain-fixture.",
            " Do not edit by hand.\",\n",
            "  \"workchain\": 0,\n",
            "  \"address\": \"0:{address}\",\n",
            "  \"state_hash\": \"{state_hash}\",\n",
            "  \"code_hash\": \"{code_hash}\",\n",
            "  \"deploy_value_nanotos\": {deploy},\n",
            "  \"deposit\": {{\n",
            "    \"amount_nanotos\": {amount},\n",
            "    \"message_value_nanotos\": {value},\n",
            "    \"gas_ceiling\": {ceiling},\n",
            "    \"sandbox_gas_used\": {sandbox_gas},\n",
            "    \"owner_commitment\": \"{owner}\"\n",
            "  }},\n",
            "  \"expected_after_deposit\": {{\n",
            "    \"leaf_index\": {leaf_index},\n",
            "    \"commitment_next_index\": {next_index},\n",
            "    \"commitment_root\": \"{root}\",\n",
            "    \"native_liability\": {liability}\n",
            "  }},\n",
            "  \"expected_at_genesis\": {{\n",
            "    \"commitment_root\": \"{empty_root}\",\n",
            "    \"nullifier_root\": \"{nullifier_root}\"\n",
            "  }}\n",
            "}}\n"
        ),
        address = hex(address.as_slice()),
        state_hash = hex(&shielded_pool_genesis::manifest::cell_hash(&state)),
        code_hash = hex(code.repr_hash().as_slice()),
        // The deploy carries reserve, not liability: enough to clear the
        // reserve floor and pay the storage the account will owe.
        deploy = 100u64 * 1_000_000_000,
        amount = DENOMINATION,
        value = message_value,
        ceiling = DEPOSIT_GAS_CEILING,
        sandbox_gas = sandbox_gas,
        owner = dec(owner),
        leaf_index = leaf_index,
        next_index = leaf_index + 1,
        root = dec(commitment_root),
        liability = DENOMINATION,
        empty_root = dec(genesis.commitment_root),
        nullifier_root = dec(genesis.nullifier_root),
    );
    write(&out.join("fixture.json"), fixture.as_bytes())?;

    eprintln!("pool address 0:{}", hex(address.as_slice()));
    Ok(())
}
