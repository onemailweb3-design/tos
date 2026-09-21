/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The bytes a real node needs in order to hold a shielded pool, take two
//! deposits and pay a proved withdrawal out.
//!
//! Every gas figure, every root and every refusal in this project was measured
//! in a sandbox executor. That executor is the same code a validator runs, but
//! running it is not the same as running a chain: nothing measured there has
//! been through block production, a real message queue, real forward fees or a
//! real account balance.
//!
//! This writes the deployment and one whole scenario out so that it can be. It
//! is deliberately not a second implementation of anything: the code comes
//! from `pool_sources()`, the state from
//! `shielded_pool_genesis::development_parameters`, the message bodies from
//! `Pool::deposit_body` and `Transact::body`, and the roots the chain is
//! expected to reach from the circuit's own reference tree -- so every on-chain
//! check is a prediction made before the message is sent, not a read-back.
//! The same scenario is then run in the sandbox, so the two can be compared
//! for identical bytes.
//!
//! Two couplings decide whether a proof made here is valid there, and both are
//! recorded in the fixture rather than assumed:
//!
//!   * **the chain's `global_id`** goes into the execution domain, which is
//!     eight of the eighteen public inputs. A proof built for one chain is
//!     refused by another.
//!   * **`valid_until`** must be within section 9's one-hour intent window of
//!     the moment the transact executes. A fixture is perishable.
//!
//! Usage: `onchain-fixture <repo root> <output directory>`

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ark_ff::AdditiveGroup;
use chain_block::{write_boc, Cell, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::circuit::{HeldNote, ShieldedTransactionCircuit, TransactionBuilder};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::wire::{output_data_hash, OUTPUT_DATA_BYTES};
use shielded_pool_circuit::{groth16, imt, notes, scenario, tree, wire};
use shielded_pool_circuit_crosscheck::pool::{
    dec, development_vk_bytes, pool_sources, Pool, DENOMINATION, WITHDRAWAL_FEE,
};
use shielded_pool_circuit_crosscheck::transact::{Anchor, AuthKey, Recipient, Transact};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use shielded_pool_circuit_crosscheck::{stdlib_path, ACTIVE_VERSION};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};

/// Section 14.1's ceilings, which are what a sender funds -- not what the path
/// will use. `shielded_pool_sandbox.rs` fails if these stop agreeing with the
/// contract's own constants.
const DEPOSIT_GAS_CEILING: u64 = 220_000;
const TRANSACT_GAS_CEILING: u64 = 1_460_000;

/// Section 9's intent window is an hour. Half of it leaves room for a build,
/// a chain to come up and three messages to land.
const INTENT_LIFETIME: u32 = 1_800;

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

/// A destination that takes the money, so the payout succeeds and nothing
/// bounces. The recovery path has its own coverage in the sandbox; what a
/// chain has never done is pay one out at all.
const ACCEPTER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

/// The owners this fixture deposits to. Fixed, so that two runs differ only
/// in the one thing that cannot be fixed: the ML-DSA keys, which have no
/// deterministic constructor here.
const OWNER_NF_KEY: [u64; 2] = [0x5348_5f4f_574e_4530, 0x5348_5f4f_574e_4531];
const NOTE_SECRET: [u64; 2] = [0x5348_5f53_4543_5230, 0x5348_5f53_4543_5231];
const PAYLOAD_SEED: [u8; 2] = [0x31, 0x32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn payload(seed: u8) -> Vec<u8> {
    (0..OUTPUT_DATA_BYTES as u32).map(|index| (index as u8) ^ seed).collect()
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    eprintln!("wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn write_cell(path: &Path, cell: &Cell) -> Result<(), Box<dyn std::error::Error>> {
    write(path, &write_boc(cell)?)
}

fn account_of(address: &MsgAddressInt) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = address.address().get_bytestring(0);
    if bytes.len() != 32 {
        return Err("an account id that is not 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn address_of(code: &Cell, data: &Cell) -> Result<MsgAddressInt, Box<dyn std::error::Error>> {
    let init = StateInit::with_code_and_data(code.clone(), data.clone());
    let hash = init.write_to_new_cell().and_then(|builder| builder.into_cell())?.hash(0);
    Ok(MsgAddressInt::with_params(0, hash)?)
}

/// One note the pool will mint, with everything the prover needs to spend it.
struct Note {
    key: AuthKey,
    owner_nf_key: Fr,
    note_secret: Fr,
    payload: Vec<u8>,
    data_hash: Fr,
    owner: Fr,
    leaf_index: u64,
}

impl Note {
    fn new(slot: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let key = AuthKey::generate()?;
        let owner_nf_key = Fr::from(OWNER_NF_KEY[slot]);
        let note_secret = Fr::from(NOTE_SECRET[slot]);
        let payload = payload(PAYLOAD_SEED[slot]);
        let data_hash = output_data_hash(&payload);
        let owner = notes::owner_commitment(
            notes::owner_nf_key_hash(owner_nf_key),
            key.hash(),
            note_secret,
        );
        Ok(Self {
            key,
            owner_nf_key,
            note_secret,
            payload,
            data_hash,
            owner,
            leaf_index: slot as u64,
        })
    }

    fn deposit_body(&self) -> Result<Cell, Box<dyn std::error::Error>> {
        Ok(Pool::deposit_body(DENOMINATION, self.owner, byte_chain(&self.payload)?)?)
    }

    /// The leaf the contract will commit for this note at its index.
    fn leaf(&self) -> Fr {
        let body =
            notes::note_body_commitment(self.owner, Fr::from(u128::from(DENOMINATION)), self.data_hash);
        notes::note_commitment(body, Fr::from(self.leaf_index))
    }

    fn held(&self) -> HeldNote {
        HeldNote {
            is_phantom: false,
            owner_nf_key: self.owner_nf_key,
            note_secret: self.note_secret,
            amount: Fr::from(u128::from(DENOMINATION)),
            output_data_hash: self.data_hash,
            leaf_index: self.leaf_index,
        }
    }
}

/// The three message bodies, and what each one must leave behind.
struct Scenario {
    deposits: [Cell; 2],
    roots_after_deposit: [Fr; 2],
    transact: Cell,
    nullifier_root_after: Fr,
    commitment_root_after: Fr,
    valid_until: u32,
    payout: u64,
}

#[allow(clippy::too_many_arguments)]
fn build_scenario(
    global_id: i32,
    pool_account: &[u8; 32],
    destination_account: &[u8; 32],
    the_notes: &[Note; 2],
    valid_until: u32,
) -> Result<Scenario, Box<dyn std::error::Error>> {
    let domain = wire::execution_domain(global_id, pool_account);

    // The tree, as the contract will build it: two deposits, in order.
    let mut frontier = tree::Frontier::new();
    let mut roots_after_deposit = [Fr::ZERO; 2];
    for (slot, note) in the_notes.iter().enumerate() {
        let (assigned, root) = frontier.append(note.leaf())?;
        if assigned != note.leaf_index {
            return Err("the reference tree assigned another index".into());
        }
        roots_after_deposit[slot] = root;
    }
    let anchor_root = roots_after_deposit[1];

    // Two notes in, one denomination out to the destination, the configured
    // fee leaving with it, the change staying inside as three output notes.
    let change =
        u128::from(DENOMINATION) * 2 - u128::from(DENOMINATION) - u128::from(WITHDRAWAL_FEE);
    let recovery_owner_commitment = Fr::from(0x5eedu64);
    let recovery_payload = payload(0x77);
    let output_payloads = [payload(1), payload(2), payload(3)];
    let output_data_hashes = [
        output_data_hash(&output_payloads[0]),
        output_data_hash(&output_payloads[1]),
        output_data_hash(&output_payloads[2]),
    ];

    let mut outputs_of = scenario::Pool::new();
    let outputs = [
        outputs_of.real_output(Fr::from(change / 2)),
        outputs_of.real_output(Fr::from(change - change / 2)),
        outputs_of.dummy_output(),
    ];

    let builder = TransactionBuilder {
        execution_domain: domain,
        valid_until,
        intent_nonce: Fr::from(0xfeed_face_u64),
        public_amount_out: Fr::from(u128::from(DENOMINATION)),
        withdrawal_fee: Fr::from(u128::from(WITHDRAWAL_FEE)),
        public_recipient_hash: wire::public_recipient_hash(destination_account),
        recovery_template_hash: wire::recovery_template_hash(
            recovery_owner_commitment,
            output_data_hash(&recovery_payload),
        ),
        is_withdrawal: None,
        input_pq_auth_key_hash: [the_notes[0].key.hash(), the_notes[1].key.hash()],
        outputs,
        output_data_hash: output_data_hashes,
    };
    let (public, witness) = builder.build(
        &frontier,
        anchor_root,
        [the_notes[0].held(), the_notes[1].held()],
    )?;

    // The development keys. The pool was deployed with this verifying key's
    // hash inside its configuration, so a prover holding any other key
    // produces a proof the contract refuses -- checked here rather than
    // discovered on the chain.
    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))?;
    if groth16::canonical_verifying_key(&keys.verifying)?.bytes != development_vk_bytes()? {
        return Err("the prover's verifying key is not the one the pool was deployed with".into());
    }
    let proof = groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 3)?;
    let canonical = groth16::CanonicalProof::from_proof(&proof)?;

    let digest = public.transaction_intent_digest;
    let signatures = [the_notes[0].key.sign(digest)?, the_notes[1].key.sign(digest)?];

    // The two nullifier insertions, in the order the contract will do them:
    // the second witness is against the tree the first one left.
    let mut tree_state = imt::State::genesis();
    let (witness_0, after_first) = tree_state.witness_for(&public.nullifier_0)?;
    tree_state.apply(after_first);
    let (witness_1, after_second) = tree_state.witness_for(&public.nullifier_1)?;
    tree_state.apply(after_second);

    let transact = Transact {
        public: &public,
        proof: &canonical,
        anchor_root,
        anchor: Anchor::Current,
        valid_until,
        output_payloads: &output_payloads,
        keys: [&the_notes[0].key.public, &the_notes[1].key.public],
        signatures: &signatures,
        witnesses: &[witness_0, witness_1],
        public_amount_out: DENOMINATION,
        withdrawal_fee: WITHDRAWAL_FEE,
        recipient: Some(Recipient(*destination_account)),
        recovery_owner_commitment,
        recovery_payload: Some(recovery_payload),
    }
    .body()?;

    // Three outputs are appended after the two deposits, at indices 2, 3, 4.
    let mut after = frontier;
    let mut commitment_root_after = anchor_root;
    let bodies = [public.note_body_0, public.note_body_1, public.note_body_2];
    for (slot, note) in bodies.iter().enumerate() {
        let index = 2 + slot as u64;
        let (assigned, root) = after.append(notes::note_commitment(*note, Fr::from(index)))?;
        if assigned != index {
            return Err("an output note landed at another index".into());
        }
        commitment_root_after = root;
    }

    Ok(Scenario {
        deposits: [the_notes[0].deposit_body()?, the_notes[1].deposit_body()?],
        roots_after_deposit,
        transact,
        nullifier_root_after: tree_state.root(),
        commitment_root_after,
        valid_until,
        payout: DENOMINATION,
    })
}

/// The gas the sandbox executor charges for each of the three messages.
///
/// The same bytes, the same state, the same code. Every gas figure this
/// project quotes comes from this executor on the understanding that it is
/// what a validator runs; recording it here lets the on-chain harness compare
/// the two directly.
fn sandbox_gas(
    code: &Cell,
    state: &Cell,
    destination_code: &Cell,
    scenario: &Scenario,
    now: u32,
) -> Result<[i64; 3], Box<dyn std::error::Error>> {
    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
    bc.set_workchain(0);
    bc.set_now(now);
    let payer = bc.treasury("depositor", 1_000_000 * DENOMINATION)?;

    let deploy = |bc: &mut Blockchain, code: &Cell, data: &Cell, value: u64| {
        let init = StateInit::with_code_and_data(code.clone(), data.clone());
        let address = address_of(code, data)?;
        bc.send_message(
            MessageBuilder::internal(payer.address(), &address, value)
                .bounce(false)
                .state_init(init)
                .body(Cell::default())
                .build(),
        )?
        .expect_success();
        Ok::<MsgAddressInt, Box<dyn std::error::Error>>(address)
    };

    let pool = deploy(&mut bc, code, state, 100 * DENOMINATION)?;
    deploy(&mut bc, destination_code, &Cell::default(), 1 * DENOMINATION)?;

    let mut gas = [0i64; 3];
    let steps: [(&Cell, u64); 3] = [
        (&scenario.deposits[0], DENOMINATION + compute_fee(DEPOSIT_GAS_CEILING)),
        (&scenario.deposits[1], DENOMINATION + compute_fee(DEPOSIT_GAS_CEILING)),
        (&scenario.transact, compute_fee(TRANSACT_GAS_CEILING)),
    ];
    for (index, (body, value)) in steps.into_iter().enumerate() {
        let result = bc.send_message(
            MessageBuilder::internal(payer.address(), &pool, value)
                .bounce(true)
                .body(body.clone())
                .build(),
        )?;
        result.expect_success();
        gas[index] = match result.read_primary_description().compute_ph {
            chain_block::TrComputePhase::Vm(phase) => phase
                .gas_used
                .to_string()
                .parse()
                .map_err(|error| format!("the gas the sandbox charged: {error}"))?,
            chain_block::TrComputePhase::Skipped(_) => {
                return Err("a message skipped its compute phase".into())
            }
        };
    }
    Ok(gas)
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
    let genesis =
        shielded_pool_genesis::build(shielded_pool_genesis::development_parameters(&root)?)?;
    let state = genesis.state.clone();
    let pool_address = address_of(&code, &state)?;
    let pool_account = account_of(&pool_address)?;

    // Where the withdrawal goes. A contract that takes the money, deployed by
    // the harness at the address its own code hashes to.
    let accepter_path = std::env::temp_dir().join("tos_shielded_onchain_accepter.fc");
    std::fs::write(&accepter_path, ACCEPTER)?;
    let destination_code = compile_func(&[stdlib_path(), accepter_path])?;
    let destination_address = address_of(&destination_code, &Cell::default())?;
    let destination_account = account_of(&destination_address)?;

    // The chain's global id goes into the execution domain, and the domain is
    // eight of the eighteen public inputs. It is read from the sandbox rather
    // than written down, and the harness sets the chain it builds to match --
    // a proof built for one chain is refused by another.
    let global_id = shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()?.domain_inputs()?.0;

    let now = u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let valid_until = now + INTENT_LIFETIME;

    let the_notes = [Note::new(0)?, Note::new(1)?];
    eprintln!("proving the withdrawal for global_id {global_id} ...");
    let scenario =
        build_scenario(global_id, &pool_account, &destination_account, &the_notes, valid_until)?;

    eprintln!("running the same three messages in the sandbox ...");
    let gas = sandbox_gas(&code, &state, &destination_code, &scenario, now)?;
    eprintln!("the sandbox charges {} / {} / {} gas", gas[0], gas[1], gas[2]);

    write_cell(&out.join("code.boc"), &code)?;
    write_cell(&out.join("data.boc"), &state)?;
    write_cell(&out.join("destination-code.boc"), &destination_code)?;
    write_cell(&out.join("deposit-0.boc"), &scenario.deposits[0])?;
    write_cell(&out.join("deposit-1.boc"), &scenario.deposits[1])?;
    write_cell(&out.join("transact.boc"), &scenario.transact)?;

    let deposit_value = DENOMINATION + compute_fee(DEPOSIT_GAS_CEILING);
    let transact_value = compute_fee(TRANSACT_GAS_CEILING);
    let fixture = format!(
        concat!(
            "{{\n",
            "  \"note\": \"Generated by tools/shielded-pool-circuit/crosscheck onchain-fixture.",
            " Do not edit by hand.\",\n",
            "  \"workchain\": 0,\n",
            "  \"global_id\": {global_id},\n",
            "  \"built_at\": {built_at},\n",
            "  \"valid_until\": {valid_until},\n",
            "  \"address\": \"0:{address}\",\n",
            "  \"state_hash\": \"{state_hash}\",\n",
            "  \"code_hash\": \"{code_hash}\",\n",
            "  \"deploy_value_nanotos\": {deploy},\n",
            "  \"destination\": {{\n",
            "    \"address\": \"0:{destination}\",\n",
            "    \"code\": \"destination-code.boc\",\n",
            "    \"deploy_value_nanotos\": {destination_deploy},\n",
            "    \"expects_nanotos\": {payout}\n",
            "  }},\n",
            "  \"expected_at_genesis\": {{\n",
            "    \"commitment_root\": \"{empty_root}\",\n",
            "    \"nullifier_root\": \"{nullifier_root}\",\n",
            "    \"commitment_next_index\": 0,\n",
            "    \"native_liability\": 0\n",
            "  }},\n",
            "  \"steps\": [\n",
            "    {{\n",
            "      \"name\": \"the first deposit\",\n",
            "      \"body\": \"deposit-0.boc\",\n",
            "      \"value_nanotos\": {deposit_value},\n",
            "      \"gas_ceiling\": {deposit_ceiling},\n",
            "      \"sandbox_gas_used\": {gas0},\n",
            "      \"expect\": {{\n",
            "        \"commitment_root\": \"{root0}\",\n",
            "        \"commitment_next_index\": 1,\n",
            "        \"native_liability\": {one}\n",
            "      }}\n",
            "    }},\n",
            "    {{\n",
            "      \"name\": \"the second deposit\",\n",
            "      \"body\": \"deposit-1.boc\",\n",
            "      \"value_nanotos\": {deposit_value},\n",
            "      \"gas_ceiling\": {deposit_ceiling},\n",
            "      \"sandbox_gas_used\": {gas1},\n",
            "      \"expect\": {{\n",
            "        \"commitment_root\": \"{root1}\",\n",
            "        \"commitment_next_index\": 2,\n",
            "        \"native_liability\": {two}\n",
            "      }}\n",
            "    }},\n",
            "    {{\n",
            "      \"name\": \"the withdrawal\",\n",
            "      \"body\": \"transact.boc\",\n",
            "      \"value_nanotos\": {transact_value},\n",
            "      \"gas_ceiling\": {transact_ceiling},\n",
            "      \"sandbox_gas_used\": {gas2},\n",
            "      \"expect\": {{\n",
            "        \"commitment_root\": \"{root_after}\",\n",
            "        \"commitment_next_index\": 5,\n",
            "        \"nullifier_root\": \"{nullifier_after}\",\n",
            "        \"nullifier_next_index\": 3,\n",
            "        \"native_liability\": {liability_after}\n",
            "      }}\n",
            "    }}\n",
            "  ]\n",
            "}}\n"
        ),
        global_id = global_id,
        built_at = now,
        valid_until = scenario.valid_until,
        address = hex(pool_address.address().get_bytestring(0).as_slice()),
        state_hash = hex(&shielded_pool_genesis::manifest::cell_hash(&state)),
        code_hash = hex(code.repr_hash().as_slice()),
        deploy = 100u64 * DENOMINATION,
        destination = hex(destination_address.address().get_bytestring(0).as_slice()),
        destination_deploy = DENOMINATION,
        payout = scenario.payout,
        empty_root = dec(genesis.commitment_root),
        nullifier_root = dec(genesis.nullifier_root),
        deposit_value = deposit_value,
        deposit_ceiling = DEPOSIT_GAS_CEILING,
        transact_value = transact_value,
        transact_ceiling = TRANSACT_GAS_CEILING,
        gas0 = gas[0],
        gas1 = gas[1],
        gas2 = gas[2],
        root0 = dec(scenario.roots_after_deposit[0]),
        root1 = dec(scenario.roots_after_deposit[1]),
        root_after = dec(scenario.commitment_root_after),
        nullifier_after = dec(scenario.nullifier_root_after),
        one = DENOMINATION,
        two = 2 * DENOMINATION,
        // Two denominations came in; one denomination and the fee went out.
        liability_after = 2 * DENOMINATION - DENOMINATION - WITHDRAWAL_FEE,
    );
    write(&out.join("fixture.json"), fixture.as_bytes())?;

    eprintln!("pool address 0:{}", hex(pool_account.as_slice()));
    eprintln!("the intent is valid until {} ({INTENT_LIFETIME}s from now)", scenario.valid_until);
    Ok(())
}
