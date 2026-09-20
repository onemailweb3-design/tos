/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! A withdrawal that is paid out, refused by its recipient, bounced by the
//! protocol and recovered into a note -- in one message cascade.
//!
//! This is what section 15.3 means by "a real outbound -> failure ->
//! protocol-generated bounce round trip", and it says plainly that a helper
//! which fabricates `bounced=true` is not evidence. The trip has to start with
//! the pool sending a payout, which is step 16 of section 16.2, which is after
//! the proof. So it could not be done until a proof verified. It can now.
//!
//! Nothing in the cascade below is arranged. The pool sends the payout because
//! its own handler decided to; the destination fails because it throws; the
//! bounce is the executor's; and the pool recovers because it authenticated
//! the record that came back.

use chain_block::{Cell, CommonMsgInfo, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::circuit::{HeldNote, ShieldedTransactionCircuit, TransactionBuilder};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{groth16, imt, notes, wire};
use shielded_pool_circuit_crosscheck::pool::{
    dec, development_vk_bytes, Pool, DENOMINATION, WITHDRAWAL_FEE,
};
use shielded_pool_circuit_crosscheck::transact::{AuthKey, Recipient, Transact};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;

/// A destination that refuses anything with a body, so the payout it is sent
/// fails in the compute phase and the protocol bounces it. It accepts its own
/// deployment, which carries none.
const REFUSER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  slice header = in_msg_full.begin_parse();
  int flags = header~load_uint(4);
  if (flags & 1) {
    return ();
  }
  if (in_msg_body.slice_empty?()) {
    return ();
  }
  throw(701);
}
() recv_external(slice in_msg) impure { }
"#;

/// A destination that takes the money, so the payout succeeds and nothing
/// bounces. The pair is what shows the recovery is caused by the bounce and
/// not by the withdrawal.
const ACCEPTER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

fn payload(seed: u8) -> Vec<u8> {
    (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ seed).collect()
}

/// Deploys the refuser into the pool's own chain, so the payout can reach it.
fn deploy_destination(bc: &mut Blockchain, name: &str, source: &str) -> MsgAddressInt {
    let path = std::env::temp_dir().join(format!("tos_shielded_round_trip_{name}.fc"));
    std::fs::write(&path, source).expect("write the destination");
    let stdlib = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../crypto/smartcont/stdlib.fc");
    let code = compile_func(&[stdlib, path]).expect("compile the destination");
    let si = StateInit::with_code_and_data(code, Cell::default());
    let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let addr = MsgAddressInt::with_params(0, hash).unwrap();
    let payer = bc.treasury(name, 1_000 * TOS).expect("treasury");
    bc.send_message(
        MessageBuilder::internal(payer.address(), &addr, 100 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build(),
    )
    .expect("deploy the destination")
    .expect_success();
    addr
}

fn account_of(addr: &MsgAddressInt) -> [u8; 32] {
    let bytes = addr.address().get_bytestring(0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// One note the pool minted, with everything the prover needs to spend it.
struct Held {
    key: AuthKey,
    owner_nf_key: Fr,
    note_secret: Fr,
    data_hash: Fr,
    leaf_index: u64,
}

/// What the pool ended up holding and owing after one withdrawal.
struct Outcome {
    pool_liability_before: u128,
    pool_liability_after: u128,
    commitment_next_index: String,
    nullifier_next_index: String,
    refused_at: Option<String>,
    bounced_from: Option<String>,
    destination: String,
    transactions: usize,
    holds: u128,
    reserve: u128,
}

/// One withdrawal of a single denomination to `destination`, proved and sent.
fn withdraw_to(name: &str, source: &str) -> Outcome {
    let mut frontier = shielded_pool_circuit::tree::Frontier::new();
    let nullifiers = imt::State::genesis();
    let mut pool = Pool::deploy(frontier.empty_root(), nullifiers.root()).expect("deploy the pool");
    let destination = deploy_destination(&mut pool.bc, name, source);

    let global_id = {
        let probe = shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
            .expect("deploy the wire probe");
        probe.domain_inputs().expect("the domain inputs").0
    };
    let domain = wire::execution_domain(global_id, &pool.account().expect("the pool's account"));

    // --- two notes, because a withdrawal has to cover its own fee ---------
    //
    // The denomination list holds one value, so two deposits are how the pool
    // comes to hold more than one of them. A withdrawal of one denomination
    // plus the configured fee cannot come out of a single note.
    let mut held = Vec::new();
    let mut root = frontier.empty_root();
    for (slot, seed) in [0x31u8, 0x32].into_iter().enumerate() {
        let key = AuthKey::generate().expect("an ML-DSA key");
        let owner_nf_key = Fr::from(0x1000_0000u64 + slot as u64);
        let note_secret = Fr::from(0x2000_0000u64 + slot as u64);
        let bytes = payload(seed);
        let data_hash = wire::output_data_hash(&bytes);
        let owner = notes::owner_commitment(
            notes::owner_nf_key_hash(owner_nf_key),
            key.hash(),
            note_secret,
        );
        pool.send(
            DENOMINATION + COMPUTE_FEE,
            Pool::deposit_body(DENOMINATION, owner, byte_chain(&bytes).expect("payload"))
                .expect("deposit body"),
        )
        .expect("deposit")
        .expect_success();

        let body =
            notes::note_body_commitment(owner, Fr::from(u128::from(DENOMINATION)), data_hash);
        let leaf_index = slot as u64;
        let leaf = notes::note_commitment(body, Fr::from(leaf_index));
        let (assigned, new_root) = frontier.append(leaf).expect("append");
        assert_eq!(assigned, leaf_index, "the contract assigned another index");
        held.push(Held { key, owner_nf_key, note_secret, data_hash, leaf_index });
        root = new_root;
    }
    assert_eq!(
        pool.get("commitment_root").expect("commitment root"),
        dec(root),
        "the prover's tree and the contract's disagree after two deposits"
    );

    // --- the withdrawal ---------------------------------------------------
    //
    // Two notes in, one denomination out to the refuser, the configured fee
    // leaving with it, and the change staying inside as three output notes.
    let change =
        u128::from(DENOMINATION) * 2 - u128::from(DENOMINATION) - u128::from(WITHDRAWAL_FEE);
    let recipient_account = account_of(&destination);
    let recipient_hash = wire::public_recipient_hash(&recipient_account);

    let recovery_owner_commitment = Fr::from(0x5eedu64);
    let recovery_payload = payload(0x77);
    let recovery_template_hash = wire::recovery_template_hash(
        recovery_owner_commitment,
        wire::output_data_hash(&recovery_payload),
    );

    let now: u32 = pool.bc.now().try_into().expect("a unix time");
    let valid_until = now + 600;
    let output_payloads = [payload(1), payload(2), payload(3)];
    let output_data_hash = [
        wire::output_data_hash(&output_payloads[0]),
        wire::output_data_hash(&output_payloads[1]),
        wire::output_data_hash(&output_payloads[2]),
    ];

    let mut scenario = shielded_pool_circuit::scenario::Pool::new();
    let outputs = [
        scenario.real_output(Fr::from(change / 2)),
        scenario.real_output(Fr::from(change - change / 2)),
        scenario.dummy_output(),
    ];

    let inputs = |index: usize| HeldNote {
        is_phantom: false,
        owner_nf_key: held[index].owner_nf_key,
        note_secret: held[index].note_secret,
        amount: Fr::from(u128::from(DENOMINATION)),
        output_data_hash: held[index].data_hash,
        leaf_index: held[index].leaf_index,
    };

    let builder = TransactionBuilder {
        execution_domain: domain,
        valid_until,
        intent_nonce: Fr::from(0xfeed_face_u64),
        public_amount_out: Fr::from(u128::from(DENOMINATION)),
        withdrawal_fee: Fr::from(u128::from(WITHDRAWAL_FEE)),
        public_recipient_hash: recipient_hash,
        recovery_template_hash,
        is_withdrawal: None,
        input_pq_auth_key_hash: [held[0].key.hash(), held[1].key.hash()],
        outputs,
        output_data_hash,
    };
    let (public, witness) =
        builder.build(&frontier, root, [inputs(0), inputs(1)]).expect("build the withdrawal");

    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))
        .expect("development keys");
    assert_eq!(
        groth16::canonical_verifying_key(&keys.verifying).expect("vk bytes").bytes,
        development_vk_bytes().expect("the fixture verifying key"),
        "the prover's verifying key is not the one the pool was deployed with"
    );
    let proof =
        groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 3).expect("prove");
    let canonical = groth16::CanonicalProof::from_proof(&proof).expect("canonical proof");

    let digest = public.transaction_intent_digest;
    let signatures = [
        held[0].key.sign(digest).expect("a signature"),
        held[1].key.sign(digest).expect("a signature"),
    ];

    let mut tree = nullifiers.clone();
    let (witness_0, after_first) = tree.witness_for(&public.nullifier_0).expect("first witness");
    tree.apply(after_first);
    let (witness_1, _) = tree.witness_for(&public.nullifier_1).expect("second witness");

    let body = Transact {
        public: &public,
        proof: &canonical,
        anchor_root: root,
        valid_until,
        output_payloads: &output_payloads,
        keys: [&held[0].key, &held[1].key],
        signatures: &signatures,
        witnesses: &[witness_0, witness_1],
        public_amount_out: DENOMINATION,
        withdrawal_fee: WITHDRAWAL_FEE,
        recipient: Some(Recipient(recipient_account)),
        recovery_owner_commitment,
        recovery_payload: Some(recovery_payload),
    }
    .body()
    .expect("a transact body");

    // --- the whole cascade, in one message -------------------------------
    let liability_before: u128 =
        pool.get("native_liability").expect("liability").parse().expect("a number");
    assert_eq!(
        liability_before,
        u128::from(DENOMINATION) * 2,
        "two deposits did not leave the pool owing two denominations"
    );

    let result = pool.send(COMPUTE_FEE * 4, body).expect("the withdrawal");

    // The transact itself succeeded.
    let description = result.read_primary_description();
    let exit = match description.compute_ph {
        chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
        chain_block::TrComputePhase::Skipped(s) => panic!("compute skipped: {:?}", s.reason),
    };
    assert_eq!(exit, 0, "the withdrawal was refused with exit {exit}");

    // At least the relay's message into the pool and the pool's payout out of
    // it. Whether a third follows is what the two tests below differ on.
    assert!(
        result.transaction_count() >= 2,
        "the pool sent no payout at all: {} transactions",
        result.transaction_count()
    );
    let transactions = result.transaction_count();
    let mut refused_at = None;
    let mut bounced_from = None;
    for (addr, tx) in &result.transactions {
        if let Ok(Some(msg)) = tx.read_in_msg() {
            if let CommonMsgInfo::IntMsgInfo(info) = msg.header() {
                if info.bounced {
                    bounced_from = info.src_ref().map(std::string::ToString::to_string);
                }
            }
        }
        if let Ok(chain_block::TransactionDescr::Ordinary(d)) = tx.read_description() {
            if let chain_block::TrComputePhase::Vm(vm) = &d.compute_ph {
                if vm.exit_code == 701 {
                    refused_at = Some(addr.to_string());
                }
            }
        }
    }

    let liability_after: u128 =
        pool.get("native_liability").expect("liability").parse().expect("a number");
    let balance = pool.bc.get_account(&pool.addr).expect("the pool account");
    Outcome {
        pool_liability_before: liability_before,
        pool_liability_after: liability_after,
        commitment_next_index: pool.get("commitment_next_index").expect("next index"),
        nullifier_next_index: pool.get("nullifier_next_index").expect("nullifier next index"),
        refused_at,
        bounced_from,
        destination: destination.to_string(),
        transactions,
        holds: balance.balance().map(|value| value.coins.as_u128()).expect("a balance"),
        reserve: pool.get("reserve_floor").expect("reserve floor").parse().expect("a number"),
    }
}

/// The trip section 15.3 asks for: the pool pays out, the recipient refuses,
/// the protocol bounces, and the record that travelled out comes back and
/// becomes a note again.
#[test]
fn a_withdrawal_that_is_refused_comes_back_as_a_note() {
    let outcome = withdraw_to("refuser", REFUSER);

    assert_eq!(
        outcome.refused_at.as_deref(),
        Some(outcome.destination.as_str()),
        "the recipient never refused the payout, so nothing bounced"
    );
    assert_eq!(
        outcome.bounced_from.as_deref(),
        Some(outcome.destination.as_str()),
        "no bounce came back from the address that refused"
    );
    assert_eq!(
        outcome.transactions, 3,
        "a round trip is the message in, the payout out, and the bounce back"
    );
    assert_eq!(outcome.nullifier_next_index, "3", "two nullifiers should have been spent");
    // Two deposits, three outputs from the transact, one recovery note.
    assert_eq!(outcome.commitment_next_index, "6", "the recovery did not mint a note");

    let paid_out = u128::from(DENOMINATION) + u128::from(WITHDRAWAL_FEE);
    let recovered = outcome.pool_liability_after + paid_out - outcome.pool_liability_before;
    eprintln!(
        "withdrew {DENOMINATION} and paid {WITHDRAWAL_FEE} in fees; \
         the bounce returned {recovered}"
    );
    assert!(recovered > 0, "nothing was recovered");

    // Section 15.4: the pool never restores more principal than actually came
    // back. What the recipient's compute and the bounce transport consumed is
    // the withdrawing user's loss, not a subsidy from everyone else's reserve.
    assert!(
        recovered < u128::from(DENOMINATION),
        "the pool minted back {recovered} of a {DENOMINATION} payout, more than returned"
    );
    assert!(
        outcome.holds >= outcome.pool_liability_after + outcome.reserve,
        "the pool owes {} with a {} floor and holds only {}",
        outcome.pool_liability_after,
        outcome.reserve,
        outcome.holds
    );
}

/// The same withdrawal to a recipient that takes the money. Nothing bounces,
/// nothing is recovered, and the pool stops owing what left. Without this the
/// test above would pass just as well if the recovery note were minted by the
/// withdrawal rather than by the bounce.
#[test]
fn a_withdrawal_that_is_taken_leaves_nothing_to_recover() {
    let outcome = withdraw_to("accepter", ACCEPTER);

    assert_eq!(outcome.refused_at, None, "the recipient refused a payout it should have taken");
    assert_eq!(outcome.bounced_from, None, "something bounced from a successful payout");
    assert_eq!(
        outcome.transactions, 2,
        "a payout that was taken should leave the message in and the payout out, nothing more"
    );
    assert_eq!(outcome.nullifier_next_index, "3", "two nullifiers should have been spent");
    // Two deposits and three outputs, and no recovery note.
    assert_eq!(
        outcome.commitment_next_index, "5",
        "a withdrawal that was taken minted a recovery note anyway"
    );

    let paid_out = u128::from(DENOMINATION) + u128::from(WITHDRAWAL_FEE);
    assert_eq!(
        outcome.pool_liability_after,
        outcome.pool_liability_before - paid_out,
        "the pool still owes what it paid out"
    );
    assert!(
        outcome.holds >= outcome.pool_liability_after + outcome.reserve,
        "the pool owes {} with a {} floor and holds only {}",
        outcome.pool_liability_after,
        outcome.reserve,
        outcome.holds
    );
}
