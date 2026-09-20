/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! One private transfer, end to end, with a proof that verifies.
//!
//! Everything else on this branch stops at the pairing. The circuit produces
//! valid proofs and the contract verifies proofs, but until the circuit's
//! eighteen public inputs are the eighteen the contract computes from a real
//! message, the two have never met. This is where they meet.
//!
//! The shape of the test is the shape of the problem. Eight of the eighteen
//! are derived by the contract from bytes -- payloads, keys, addresses, the
//! pool's own account -- so the witness has to be built *from* those bytes
//! rather than from a scenario generator. The note being spent has to be a
//! note the contract itself minted, at an index the contract itself assigned,
//! under a commitment whose preimages the prover holds. And the intent digest
//! the signatures cover is the one the circuit computed, which the contract
//! recomputes.

use ark_ff::AdditiveGroup;
use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};

use chain_block::{BuilderData, Cell, IBitstring};
use shielded_pool_circuit::circuit::{HeldNote, ShieldedTransactionCircuit, TransactionBuilder};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::public_inputs::PublicInputs;
use shielded_pool_circuit::tree::Frontier;
use shielded_pool_circuit::{groth16, imt, notes, wire};
use shielded_pool_circuit_crosscheck::imt_probe::encode_witness;
use shielded_pool_circuit_crosscheck::pool::{
    addr_none, be, dec, development_vk_bytes, refs_only, store_coins, Pool, DENOMINATION,
    OP_TRANSACT,
};
use shielded_pool_circuit_crosscheck::wire::byte_chain;

const TOS: u64 = 1_000_000_000;
/// Enough to fund the deposit and to pay for a transact's own compute.
const COMPUTE_FEE: u64 = 3 * TOS;

/// Everything a successful transfer changes, so a refusal can be required to
/// change none of it.
fn snapshot(pool: &Pool) -> Vec<String> {
    [
        "commitment_root",
        "commitment_next_index",
        "nullifier_root",
        "nullifier_next_index",
        "native_liability",
    ]
    .iter()
    .map(|method| pool.get(method).expect("a get-method"))
    .collect()
}

fn payload(seed: u8) -> Vec<u8> {
    (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ seed).collect()
}

/// A one-time ML-DSA-44 key, as section 4.1 requires per note.
struct AuthKey {
    public: [u8; 1312],
    secret: ml_dsa_44::PrivateKey,
}

impl AuthKey {
    fn generate() -> Self {
        let (public, secret) = ml_dsa_44::try_keygen().expect("ML-DSA-44 keygen");
        AuthKey { public: public.into_bytes(), secret }
    }

    fn hash(&self) -> Fr {
        wire::pq_auth_key_hash(&self.public)
    }

    fn sign(&self, digest: Fr) -> [u8; 2420] {
        self.secret
            .try_sign(&be(digest), b"TOS-SHIELDED-POOL-MLDSA44-v1")
            .expect("ML-DSA-44 signing")
    }
}

/// What to break, so the test can be shown to be able to fail.
#[derive(Clone, Copy, Default)]
struct Tamper {
    /// Submit a valid proof of a different statement. Flipping a bit of a
    /// point would be refused while blst was still decoding it, which proves
    /// only that blst decodes; this proves the verifier checks the statement.
    other_proof: bool,
    /// Send a payload other than the one the proof committed to.
    payload: bool,
    /// Send a nullifier other than the one the proof committed to.
    nullifier: bool,
}

/// Section 12.2's transact body, built from the public inputs the circuit
/// proved and the proof it produced.
#[allow(clippy::too_many_arguments)]
fn transact_body(
    public: &PublicInputs,
    proof: &groth16::CanonicalProof,
    other: &groth16::CanonicalProof,
    anchor_root: Fr,
    valid_until: u32,
    payloads: &[Vec<u8>; 3],
    keys: &[&AuthKey; 2],
    signatures: &[[u8; 2420]; 2],
    witnesses: &[imt::Witness; 2],
    tamper: Tamper,
) -> Cell {
    let mut proof_bundle = BuilderData::new();
    proof_bundle.append_raw(&be(anchor_root), 256).unwrap();
    proof_bundle.append_raw(&be(public.nullifier_0), 256).unwrap();
    let mut nullifier_1 = be(public.nullifier_1);
    if tamper.nullifier {
        nullifier_1[31] ^= 1;
    }
    proof_bundle.append_raw(&nullifier_1, 256).unwrap();
    let mut bodies = BuilderData::new();
    for body in [public.note_body_0, public.note_body_1, public.note_body_2] {
        bodies.append_raw(&be(body), 256).unwrap();
    }
    proof_bundle.checked_append_reference(bodies.into_cell().unwrap()).unwrap();

    // Section 10.1: A and C in the root, B in the reference.
    let used = if tamper.other_proof { other } else { proof };
    let mut proof_ac = BuilderData::new();
    proof_ac.append_raw(&used.a, 384).unwrap();
    proof_ac.append_raw(&used.c, 384).unwrap();
    let mut proof_b = BuilderData::new();
    proof_b.append_raw(&used.b, 768).unwrap();
    proof_ac.checked_append_reference(proof_b.into_cell().unwrap()).unwrap();
    proof_bundle.checked_append_reference(proof_ac.into_cell().unwrap()).unwrap();

    // A transfer carries no recovery material.
    let mut output = BuilderData::new();
    output.append_raw(&[0u8; 32], 256).unwrap();
    for (slot, bytes) in payloads.iter().enumerate() {
        let mut sent = bytes.clone();
        if tamper.payload && slot == 0 {
            sent[17] ^= 1;
        }
        output.checked_append_reference(byte_chain(&sent).unwrap()).unwrap();
    }
    output.checked_append_reference(Cell::default()).unwrap();

    let auth = refs_only(&[
        byte_chain(&keys[0].public).unwrap(),
        byte_chain(&signatures[0]).unwrap(),
        byte_chain(&keys[1].public).unwrap(),
        byte_chain(&signatures[1]).unwrap(),
    ])
    .unwrap();

    let witness_bundle = refs_only(&[
        encode_witness(&witnesses[0]).unwrap(),
        encode_witness(&witnesses[1]).unwrap(),
    ])
    .unwrap();

    let digest = be(public.transaction_intent_digest);
    let mut builder = BuilderData::new();
    builder.append_u32(OP_TRANSACT).unwrap();
    builder.append_u64(u64::from_be_bytes(digest[24..].try_into().unwrap())).unwrap();
    builder.append_u8(0).unwrap(); // anchor kind: the current root
    builder.append_u32(0).unwrap(); // anchor id
    builder.append_u32(valid_until).unwrap();
    store_coins(&mut builder, 0).unwrap(); // a transfer moves nothing out
    store_coins(&mut builder, 0).unwrap(); // and pays no withdrawal fee
    addr_none(&mut builder).unwrap();
    builder.append_raw(&digest, 256).unwrap();
    builder.checked_append_reference(proof_bundle.into_cell().unwrap()).unwrap();
    builder.checked_append_reference(output.into_cell().unwrap()).unwrap();
    builder.checked_append_reference(auth).unwrap();
    builder.checked_append_reference(witness_bundle).unwrap();
    builder.into_cell().expect("a transact body")
}

/// Deposit one note, then spend it: two inputs (one real, one phantom), three
/// outputs, no value crossing the pool's boundary.
#[test]
fn a_private_transfer_with_a_proof_that_verifies() {
    // The prover's view of the two trees, which start where the contract's do.
    let mut frontier = Frontier::new();
    let nullifiers = imt::State::genesis();
    let mut pool = Pool::deploy(frontier.empty_root(), nullifiers.root()).expect("deploy the pool");
    assert_eq!(
        pool.get("commitment_root").expect("commitment root"),
        dec(frontier.empty_root()),
        "the contract and the prover disagree about the empty commitment tree"
    );
    assert_eq!(
        pool.get("nullifier_root").expect("nullifier root"),
        dec(nullifiers.root()),
        "the contract and the prover disagree about the genesis nullifier tree"
    );

    // The proving key the prover will use has to be the verifying key the
    // contract was deployed with, or nothing below means anything.
    let terms = shielded_pool_circuit::scenario::PublicTerms::transfer();
    let domain = wire::execution_domain(
        {
            // The chain's global id, read from the chain rather than assumed.
            let probe = shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
                .expect("deploy the wire probe");
            probe.domain_inputs().expect("the domain inputs").0
        },
        &pool.account().expect("the pool's account"),
    );

    // --- the note the transfer will spend ------------------------------
    //
    // Its owner commitment is built from preimages the prover keeps, and one
    // of them is the hash of a real ML-DSA key. The contract will mint the
    // note from this commitment and the amount it actually admits.
    let input_key = AuthKey::generate();
    let phantom_key = AuthKey::generate();
    let owner_nf_key = Fr::from(0x11_2233_4455_6677u64);
    let note_secret = Fr::from(0x99_aabb_ccdd_eeffu64);
    let deposit_payload = payload(0x21);
    let deposit_data_hash = wire::output_data_hash(&deposit_payload);
    let owner_commitment = notes::owner_commitment(
        notes::owner_nf_key_hash(owner_nf_key),
        input_key.hash(),
        note_secret,
    );

    pool.send(
        DENOMINATION + COMPUTE_FEE,
        Pool::deposit_body(
            DENOMINATION,
            owner_commitment,
            byte_chain(&deposit_payload).expect("payload"),
        )
        .expect("deposit body"),
    )
    .expect("deposit")
    .expect_success();

    // The prover mirrors the append the contract just made, and the two roots
    // have to agree before anything is proved against one of them.
    let note_body = notes::note_body_commitment(
        owner_commitment,
        Fr::from(u128::from(DENOMINATION)),
        deposit_data_hash,
    );
    let leaf = notes::note_commitment(note_body, Fr::ZERO);
    let (leaf_index, root) = frontier.append(leaf).expect("append");
    assert_eq!(leaf_index, 0, "the contract assigned another index");
    assert_eq!(
        pool.get("commitment_root").expect("commitment root"),
        dec(root),
        "the prover's tree and the contract's disagree after one deposit"
    );

    // --- the transfer ---------------------------------------------------
    let now: u32 = pool.bc.now().try_into().expect("a unix time");
    let valid_until = now + 600;
    let output_payloads = [payload(1), payload(2), payload(3)];
    let output_data_hash = [
        wire::output_data_hash(&output_payloads[0]),
        wire::output_data_hash(&output_payloads[1]),
        wire::output_data_hash(&output_payloads[2]),
    ];

    let mut scenario_pool = shielded_pool_circuit::scenario::Pool::new();
    let outputs = [
        scenario_pool.real_output(Fr::from(u128::from(DENOMINATION) / 2)),
        scenario_pool
            .real_output(Fr::from(u128::from(DENOMINATION) - u128::from(DENOMINATION) / 2)),
        scenario_pool.dummy_output(),
    ];

    let held_of = || {
        [
            HeldNote {
                is_phantom: false,
                owner_nf_key,
                note_secret,
                amount: Fr::from(u128::from(DENOMINATION)),
                output_data_hash: deposit_data_hash,
                leaf_index: 0,
            },
            HeldNote {
                is_phantom: true,
                owner_nf_key: Fr::from(7u64),
                note_secret: Fr::from(9u64),
                amount: Fr::ZERO,
                output_data_hash: Fr::from(11u64),
                leaf_index: 0,
            },
        ]
    };
    let held = held_of();
    let held_again = held_of();

    let builder = TransactionBuilder {
        execution_domain: domain,
        valid_until,
        intent_nonce: Fr::from(0x1234_5678u64),
        public_amount_out: terms.public_amount_out,
        withdrawal_fee: terms.withdrawal_fee,
        public_recipient_hash: terms.public_recipient_hash,
        recovery_template_hash: terms.recovery_template_hash,
        is_withdrawal: None,
        input_pq_auth_key_hash: [input_key.hash(), phantom_key.hash()],
        outputs,
        output_data_hash,
    };
    let (public, witness) = builder.build(&frontier, root, held).expect("build the transaction");

    // --- the proof -------------------------------------------------------
    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))
        .expect("development keys");
    let encoded = groth16::canonical_verifying_key(&keys.verifying).expect("vk bytes");
    assert_eq!(
        encoded.bytes,
        development_vk_bytes().expect("the fixture verifying key"),
        "the prover's verifying key is not the one the pool was deployed with"
    );
    let proof =
        groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 1).expect("prove");
    assert!(
        groth16::verify(&keys.verifying, &public, &proof).expect("verify"),
        "the proof does not verify out of circuit, so nothing on chain could"
    );
    let canonical = groth16::CanonicalProof::from_proof(&proof).expect("canonical proof");

    // A second transaction, differing only in its intent nonce, proved with
    // the same key. Its proof is valid; it is a proof of something else.
    let (other_public, other_witness) =
        TransactionBuilder { intent_nonce: Fr::from(0x8765_4321u64), ..builder }
            .build(&frontier, root, held_again)
            .expect("build another transaction");
    assert_ne!(
        other_public.transaction_intent_digest, public.transaction_intent_digest,
        "the two transactions are the same transaction"
    );
    let other_proof =
        groth16::prove(&keys, ShieldedTransactionCircuit::new(other_public, other_witness), 2)
            .expect("prove the other transaction");
    let elsewhere =
        groth16::CanonicalProof::from_proof(&other_proof).expect("canonical other proof");

    // --- the message ------------------------------------------------------
    let digest = public.transaction_intent_digest;
    let signatures = [input_key.sign(digest), phantom_key.sign(digest)];

    let mut tree = nullifiers.clone();
    let (witness_0, after_first) = tree.witness_for(&public.nullifier_0).expect("first witness");
    tree.apply(after_first);
    let (witness_1, _) = tree.witness_for(&public.nullifier_1).expect("second witness");

    let build = |tamper: Tamper| {
        transact_body(
            &public,
            &canonical,
            &elsewhere,
            root,
            valid_until,
            &output_payloads,
            &[&input_key, &phantom_key],
            &signatures,
            &[witness_0.clone(), witness_1.clone()],
            tamper,
        )
    };

    // A test that has never failed is not known to be able to. Each of these
    // is a well-formed message that a wallet could send and the contract must
    // refuse, and each breaks exactly one of the things the proof binds.
    let before = snapshot(&pool);
    for (what, tamper, expected) in [
        (
            "a valid proof of another statement",
            Tamper { other_proof: true, ..Tamper::default() },
            262,
        ),
        (
            "a payload the proof did not commit to",
            Tamper { payload: true, ..Tamper::default() },
            262,
        ),
        (
            // Not 262. The nullifier goes into the tree at step 10 and the
            // proof is checked at step 12, so a nullifier the witness does
            // not bracket is refused by the tree before the proof is asked
            // about it. The code is 120: under the root the updated low leaf
            // produces, the append slot is no longer unallocated.
            "a nullifier the proof did not commit to",
            Tamper { nullifier: true, ..Tamper::default() },
            120,
        ),
    ] {
        let (exit, _) = pool.run(COMPUTE_FEE * 4, build(tamper)).expect("a tampered transact");
        assert_eq!(exit, expected, "{what} was accepted");
        assert_eq!(snapshot(&pool), before, "{what} moved the state");
    }

    let liability_before = pool.get("native_liability").expect("liability");
    let (exit, used) = pool.run(COMPUTE_FEE * 4, build(Tamper::default())).expect("transact");
    assert_eq!(exit, 0, "the transfer was refused with exit {exit}");

    /// Section 14.1. The contract sets this on itself, and a sender prepays
    /// `get_compute_fee(ceiling)` rather than what the path costs, so the
    /// headroom is not free -- it is what every sender overpays.
    const TRANSACT_GAS_CEILING: i64 = 2_000_000;
    eprintln!(
        "a successful private transfer: {used} gas, {}% of the {TRANSACT_GAS_CEILING} ceiling, \
         {} to spare",
        used * 100 / TRANSACT_GAS_CEILING,
        TRANSACT_GAS_CEILING - used
    );
    assert!(
        used < TRANSACT_GAS_CEILING,
        "a successful transfer uses {used} gas and no longer fits the profile's own ceiling"
    );

    // --- what it did ------------------------------------------------------
    assert_eq!(
        pool.get("commitment_next_index").expect("next index"),
        "4",
        "one deposit and three outputs should leave four leaves"
    );
    assert_eq!(
        pool.get("nullifier_next_index").expect("nullifier next index"),
        "3",
        "two nullifiers should have been inserted"
    );
    assert_eq!(
        pool.get("native_liability").expect("liability"),
        liability_before,
        "a transfer moved value across the pool's boundary"
    );
}
