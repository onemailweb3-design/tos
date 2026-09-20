/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The liquid-staking controller, run rather than read.
//!
//! Of the three pooled-staking contracts this is the one whose failure is not a missed
//! round. It keeps a state machine, and in `SENT_STAKE_REQUEST` it recognises exactly two
//! answers from the elector: the stake was taken, or the stake was refused. Anything else
//! sets `halted?`, which is a permanent stop that only a governor can lift.
//!
//! Since the post-quantum cutover the elector answers a classical stake with its
//! unknown-query tag, which is neither of those two. So the first stake this controller
//! sends halts it. Nothing said so, because the contract had no tests.

use chain_block::{
    Account, BuilderData, Cell, Coins, ConfigParams, IBitstring, MsgAddressInt, Serializable,
    ShardStateUnsplit, StateInit, TransactionTickTock,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func, generate_zerostate_state};

const TOS: u64 = 1_000_000_000;

const NEW_STAKE: u32 = 0x4e73_744b;
const UNKNOWN_QUERY: u32 = 0xffff_ffff;
const NEW_STAKE_OK: u32 = 0xf374_484c;
const NEW_STAKE_ERROR: u32 = 0xee6f_454c;

const STATE_REST: u8 = 0;
const STATE_SENT_STAKE_REQUEST: u8 = 2;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    })
}

fn zerostate() -> ShardStateUnsplit {
    generate_zerostate_state(repo_root().join("crypto/smartcont/gen-zerostate.fif"))
        .expect("zerostate generation needs build/crypto/create-state and the fift libraries")
}

fn configuration(state: &ShardStateUnsplit) -> ConfigParams {
    state
        .read_custom()
        .expect("masterchain extra")
        .expect("the zerostate is a masterchain state")
        .config()
        .clone()
}

fn account(state: &ShardStateUnsplit, address: &MsgAddressInt) -> Account {
    state
        .read_accounts()
        .expect("accounts")
        .account(&address.address())
        .expect("account lookup")
        .unwrap_or_else(|| panic!("the zerostate deploys nothing at {address}"))
        .read_account()
        .expect("account")
}

fn masterchain(id: chain_block::AccountId) -> MsgAddressInt {
    MsgAddressInt::with_standart(None, -1, id).expect("masterchain address")
}

/// The controller carries its own stdlib beside its includes, so it is compiled with
/// that one: a contract built against other definitions is another contract.
fn controller_code() -> Cell {
    compile_func(&[repo_root().join("crypto/smartcont/liquid-staking/controller.func")])
        .expect("the liquid-staking controller compiles")
}

/// A controller at rest, approved, owing nothing. The static half lives behind two
/// references, which is how the contract reads it back.
fn controller_data(
    validator: &MsgAddressInt,
    pool: &MsgAddressInt,
    governor: &MsgAddressInt,
) -> Cell {
    let none = BuilderData::new();

    let mut roles = BuilderData::new();
    governor.write_to(&mut roles).expect("approver");
    governor.write_to(&mut roles).expect("halter");

    let mut statics = BuilderData::new();
    statics.append_u32(0).expect("controller id");
    validator.write_to(&mut statics).expect("validator");
    pool.write_to(&mut statics).expect("pool");
    governor.write_to(&mut statics).expect("governor");
    statics
        .checked_append_reference(roles.into_cell().expect("roles cell"))
        .expect("roles reference");

    let mut data = BuilderData::new();
    data.append_u8(STATE_REST).expect("state");
    data.append_bit_zero().expect("not halted");
    data.append_bit_one().expect("approved");
    Coins::new(0).write_to(&mut data).expect("stake amount sent");
    data.append_bits(0, 48).expect("stake at");
    data.append_raw(&[0u8; 32], 256).expect("saved validator set hash");
    data.append_u8(0).expect("validator set changes count");
    data.append_bits(0, 48).expect("validator set change time");
    data.append_bits(0, 48).expect("stake held for");
    Coins::new(0).write_to(&mut data).expect("borrowed amount");
    data.append_bits(0, 48).expect("borrowing time");
    data.append_bits(0, 2).expect("no sudoer");
    data.append_bits(0, 48).expect("sudoer set at");
    data.append_bits(0, 24).expect("max expected interest");
    data.checked_append_reference(statics.into_cell().expect("statics cell"))
        .expect("statics reference");
    let _ = none;
    data.into_cell().expect("controller data")
}

struct Staking {
    chain: Blockchain,
    elector: MsgAddressInt,
    controller: MsgAddressInt,
    validator: MsgAddressInt,
}

fn launch(balance: u64) -> Staking {
    let state = zerostate();
    let config = configuration(&state);
    let elector = masterchain(config.elector_address().expect("elector address"));
    let config_contract = masterchain(config.config_address().expect("configuration address"));
    let current = config.validator_set().expect("the zerostate elects a validator set");
    let params = config.elector_params().expect("elector parameters");
    let elector_account = account(&state, &elector);
    let config_account = account(&state, &config_contract);

    let mut chain = Blockchain::with_config(config).expect("sandbox with the real config");
    chain.set_workchain(-1);
    chain.set_account(elector.clone(), elector_account);
    chain.set_account(config_contract, config_account);

    chain.set_now(current.utime_until() - params.elections_start_before);
    chain.tick_tock(&elector, TransactionTickTock::Tick).expect("tick runs").expect_success();

    let validator = chain.treasury("ls-validator", 100_000 * TOS).expect("the validator wallet");
    let validator_address = validator.address().clone();
    let pool = chain.treasury("ls-pool", 10_000 * TOS).expect("the pool");
    let pool_address = pool.address().clone();
    let governor = chain.treasury("ls-governor", 10_000 * TOS).expect("the governor");
    let governor_address = governor.address().clone();

    let init = StateInit::with_code_and_data(
        controller_code(),
        controller_data(&validator_address, &pool_address, &governor_address),
    );
    let controller = MsgAddressInt::with_params(
        -1,
        init.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("controller address");

    // Placed rather than deployed by message: the controller reads an operation before
    // anything else, so it has no empty-body deploy path.
    let deployment = MessageBuilder::internal(&validator_address, &controller, balance)
        .bounce(false)
        .state_init(init)
        .body(Cell::default())
        .build();
    chain.set_account(
        controller.clone(),
        Account::from_message(&deployment).expect("an account from the deployment"),
    );

    Staking { chain, elector, controller, validator: validator_address }
}

/// The order: stake this much, on these terms. The payload is built into the body rather
/// than into a cell of its own, because the contract reads it as a continuation of the
/// same slice and a reference does not survive being appended as bits.
fn stake_order(query_id: u64, value: u64, election: u32) -> Cell {
    let mut signature = BuilderData::new();
    signature.append_raw(&[0x5a; 64], 512).expect("signature bits");

    let mut body = BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(query_id).expect("query id");
    Coins::new(value).write_to(&mut body).expect("value");
    body.append_raw(&[0x11; 32], 256).expect("validator public key");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&[0xa5; 32], 256).expect("adnl address");
    body.checked_append_reference(signature.into_cell().expect("signature cell"))
        .expect("signature reference");
    body.into_cell().expect("stake order")
}

impl Staking {
    fn election(&self) -> u32 {
        let result = self
            .chain
            .run_get_method(&self.elector, "active_election_id", vec![])
            .expect("the elector answers");
        assert_eq!(result.exit_code, 0, "active_election_id failed");
        result
            .stack
            .last()
            .expect("a value")
            .as_integer()
            .expect("an integer")
            .to_string()
            .parse()
            .expect("an election id")
    }

    /// The two fields these tests judge: where the state machine is, and whether it has
    /// stopped.
    fn state(&self) -> (u8, bool) {
        let result = self
            .chain
            .run_get_method(&self.controller, "get_validator_controller_data", vec![])
            .expect("the controller answers");
        assert_eq!(result.exit_code, 0, "get_validator_controller_data failed");
        let state: u8 =
            result.stack[0].as_integer().expect("state").to_string().parse().expect("a state");
        let halted = result.stack[1].as_integer().expect("halted").to_string() != "0";
        (state, halted)
    }

    fn order(&mut self, query_id: u64, value: u64, election: u32) -> tos_sandbox::SendResult {
        let order = stake_order(query_id, value, election);
        let sender = self.validator.clone();
        let target = self.controller.clone();
        self.chain
            .send_message(MessageBuilder::internal(&sender, &target, 2 * TOS).body(order).build())
            .expect("the order is delivered")
    }
}

/// What the elector itself did, separated from what came back. A throw inside the elector
/// bounces a message whose first word is also `0xffffffff`, so a test that only looked
/// for that tag could not tell a refusal from an abort.
fn elector_verdict(result: &tos_sandbox::SendResult, elector: &MsgAddressInt) -> (bool, Vec<u32>) {
    let mut aborted = false;
    let mut tags = Vec::new();
    let mut ran = false;
    for (address, transaction) in &result.transactions {
        if address != elector {
            continue;
        }
        ran = true;
        aborted |= transaction.read_description().expect("description").is_aborted();
        transaction
            .iterate_out_msgs(|message| {
                if let Some(body) = message.body() {
                    let mut body = body.clone();
                    if let Ok(tag) = body.get_next_u32() {
                        tags.push(tag);
                    }
                }
                Ok(true)
            })
            .expect("out messages");
    }
    assert!(ran, "the elector was never reached");
    (aborted, tags)
}

#[test]
fn the_controller_starts_at_rest_and_running() {
    let staking = launch(100_000 * TOS);
    assert_eq!(staking.state(), (STATE_REST, false), "a fresh controller is not at rest");
    assert_ne!(staking.election(), 0, "the fixture needs an open election");
}

/// Only the validator may spend this controller's funds on a stake. Without this the
/// test below could be passing against a contract that never ran.
#[test]
fn only_the_validator_can_order_a_stake() {
    let mut staking = launch(100_000 * TOS);
    let election = staking.election();
    let stranger = staking.chain.treasury("ls-stranger", 10_000 * TOS).expect("another wallet");
    let sender = stranger.address().clone();
    let target = staking.controller.clone();
    let order = stake_order(1, 60_000 * TOS, election);
    let result = staking
        .chain
        .send_message(MessageBuilder::internal(&sender, &target, 2 * TOS).body(order).build())
        .expect("delivered");
    assert!(
        result.transactions.iter().any(|(_, transaction)| transaction
            .read_description()
            .expect("description")
            .is_aborted()),
        "a stranger's order was carried out"
    );
    assert_eq!(staking.state(), (STATE_REST, false), "a refused order moved the controller");
}

/// The first stake this controller sends stops it for good.
///
/// The elector does not know the classical opcode, so it answers with its unknown-query
/// tag. The controller is in `SENT_STAKE_REQUEST` and recognises only the two answers a
/// stake used to produce; anything else means something it cannot account for has
/// happened, so it halts. Its capital comes back and it can no longer do anything with
/// it without a governor.
///
/// **This test is inverted when the Controller relay lands.**
#[test]
fn a_liquid_staking_controller_halts_on_the_first_stake_it_sends() {
    let mut staking = launch(100_000 * TOS);
    let election = staking.election();

    let result = staking.order(1, 60_000 * TOS, election);

    // It did send a stake, and the elector answered rather than throwing.
    let elector = staking.elector.clone();
    let (aborted, answered) = elector_verdict(&result, &elector);
    assert!(!aborted, "the elector tried to process the classical stake and threw");
    assert_eq!(
        answered.first().copied(),
        Some(UNKNOWN_QUERY),
        "the elector recognised the classical stake operation: {answered:02x?}"
    );
    assert!(!answered.contains(&NEW_STAKE_OK), "the elector accepted a classical stake");
    assert!(
        !answered.contains(&NEW_STAKE_ERROR),
        "the elector refused in a way this controller understands, so this test is stale"
    );

    // And the controller stopped. This is the difference between this contract and the
    // other two: not a missed round, a halt.
    let (state, halted) = staking.state();
    assert!(halted, "the controller carried on after an answer it could not account for");
    assert_eq!(
        state, STATE_SENT_STAKE_REQUEST,
        "a halted controller should still remember it had sent a stake"
    );

    // Halted, it refuses the next order rather than trying again.
    let again = staking.order(2, 60_000 * TOS, election);
    assert!(
        again.transactions.iter().any(|(_, transaction)| transaction
            .read_description()
            .expect("description")
            .is_aborted()),
        "a halted controller took another order"
    );
}
