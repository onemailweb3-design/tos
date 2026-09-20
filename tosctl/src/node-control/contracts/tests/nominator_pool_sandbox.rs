/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The nominator pool, run rather than read.
//!
//! This contract had no behavioural coverage at all, which is how it came to be unable to
//! stake without anything going red. The post-quantum cutover gave the elector one stake
//! operation, `PQst`, and this pool still sends the classical one; the elector does not
//! know that opcode, so the message reaches its unknown-query branch and the money comes
//! back. Nothing in the tree said so until here.
//!
//! The pooled-staking ruling relays a pool's stake through a Validator Controller. These
//! tests exist so that the state the pool is in today is a fact the tree asserts, and so
//! that the change has something that can fail.

use chain_block::{
    Account, BuilderData, Cell, Coins, ConfigParams, IBitstring, MsgAddressInt, Serializable,
    ShardStateUnsplit, StateInit, TransactionTickTock,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func, generate_zerostate_state};

const TOS: u64 = 1_000_000_000;

/// The pool's own operation for "send a stake to the elector". It is also the opcode the
/// pool forwards, which is the part the elector no longer knows.
const NEW_STAKE: u32 = 0x4e73_744b;
/// What the elector answers a message whose operation it does not recognise.
const UNKNOWN_QUERY: u32 = 0xffff_ffff;
/// The only refusal the pool understands.
const NEW_STAKE_ERROR: u32 = 0xee6f_454c;
/// The elector's acceptance.
const NEW_STAKE_OK: u32 = 0xf374_484c;

/// `new_stake` from somebody who is not the configured validator.
const ERROR_NOT_THE_VALIDATOR: i32 = 78;
/// `new_stake` while a stake is already out.
const ERROR_NOT_IDLE: i32 = 79;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    })
}

/// The zerostate is generated rather than fixtured, so the elector and the configuration
/// these tests run against are the ones the chain would launch with.
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

/// The pool carries its own stdlib, so it is compiled with that one rather than with the
/// tree's: a contract compiled against different definitions is a different contract.
fn pool_code() -> Cell {
    let dir = repo_root().join("crypto/smartcont/nominator-pool");
    compile_func(&[dir.join("stdlib.fc"), dir.join("pool.fc")]).expect("the pool compiles")
}

/// `state = 0`, no nominators, no withdrawals: a pool that has been funded by its
/// validator and has never staked.
fn pool_data(validator: &chain_block::AccountId, validator_amount: u64) -> Cell {
    let mut config = BuilderData::new();
    config.append_raw(&validator.get_bytestring(0), 256).expect("validator address");
    config.append_u16(4_000).expect("reward share");
    config.append_u16(40).expect("max nominators");
    Coins::new(200 * TOS).write_to(&mut config).expect("min validator stake");
    Coins::new(10 * TOS).write_to(&mut config).expect("min nominator stake");

    let mut data = BuilderData::new();
    data.append_u8(0).expect("state");
    data.append_u16(0).expect("nominators count");
    Coins::new(0).write_to(&mut data).expect("stake amount sent");
    Coins::new(validator_amount).write_to(&mut data).expect("validator amount");
    data.checked_append_reference(config.into_cell().expect("config cell")).expect("config");
    data.append_bit_zero().expect("no nominators");
    data.append_bit_zero().expect("no withdraw requests");
    data.append_u32(0).expect("stake at");
    data.append_raw(&[0u8; 32], 256).expect("saved validator set hash");
    data.append_u8(0).expect("validator set changes count");
    data.append_u32(0).expect("validator set change time");
    data.append_u32(0).expect("stake held for");
    data.append_bit_zero().expect("no config proposal votings");
    data.into_cell().expect("pool data")
}

struct Pooled {
    chain: Blockchain,
    elector: MsgAddressInt,
    pool: MsgAddressInt,
    validator: MsgAddressInt,
}

/// A funded pool on a chain carrying the real elector, with an election open.
fn launch(validator_amount: u64, pool_balance: u64) -> Pooled {
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

    // An open election, reached the way the chain reaches it.
    chain.set_now(current.utime_until() - params.elections_start_before);
    chain.tick_tock(&elector, TransactionTickTock::Tick).expect("tick runs").expect_success();

    // The validator's own masterchain wallet, which is what the pool takes orders from.
    let validator = chain.treasury("pool-validator", 100_000 * TOS).expect("the validator wallet");

    let init = StateInit::with_code_and_data(
        pool_code(),
        pool_data(&validator.address().address(), validator_amount),
    );
    let pool = MsgAddressInt::with_params(
        -1,
        init.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("pool address");
    // Placed rather than deployed by message. The pool's entry point reads an operation
    // from the body before it does anything else, so it has no empty-body deploy path,
    // and driving one through some other operation would start these tests from a state
    // no operator would deploy into.
    let deployment = MessageBuilder::internal(validator.address(), &pool, pool_balance)
        .bounce(false)
        .state_init(init)
        .body(Cell::default())
        .build();
    chain.set_account(
        pool.clone(),
        Account::from_message(&deployment).expect("an account from the deployment"),
    );

    Pooled { chain, elector, pool, validator: validator.address().clone() }
}

/// The order an operator gives the pool: stake this much, on these terms.
///
/// After the value, the body carries the classical stake payload the pool forwards
/// unchanged, in the shape its own `check_new_stake_msg` parses: four fields and a
/// reference holding the signature. The payload is built into this body rather than into
/// a cell of its own, because the pool reads it as a continuation of the same slice --
/// and a reference does not survive being appended as bits, which is how this first
/// failed with a cell underflow the contract never reached its own checks to report.
///
/// The signature is a pattern. Nothing on this path verifies it: the pool does not, and
/// the elector no longer reaches the code that would.
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

impl Pooled {
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

    /// The pool's own view of itself. Only the fields these tests judge.
    fn state(&self) -> (u8, u128) {
        let result = self
            .chain
            .run_get_method(&self.pool, "get_pool_data", vec![])
            .expect("the pool answers");
        assert_eq!(result.exit_code, 0, "get_pool_data failed");
        let state = result.stack[0].as_integer().expect("state").to_string().parse().expect("u8");
        let sent = result.stack[2]
            .as_integer()
            .expect("stake amount sent")
            .to_string()
            .parse()
            .expect("u128");
        (state, sent)
    }

    fn order(&mut self, query_id: u64, value: u64, election: u32) -> tos_sandbox::SendResult {
        let order = stake_order(query_id, value, election);
        self.chain
            .send_message(
                MessageBuilder::internal(&self.validator, &self.pool, 2 * TOS).body(order).build(),
            )
            .expect("the order is delivered")
    }
}

/// Every reply tag any account sent during the cascade, in order. A pool stake is a round
/// trip -- order, forward, answer -- and which tag came back is the whole question.
fn reply_tags(result: &tos_sandbox::SendResult) -> Vec<u32> {
    let mut tags = Vec::new();
    for (_, transaction) in &result.transactions {
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
    tags
}

/// What the elector itself did, separated from what came back.
///
/// A tag alone cannot tell a refusal from a bounce: a throw inside the elector returns a
/// bounced message whose first word is also `0xffffffff`, so a test that only looked for
/// that tag would report "the elector refused politely" when the elector had in fact
/// aborted. Teaching the elector the classical opcode again survived exactly that.
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
fn the_pool_deploys_idle_and_reports_what_it_was_configured_with() {
    let pooled = launch(1_000 * TOS, 20_000 * TOS);
    let (state, sent) = pooled.state();
    assert_eq!(state, 0, "a fresh pool is not idle");
    assert_eq!(sent, 0, "a fresh pool has a stake out");
    assert_ne!(pooled.election(), 0, "the fixture needs an open election");
}

/// The harness drives the real contract: an order from anybody else is refused by the
/// rule that says only the validator commands this pool. Without this the tests below
/// could be passing against a contract that never ran.
#[test]
fn only_the_configured_validator_can_order_a_stake() {
    let mut pooled = launch(1_000 * TOS, 20_000 * TOS);
    let election = pooled.election();
    let stranger = pooled.chain.treasury("stranger", 10_000 * TOS).expect("another wallet");
    let order = stake_order(1, 1_000 * TOS, election);
    pooled
        .chain
        .send_message(
            MessageBuilder::internal(stranger.address(), &pooled.pool, 2 * TOS).body(order).build(),
        )
        .expect("delivered")
        .expect_exit_code(ERROR_NOT_THE_VALIDATOR);
    assert_eq!(pooled.state().0, 0, "a refused order moved the pool anyway");
}

/// A pool cannot stake, and does not learn that it cannot.
///
/// The elector has one stake operation and it is not this one, so the forwarded message
/// reaches the unknown-query branch and the value returns. The pool recognises only
/// `new_stake_error` as a refusal, so nothing tells it the stake was declined: it is left
/// in state 1, believing a stake is out, until the validator-set changes it counts have
/// gone by.
///
/// **This test is inverted when the Controller relay lands.** It asserts the breakage the
/// pooled-staking ruling exists to remove, so that removing it has something to turn.
#[test]
fn a_pools_stake_is_refused_by_the_elector_and_the_pool_is_left_believing_it_was_placed() {
    let mut pooled = launch(1_000 * TOS, 20_000 * TOS);
    let election = pooled.election();
    let staked = 1_000 * TOS;

    let result = pooled.order(1, staked, election);

    // The pool did send it, and the elector did answer.
    let tags = reply_tags(&result);
    assert!(tags.contains(&NEW_STAKE), "the pool did not forward a stake to the elector");

    // The elector answered, rather than throwing: the opcode is unknown to it, so it never
    // reaches the code that would refuse or accept a stake.
    let elector = pooled.elector.clone();
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
        "the elector refused in a way the pool understands, so this test is stale"
    );

    // And the pool believes a stake is out.
    let (state, sent) = pooled.state();
    assert_eq!(state, 1, "the pool did not record a stake it thinks it placed");
    assert_eq!(sent, u128::from(staked - TOS), "the pool recorded the wrong amount");

    // Which means it will refuse the next order, having never validated anything.
    let again = stake_order(2, staked, election);
    pooled
        .chain
        .send_message(
            MessageBuilder::internal(&pooled.validator, &pooled.pool, 2 * TOS).body(again).build(),
        )
        .expect("delivered")
        .expect_exit_code(ERROR_NOT_IDLE);
}

/// The elector keeps nothing. The stake bounces rather than stranding a pool's capital,
/// which is why this is a liveness failure and not a loss.
#[test]
fn the_refused_stake_comes_back_to_the_pool() {
    let mut pooled = launch(1_000 * TOS, 20_000 * TOS);
    let election = pooled.election();
    let before = pooled
        .chain
        .get_account(&pooled.pool)
        .expect("the pool is deployed")
        .balance()
        .and_then(|balance| balance.coins.as_u64())
        .expect("a balance");

    pooled.order(1, 1_000 * TOS, election);

    let after = pooled
        .chain
        .get_account(&pooled.pool)
        .expect("the pool is deployed")
        .balance()
        .and_then(|balance| balance.coins.as_u64())
        .expect("a balance");
    // Fees are spent on the way out and back; the stake itself is not.
    assert!(
        after > before - 100 * TOS,
        "a refused stake cost the pool {} nanotomis",
        before - after
    );
}
