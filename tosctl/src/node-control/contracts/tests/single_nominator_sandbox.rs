/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The single-nominator pool, run rather than read.
//!
//! One cold owner holds the funds, one validator wallet may spend them on a stake and on
//! nothing else. It had no behavioural coverage, and like the nominator pool beside it, it
//! can no longer stake: the elector has one stake operation since the post-quantum
//! cutover and this contract sends the other.
//!
//! Its failure differs from the nominator pool's in a way worth recording. It keeps no
//! state machine, so it is not left believing a stake is out -- the round is simply
//! missed, silently, every time.

use chain_block::{
    Account, BuilderData, Cell, Coins, ConfigParams, IBitstring, MsgAddressInt, Serializable,
    ShardStateUnsplit, StateInit, TransactionTickTock,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib, generate_zerostate_state};

const TOS: u64 = 1_000_000_000;

const NEW_STAKE: u32 = 0x4e73_744b;
const RECOVER_STAKE: u32 = 0x4765_7424;
const WITHDRAW: u32 = 0x1000;
const UNKNOWN_QUERY: u32 = 0xffff_ffff;
const NEW_STAKE_OK: u32 = 0xf374_484c;
const NEW_STAKE_ERROR: u32 = 0xee6f_454c;

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

fn nominator_code() -> Cell {
    compile_func_with_stdlib(&[
        repo_root().join("crypto/smartcont/single-nominator-pool/single-nominator-code.fc")
    ])
    .expect("the single-nominator contract compiles")
}

/// Its whole storage: who owns the money, and who may stake it.
fn nominator_data(owner: &MsgAddressInt, validator: &MsgAddressInt) -> Cell {
    let mut data = BuilderData::new();
    owner.write_to(&mut data).expect("owner address");
    validator.write_to(&mut data).expect("validator address");
    data.into_cell().expect("nominator data")
}

struct Pooled {
    chain: Blockchain,
    elector: MsgAddressInt,
    nominator: MsgAddressInt,
    owner: MsgAddressInt,
    validator: MsgAddressInt,
}

fn launch(balance: u64) -> Pooled {
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

    let owner = chain.treasury("cold-owner", 100_000 * TOS).expect("the owner wallet");
    let owner_address = owner.address().clone();
    let validator = chain.treasury("validator-wallet", 100_000 * TOS).expect("the hot wallet");
    let validator_address = validator.address().clone();

    let init = StateInit::with_code_and_data(
        nominator_code(),
        nominator_data(&owner_address, &validator_address),
    );
    let nominator = MsgAddressInt::with_params(
        -1,
        init.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("nominator address");

    // This contract does have an empty-body path, so it is deployed the way an operator
    // deploys it rather than placed.
    chain
        .send_message(
            MessageBuilder::internal(&owner_address, &nominator, balance)
                .bounce(false)
                .state_init(init)
                .body(Cell::default())
                .build(),
        )
        .expect("the nominator deploys")
        .expect_success();

    Pooled { chain, elector, nominator, owner: owner_address, validator: validator_address }
}

/// The order: stake this much, on these terms. The payload is built into the body rather
/// than into a cell of its own, because the contract reads it as a continuation of the
/// same slice and a reference does not survive being appended as bits.
fn stake_order(query_id: u64, amount: u64, election: u32) -> Cell {
    let mut signature = BuilderData::new();
    signature.append_raw(&[0x5a; 64], 512).expect("signature bits");

    let mut body = BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(query_id).expect("query id");
    Coins::new(amount).write_to(&mut body).expect("stake amount");
    body.append_raw(&[0x11; 32], 256).expect("validator public key");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&[0xa5; 32], 256).expect("adnl address");
    body.checked_append_reference(signature.into_cell().expect("signature cell"))
        .expect("signature reference");
    body.into_cell().expect("stake order")
}

fn simple_order(op: u32, query_id: u64) -> Cell {
    let mut body = BuilderData::new();
    body.append_u32(op).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.into_cell().expect("order")
}

fn withdraw_order(query_id: u64, amount: u64) -> Cell {
    let mut body = BuilderData::new();
    body.append_u32(WITHDRAW).expect("operation");
    body.append_u64(query_id).expect("query id");
    Coins::new(amount).write_to(&mut body).expect("amount");
    body.into_cell().expect("withdraw order")
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

    fn balance(&self, address: &MsgAddressInt) -> u64 {
        self.chain
            .get_account(address)
            .and_then(|account| account.balance().and_then(|balance| balance.coins.as_u64()))
            .unwrap_or(0)
    }

    fn from(&mut self, sender: &MsgAddressInt, body: Cell, value: u64) -> tos_sandbox::SendResult {
        let target = self.nominator.clone();
        self.chain
            .send_message(MessageBuilder::internal(sender, &target, value).body(body).build())
            .expect("the order is delivered")
    }
}

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
fn the_nominator_deploys_and_reports_both_roles() {
    let pooled = launch(20_000 * TOS);
    let result = pooled
        .chain
        .run_get_method(&pooled.nominator, "get_roles", vec![])
        .expect("the nominator answers");
    assert_eq!(result.exit_code, 0, "get_roles failed");
    assert_eq!(result.stack.len(), 2, "a single nominator has exactly two roles");
}

/// The role separation this contract exists for, and the proof that the harness reaches
/// real behaviour: the owner may take the money home, and the validator may not.
#[test]
fn the_owner_takes_the_money_home_and_the_validator_cannot() {
    let mut pooled = launch(20_000 * TOS);
    let before = pooled.balance(&pooled.owner.clone());

    pooled.from(&pooled.owner.clone(), withdraw_order(1, 5_000 * TOS), TOS).expect_success();
    let after = pooled.balance(&pooled.owner.clone());
    assert!(after > before + 4_000 * TOS, "the owner did not get the funds back");

    // The same order from the validator does nothing at all: the contract reaches no
    // branch for it, so it neither sends nor throws.
    let held = pooled.balance(&pooled.nominator.clone());
    let result = pooled.from(&pooled.validator.clone(), withdraw_order(2, 5_000 * TOS), TOS);
    assert!(reply_tags(&result).is_empty(), "the validator moved funds it is not allowed to move");
    assert!(
        pooled.balance(&pooled.nominator.clone()) >= held,
        "the validator's withdrawal took money out"
    );
}

/// A single-nominator pool cannot stake either, and unlike the nominator pool it is told
/// nothing and records nothing: the round is missed in silence.
///
/// **This test is inverted when the Controller relay lands.**
#[test]
fn a_single_nominators_stake_is_refused_and_the_round_is_missed_in_silence() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();

    let result =
        pooled.from(&pooled.validator.clone(), stake_order(1, 1_000 * TOS, election), 2 * TOS);

    let tags = reply_tags(&result);
    assert!(tags.contains(&NEW_STAKE), "the nominator did not forward a stake");

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
        "the elector refused in a way this contract could act on, so this test is stale"
    );

    // It keeps no state, so there is nothing for it to have recorded, and nothing to
    // stop it trying again next round with the same result.
    let roles = pooled
        .chain
        .run_get_method(&pooled.nominator, "get_roles", vec![])
        .expect("the nominator answers");
    assert_eq!(roles.exit_code, 0, "a refused stake changed what the contract can answer");
}

/// The capital comes back, which is why this is a missed round rather than a loss.
#[test]
fn the_refused_stake_returns_to_the_nominator() {
    let mut pooled = launch(20_000 * TOS);
    let election = pooled.election();
    let before = pooled.balance(&pooled.nominator.clone());

    pooled.from(&pooled.validator.clone(), stake_order(1, 1_000 * TOS, election), 2 * TOS);

    let after = pooled.balance(&pooled.nominator.clone());
    assert!(
        after > before - 100 * TOS,
        "a refused stake cost the nominator {} nanotomis",
        before - after
    );
}

/// Recovering a stake still reaches the elector, because that operation was not removed.
/// Only the way in is gone, which is what makes the failure a missed round rather than
/// stranded capital.
#[test]
fn recovering_a_stake_still_reaches_the_elector() {
    let mut pooled = launch(20_000 * TOS);
    let result = pooled.from(&pooled.validator.clone(), simple_order(RECOVER_STAKE, 1), 2 * TOS);
    let tags = reply_tags(&result);
    assert!(tags.contains(&RECOVER_STAKE), "the nominator did not ask the elector for its stake");
    let elector = pooled.elector.clone();
    let (_, answered) = elector_verdict(&result, &elector);
    assert!(
        !answered.contains(&UNKNOWN_QUERY),
        "the elector no longer knows how to return a stake: {answered:02x?}"
    );
}
