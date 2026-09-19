/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Behavioural coverage for the elector, which had none.
//!
//! Until now the elector was covered by a compile-and-compare-the-hash check and by Fift
//! assertions on the bytes of the messages sent to it. Nothing executed it, so every claim
//! about what it does with a stake, an election or a validator set was a claim about code
//! nobody had run. The post-quantum work changes the elector's storage, its authorisation
//! and the descriptors it emits, and none of that can be proved against a contract with no
//! behavioural baseline.
//!
//! These tests run the real contract, from the real zerostate, under the real transaction
//! executor. The elector's state machine advances on tick transactions rather than on
//! messages, so it is driven the way the chain drives it.

use chain_block::{Account, ConfigParams, MsgAddressInt, ShardStateUnsplit, TransactionTickTock};
use tos_sandbox::{Blockchain, generate_zerostate_state};

/// The zerostate is generated rather than fixtured, so these tests run against the
/// contracts and the configuration the chain would actually launch with.
fn zerostate() -> ShardStateUnsplit {
    let root = std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root above the contracts crate")
            .to_path_buf()
    });
    generate_zerostate_state(root.join("crypto/smartcont/gen-zerostate.fif"))
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

struct Chain {
    blockchain: Blockchain,
    elector: MsgAddressInt,
    config_contract: MsgAddressInt,
    validators_until: u32,
    elect_begin_before: u32,
}

/// The two system contracts, loaded from the zerostate into a chain that carries the same
/// configuration they were deployed with.
fn launch() -> Chain {
    let state = zerostate();
    let config = configuration(&state);
    let elector = masterchain(config.elector_address().expect("elector address"));
    let config_contract = masterchain(config.config_address().expect("configuration address"));
    let current = config.validator_set().expect("the zerostate elects a validator set");
    let params = config.elector_params().expect("elector parameters");

    let elector_account = account(&state, &elector);
    let config_account = account(&state, &config_contract);

    let mut blockchain = Blockchain::with_config(config).expect("sandbox with the real config");
    blockchain.set_workchain(-1);
    blockchain.set_account(elector.clone(), elector_account);
    blockchain.set_account(config_contract.clone(), config_account);

    Chain {
        blockchain,
        elector,
        config_contract,
        validators_until: current.utime_until(),
        elect_begin_before: params.elections_start_before,
    }
}

fn active_election_id(chain: &Chain) -> i64 {
    let result = chain
        .blockchain
        .run_get_method(&chain.elector, "active_election_id", vec![])
        .expect("the elector answers its own get-method");
    assert_eq!(result.exit_code, 0, "active_election_id failed: {}", result.exit_code);
    result
        .stack
        .last()
        .expect("a return value")
        .as_integer()
        .expect("an integer")
        .to_string()
        .parse::<i64>()
        .expect("an election id")
}

#[test]
fn the_zerostate_starts_with_no_election_open() {
    let chain = launch();
    assert_eq!(active_election_id(&chain), 0, "genesis must not have an election already open");
    assert!(chain.blockchain.get_account(&chain.config_contract).is_some());
}

#[test]
fn a_tick_before_the_window_does_not_open_an_election() {
    let mut chain = launch();
    // One second before the window: the contract reads the clock, not the tick.
    let before = chain.validators_until - chain.elect_begin_before - 1;
    chain.blockchain.set_now(before);
    // The tick has to have run the contract. Without this, a tick the executor refused
    // would look exactly like a contract that correctly declined to open an election.
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success()
        .expect_exit_code(0);
    assert_eq!(
        active_election_id(&chain),
        0,
        "an election opened before the window the configuration defines"
    );
}

#[test]
fn a_tick_inside_the_window_opens_an_election() {
    let mut chain = launch();
    let opens = chain.validators_until - chain.elect_begin_before;
    chain.blockchain.set_now(opens);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success()
        .expect_exit_code(0);
    let election = active_election_id(&chain);
    assert_ne!(election, 0, "the window opened and no election did");
    assert_eq!(
        election as u32, chain.validators_until,
        "an election is identified by when the set it elects takes over"
    );
}
