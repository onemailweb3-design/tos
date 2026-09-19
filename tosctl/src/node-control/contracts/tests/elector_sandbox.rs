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
    elect_end_before: u32,
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
        elect_end_before: params.elections_end_before,
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

// ---------------------------------------------------------------------------
// Staking
//
// A stake is an internal message carrying a signature over fields the contract
// rebuilds for itself, including the sender's address. The signature is what makes a
// registration belong to a key; the sender's address in the preimage is what stops the
// same signed request being replayed from somewhere else.
// ---------------------------------------------------------------------------

/// The elector's own tags, so a reply is read rather than guessed at.
const STAKE_ACCEPTED: u32 = 0xf374484c;
const STAKE_RETURNED: u32 = 0xee6f454c;
const NEW_STAKE: u32 = 0x4e73744b;
/// `return_stake` reason 1: the signature did not verify.
const REASON_BAD_SIGNATURE: u32 = 1;
const REASON_WRONG_ELECTION: u32 = 3;
const ELECT_REQUEST: u32 = 0x654c5074;

const TOS: u64 = 1_000_000_000;

/// Exactly what the contract signs over: its own tag, the terms, the sender it saw, and
/// the transport identity being claimed. Built here independently of the contract, so a
/// change to either side's field order stops the signature verifying.
///
/// The bytes are signed as they are. `check_data_signature` verifies Ed25519 over the
/// slice's raw bytes and does not hash them first, unlike the variant that takes a hash,
/// so signing a digest here would produce a signature the contract cannot accept.
fn election_request(
    stake_at: u32,
    max_factor: u32,
    source: &chain_block::AccountId,
    adnl: &[u8; 32],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(76);
    preimage.extend_from_slice(&ELECT_REQUEST.to_be_bytes());
    preimage.extend_from_slice(&stake_at.to_be_bytes());
    preimage.extend_from_slice(&max_factor.to_be_bytes());
    preimage.extend_from_slice(&source.get_bytestring(0));
    preimage.extend_from_slice(adnl);
    assert_eq!(preimage.len(), 76, "the signed preimage is four words and two addresses");
    preimage
}

fn stake_body(
    query_id: u64,
    public_key: &[u8; 32],
    stake_at: u32,
    max_factor: u32,
    adnl: &[u8; 32],
    signature: &[u8; 64],
) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut signature_cell = chain_block::BuilderData::new();
    signature_cell.append_raw(signature, 512).expect("signature bits");
    let mut body = chain_block::BuilderData::new();
    body.append_u32(NEW_STAKE).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_raw(public_key, 256).expect("public key");
    body.append_u32(stake_at).expect("election");
    body.append_u32(max_factor).expect("max factor");
    body.append_raw(adnl, 256).expect("adnl address");
    body.checked_append_reference(signature_cell.into_cell().expect("signature cell"))
        .expect("signature reference");
    body.into_cell().expect("stake body")
}

/// The tag and reason of the first reply the elector sent back. A refusal carries the
/// reason it refused for, and a test that only read the tag would report every refusal as
/// the one it was looking for.
fn reply(result: &tos_sandbox::SendResult) -> (u32, u32) {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    let mut answer = None;
    transaction
        .iterate_out_msgs(|message| {
            if answer.is_none() {
                if let Some(body) = message.body() {
                    let mut body = body.clone();
                    let tag = body.get_next_u32().expect("a reply tag");
                    let _query = body.get_next_u64().expect("a query id");
                    answer = Some((tag, body.get_next_u32().unwrap_or(0)));
                }
            }
            Ok(true)
        })
        .expect("out messages");
    answer.expect("the elector always answers a stake")
}

struct Validator {
    key: ed25519_dalek::SigningKey,
    public_key: [u8; 32],
    adnl: [u8; 32],
}

impl Validator {
    fn new(seed: u8) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        Self { key, public_key, adnl: [seed ^ 0xff; 32] }
    }
}

/// An open election, plus a funded masterchain account to stake from.
fn open_election(name: &str, balance: u64) -> (Chain, tos_sandbox::Treasury, u32) {
    let mut chain = launch();
    let opens = chain.validators_until - chain.elect_begin_before;
    chain.blockchain.set_now(opens);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    let election = active_election_id(&chain) as u32;
    assert_ne!(election, 0, "the fixture needs an open election");
    let treasury = chain.blockchain.treasury(name, balance).expect("a funded sender");
    (chain, treasury, election)
}

fn stake_of(chain: &Chain, public_key: &[u8; 32]) -> u128 {
    let result = chain
        .blockchain
        .run_get_method(
            &chain.elector,
            "participates_in",
            vec![tos_vm::stack::StackItem::integer(
                tos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(public_key),
            )],
        )
        .expect("the elector answers");
    assert_eq!(result.exit_code, 0, "participates_in failed");
    result
        .stack
        .last()
        .expect("a stake")
        .as_integer()
        .expect("an integer")
        .to_string()
        .parse()
        .expect("a stake")
}

/// The running total the open election carries. It decides whether the election has
/// enough stake to close and how small a further stake may be, so it must never exceed
/// what the members actually placed.
fn declared_total_stake(chain: &Chain) -> u128 {
    let result = chain
        .blockchain
        .run_get_method(&chain.elector, "participant_list_extended", vec![])
        .expect("the elector answers");
    assert_eq!(result.exit_code, 0, "participant_list_extended failed");
    assert_eq!(result.stack.len(), 7, "the election summary changed shape");
    result.stack[3].as_integer().expect("an integer").to_string().parse().expect("a running total")
}

#[test]
fn a_signed_stake_registers_the_validator() {
    let (mut chain, treasury, election) = open_election("validator-a", 20_000 * TOS);
    let validator = Validator::new(0xa1);
    let max_factor = 0x10000;
    let request =
        election_request(election, max_factor, &treasury.address().address(), &validator.adnl);
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&validator.key, &request).to_bytes();

    let body =
        stake_body(1, &validator.public_key, election, max_factor, &validator.adnl, &signature);
    let result = chain
        .blockchain
        .send_message(treasury.build_message(&chain.elector, 11_000 * TOS, true, Some(body)))
        .expect("the stake is delivered");
    result.expect_success();

    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "the elector refused a correctly signed stake");
    assert_eq!(
        stake_of(&chain, &validator.public_key),
        (11_000 * TOS - TOS) as u128,
        "the registered stake is what was sent, less the confirmation the elector returns"
    );
}

#[test]
fn a_stake_signed_by_a_different_key_is_returned() {
    let (mut chain, treasury, election) = open_election("validator-b", 20_000 * TOS);
    let validator = Validator::new(0xb2);
    let impostor = Validator::new(0xb3);
    let max_factor = 0x10000;
    let request =
        election_request(election, max_factor, &treasury.address().address(), &validator.adnl);
    // Signed by a key that is not the one being registered, which is the whole of the
    // difference between this and the accepted case.
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&impostor.key, &request).to_bytes();

    let body =
        stake_body(2, &validator.public_key, election, max_factor, &validator.adnl, &signature);
    let result = chain
        .blockchain
        .send_message(treasury.build_message(&chain.elector, 11_000 * TOS, true, Some(body)))
        .expect("the stake is delivered");

    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake signed by another key was accepted, or refused for another reason"
    );
    assert_eq!(stake_of(&chain, &validator.public_key), 0, "a refused stake was registered anyway");
}

#[test]
fn a_stake_signed_for_another_sender_is_returned() {
    let (mut chain, treasury, election) = open_election("validator-c", 20_000 * TOS);
    let elsewhere =
        chain.blockchain.treasury("validator-c-elsewhere", TOS).expect("another account");
    let validator = Validator::new(0xc4);
    let max_factor = 0x10000;
    // A signature that is valid, for the same key and the same election, but made for a
    // different sender. Without the source address in the preimage this would be
    // replayable from any account.
    let request =
        election_request(election, max_factor, &elsewhere.address().address(), &validator.adnl);
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&validator.key, &request).to_bytes();

    let body =
        stake_body(3, &validator.public_key, election, max_factor, &validator.adnl, &signature);
    let result = chain
        .blockchain
        .send_message(treasury.build_message(&chain.elector, 11_000 * TOS, true, Some(body)))
        .expect("the stake is delivered");

    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake signed for another sender was accepted, or refused for another reason"
    );
    assert_eq!(stake_of(&chain, &validator.public_key), 0, "a refused stake was registered anyway");
}

/// `return_stake` reason 4: a key already staked from a different address.
const REASON_ANOTHER_ADDRESS: u32 = 4;

/// Sign and send a stake, returning what the elector answered.
fn stake(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    validator: &Validator,
    election: u32,
    query_id: u64,
    value: u64,
) -> tos_sandbox::SendResult {
    let max_factor = 0x10000;
    let request =
        election_request(election, max_factor, &from.address().address(), &validator.adnl);
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&validator.key, &request).to_bytes();
    let body = stake_body(
        query_id,
        &validator.public_key,
        election,
        max_factor,
        &validator.adnl,
        &signature,
    );
    chain
        .blockchain
        .send_message(from.build_message(&chain.elector, value, true, Some(body)))
        .expect("the stake is delivered")
}

#[test]
fn a_second_stake_from_the_same_address_is_added_to_the_first() {
    let (mut chain, treasury, election) = open_election("validator-d", 40_000 * TOS);
    let validator = Validator::new(0xd5);

    let first = stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(reply(&first), (STAKE_ACCEPTED, 0), "the first stake was refused");
    let second = stake(&mut chain, &treasury, &validator, election, 2, 12_000 * TOS);
    assert_eq!(reply(&second), (STAKE_ACCEPTED, 0), "topping up an own stake was refused");

    assert_eq!(
        stake_of(&chain, &validator.public_key),
        (23_000 * TOS - 2 * TOS) as u128,
        "two stakes from one address must accumulate, less the two confirmations"
    );
    assert_eq!(
        declared_total_stake(&chain),
        stake_of(&chain, &validator.public_key),
        "a top-up brings new money once, so the election's total is the only member's stake"
    );
}

#[test]
fn the_same_key_cannot_be_staked_from_a_second_address() {
    let (mut chain, treasury, election) = open_election("validator-e", 40_000 * TOS);
    let elsewhere =
        chain.blockchain.treasury("validator-e-second", 40_000 * TOS).expect("an account");
    let validator = Validator::new(0xe6);

    let first = stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(reply(&first), (STAKE_ACCEPTED, 0), "the first stake was refused");
    let registered = stake_of(&chain, &validator.public_key);

    // Correctly signed for its own sender, so only the rule that a key belongs to one
    // controlling address can refuse it.
    let second = stake(&mut chain, &elsewhere, &validator, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&second),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "a key was staked from a second address, or refused for another reason"
    );
    assert_eq!(
        stake_of(&chain, &validator.public_key),
        registered,
        "a refused stake changed the registration it was refused for"
    );
}

// ---------------------------------------------------------------------------
// Closing an election
//
// The elector computes a validator set, sends it to the configuration contract, and
// forgets the election only once it sees that set installed. Three separate things, and
// the third is the one that makes the elector's state depend on authoritative state
// rather than on its own success at sending a message.
// ---------------------------------------------------------------------------

/// The configuration contract's answers to a proposed validator set.
const VALIDATOR_SET_INSTALLED: u32 = 0xee764f4b;
const VALIDATOR_SET_REFUSED: u32 = 0xee764f6f;

/// The configuration a block would be built with, taken from the configuration contract's
/// own storage. Its data is `cfg_dict:^Cell seqno:uint32 public_key:uint256 votes:^Cell`,
/// and the chain's parameters are that first reference.
fn configuration_from_contract(chain: &Chain) -> ConfigParams {
    use chain_block::HashmapE;
    let account = chain
        .blockchain
        .get_account(&chain.config_contract)
        .expect("the configuration contract is deployed");
    let data = account.get_data().expect("the configuration contract has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let parameters = slice.checked_drain_reference().expect("the parameter dictionary");
    ConfigParams {
        config_addr: chain.config_contract.address().clone(),
        config_params: HashmapE::with_hashmap(32, Some(parameters)),
    }
}

fn parameter_present(config: &ConfigParams, index: u32) -> bool {
    config.config_present(index).expect("parameter lookup")
}

/// Everything a reply from either contract carries, by the address that sent it, so a
/// cascade can be read rather than guessed at.
fn replies(result: &tos_sandbox::SendResult) -> Vec<u32> {
    let mut tags = Vec::new();
    for (_, transaction) in &result.transactions {
        transaction
            .iterate_out_msgs(|message| {
                if let Some(body) = message.body() {
                    if let Ok(tag) = body.clone().get_next_u32() {
                        tags.push(tag);
                    }
                }
                Ok(true)
            })
            .expect("out messages");
    }
    tags
}

/// An election with enough validators and enough total stake to succeed: the
/// configuration requires four participants and forty thousand TOS between them.
fn elect_four() -> (Chain, u32, Vec<Validator>) {
    let (mut chain, treasury, election) = open_election("validator-set-a", 200_000 * TOS);
    let mut validators = Vec::new();
    for index in 0..4u8 {
        let validator = Validator::new(0x40 + index);
        let account = chain
            .blockchain
            .treasury(&format!("validator-set-{index}"), 40_000 * TOS)
            .expect("a funded account");
        let result =
            stake(&mut chain, &account, &validator, election, 10 + index as u64, 11_000 * TOS);
        assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "validator {index} could not stake");
        validators.push(validator);
    }
    let _ = treasury;
    (chain, election, validators)
}

#[test]
fn a_closed_election_sends_its_set_to_the_configuration_contract() {
    let (mut chain, election, validators) = elect_four();
    assert!(!parameter_present(chain.blockchain.config_params(), 36), "nothing is elected yet");

    // The election closes before the set it elects takes over, by the margin the
    // configuration states.
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    let result =
        chain.blockchain.tick_tock(&chain.elector, TransactionTickTock::Tick).expect("tick runs");
    result.expect_success();

    let tags = replies(&result);
    assert!(
        tags.contains(&VALIDATOR_SET_INSTALLED),
        "the configuration contract did not accept the elected set: {tags:02x?}"
    );
    assert!(!tags.contains(&VALIDATOR_SET_REFUSED), "the configuration contract refused the set");

    let installed = configuration_from_contract(&chain);
    assert!(
        parameter_present(&installed, 36),
        "the configuration contract answered yes without storing the next validator set"
    );
    let next = installed.next_validator_set().expect("the stored set parses");
    assert_eq!(next.list().len(), validators.len(), "every staking validator should be elected");
}

#[test]
fn the_election_is_forgotten_only_once_the_set_is_installed() {
    let (mut chain, election, _validators) = elect_four();
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();

    // The set is in the configuration contract's storage, but the chain has not adopted
    // it yet, and the elector reads the chain.
    //
    // The tick above conducted the election and stopped there, so it never reached the
    // question this test is about. A second tick does, and it must find the elected set
    // absent from the chain and keep the election. Without this tick the test would pass
    // whatever the elector decides when it does look.
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    assert_ne!(
        active_election_id(&chain),
        0,
        "the elector forgot an election whose set the chain had not adopted"
    );

    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts what the configuration contract installed");
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();

    assert_eq!(
        active_election_id(&chain),
        0,
        "the elector kept an election whose set is installed"
    );
}

// ---------------------------------------------------------------------------
// What the elector keeps, and for how long
// ---------------------------------------------------------------------------

#[test]
fn one_address_may_register_two_separate_keys() {
    let (mut chain, treasury, election) = open_election("validator-f", 60_000 * TOS);
    let first = Validator::new(0xf1);
    let second = Validator::new(0xf2);

    assert_eq!(
        reply(&stake(&mut chain, &treasury, &first, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );
    assert_eq!(
        reply(&stake(&mut chain, &treasury, &second, election, 2, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );

    // Two members, because membership is a property of the key here and one account may
    // hold several. A design that identifies a member by its controlling account instead
    // has to answer this case differently, which is why it is pinned rather than assumed.
    assert_ne!(stake_of(&chain, &first.public_key), 0, "the first key is not registered");
    assert_ne!(stake_of(&chain, &second.public_key), 0, "the second key is not registered");
    assert_ne!(
        first.public_key, second.public_key,
        "the fixture must use two keys for this to mean anything"
    );
}

/// `HashmapE n X` is a bit saying whether anything is stored, and a reference to the tree
/// if there is. Read that way rather than through a helper, so the field order below is
/// the contract's storage layout and not an approximation of it.
fn next_dictionary(slice: &mut chain_block::SliceData, bit_len: usize) -> chain_block::HashmapE {
    let present = slice.get_next_bit().expect("the presence bit of a dictionary");
    let root = if present {
        Some(slice.checked_drain_reference().expect("the tree of a non-empty dictionary"))
    } else {
        None
    };
    chain_block::HashmapE::with_hashmap(bit_len, root)
}

/// The elector's storage: `elect credits past_elections tomis active_id active_hash`.
fn past_elections(chain: &Chain) -> chain_block::HashmapE {
    let account = chain.blockchain.get_account(&chain.elector).expect("the elector is deployed");
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let _current = next_dictionary(&mut slice, 32);
    let _credits = next_dictionary(&mut slice, 256);
    next_dictionary(&mut slice, 32)
}

#[test]
fn a_finished_election_is_kept_without_any_key_material() {
    let (mut chain, election, validators) = elect_four();
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the installed set");
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    assert_eq!(active_election_id(&chain), 0, "the election should be finished by now");

    let past = past_elections(&chain);
    let record = past
        .get(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32)
                    .expect("election key"),
            )
            .expect("key slice"),
        )
        .expect("lookup")
        .unwrap_or_else(|| panic!("no record for the election that just finished"));

    // unfreeze_at:uint32 stake_held:uint32 vset_hash:uint256 frozen:HashmapE total:Tomis
    // bonuses:Tomis complaints:HashmapE
    let mut fields = record;
    let _unfreeze_at = fields.get_next_u32().expect("unfreeze time");
    let _stake_held = fields.get_next_u32().expect("hold time");
    let _vset_hash = fields.get_next_bits(256).expect("the set this election produced");
    let frozen = next_dictionary(&mut fields, 256);

    let mut counted = 0;
    chain_block::HashmapType::iterate_slices(&frozen, |_key, value| {
        // A frozen stake is an address, a weight, an amount and a flag. Nothing here
        // refers to another cell, and a consensus key does not fit in one, so this is
        // what says the elector is not keeping key material after the fact.
        assert_eq!(
            value.remaining_references(),
            0,
            "a frozen stake carries a reference, which is where a key would hide"
        );
        counted += 1;
        Ok(true)
    })
    .expect("frozen stakes");
    assert_eq!(counted, validators.len(), "every elected validator should be frozen");
}

// ---------------------------------------------------------------------------
// Rotation
//
// The configuration contract moves the next set into place on a tock, and keeps the set
// it replaced. Three validator sets exist at once during this, which is the shape any
// sizing of these accounts has to account for.
// ---------------------------------------------------------------------------

/// Elect a set, install it, and let the chain adopt it. Returns the moment the elected
/// set takes over.
fn elect_and_install() -> (Chain, u32) {
    let (mut chain, election, _validators) = elect_four();
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the installed set");
    let next =
        chain.blockchain.config_params().next_validator_set().expect("the next set is installed");
    (chain, next.utime_since())
}

#[test]
fn the_next_set_replaces_the_current_one_and_the_current_becomes_the_previous() {
    let (mut chain, takes_over) = elect_and_install();
    let before = chain.blockchain.config_params().clone();
    let replaced = before.validator_set().expect("a current set").utime_since();
    let arriving = before.next_validator_set().expect("a next set").utime_since();
    assert_ne!(replaced, arriving, "the fixture needs two distinguishable sets");

    // Before the moment it takes over, a tock must leave the sets alone.
    chain.blockchain.set_now(takes_over - 1);
    chain
        .blockchain
        .tick_tock(&chain.config_contract, TransactionTickTock::Tock)
        .expect("tock runs")
        .expect_success();
    let early = configuration_from_contract(&chain);
    assert!(parameter_present(&early, 36), "the next set was consumed before its time");
    assert_eq!(
        early.validator_set().expect("a current set").utime_since(),
        replaced,
        "the current set changed before the next one was due"
    );

    chain.blockchain.set_now(takes_over);
    chain
        .blockchain
        .tick_tock(&chain.config_contract, TransactionTickTock::Tock)
        .expect("tock runs")
        .expect_success();

    let after = configuration_from_contract(&chain);
    assert!(!parameter_present(&after, 36), "the next set is still there after taking over");
    assert_eq!(
        after.validator_set().expect("a current set").utime_since(),
        arriving,
        "the elected set did not become the current one"
    );
    assert_eq!(
        after.prev_validator_set().expect("a previous set").utime_since(),
        replaced,
        "the set that was replaced was not kept as the previous one"
    );
}

// ---------------------------------------------------------------------------
// Configuration votes
//
// A validator votes by signing, and the configuration contract verifies that signature
// against the descriptor at the index the vote names. The elected set from the tests
// above is what makes this testable: these are keys this test holds.
// ---------------------------------------------------------------------------

const NEW_PROPOSAL: u32 = 0x6e565052;
const PROPOSAL_ACCEPTED: u32 = 0xee565052;
const VOTE: u32 = 0x566f7465;
const VOTE_SIGN_TAG: u32 = 0x566f7445;
/// `send_confirmation(.., res + 0xd6745240)` with status 2: the vote was registered.
const VOTE_REGISTERED: u32 = 0xd6745240 + 2;
/// `throw_unless(34, check_data_signature(..))`.
const ERROR_BAD_VOTE_SIGNATURE: i32 = 34;

/// A set elected by this test, rotated into place, so the current validators are keys the
/// test holds and can sign with.
fn elect_install_and_rotate() -> (Chain, Vec<Validator>, u32) {
    let (mut chain, election, validators) = elect_four();
    let closes = election - chain.elect_end_before;
    chain.blockchain.set_now(closes);
    chain
        .blockchain
        .tick_tock(&chain.elector, TransactionTickTock::Tick)
        .expect("tick runs")
        .expect_success();
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the installed set");
    let takes_over = chain
        .blockchain
        .config_params()
        .next_validator_set()
        .expect("the next set is installed")
        .utime_since();
    chain.blockchain.set_now(takes_over);
    chain
        .blockchain
        .tick_tock(&chain.config_contract, TransactionTickTock::Tock)
        .expect("tock runs")
        .expect_success();
    chain
        .blockchain
        .set_config(configuration_from_contract(&chain))
        .expect("the chain adopts the rotated set");
    (chain, validators, election)
}

/// `cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell) if_hash_equal:(Maybe uint256)`
fn proposal_cell(param_id: i32, value: u32) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut payload = chain_block::BuilderData::new();
    payload.append_u32(value).expect("proposed value");
    let mut proposal = chain_block::BuilderData::new();
    proposal.append_u8(0xf3).expect("tag");
    proposal.append_i32(param_id).expect("parameter");
    proposal.append_bit_one().expect("a value is present");
    proposal.checked_append_reference(payload.into_cell().expect("value cell")).expect("value");
    proposal.append_bit_zero().expect("no expected current value");
    proposal.into_cell().expect("proposal")
}

/// The index of a validator in the current set, by its public key, because a vote names
/// an index and the contract checks the key stored at it.
fn index_of(chain: &Chain, public_key: &[u8; 32]) -> u16 {
    let set = chain.blockchain.config_params().validator_set().expect("a current set");
    for (index, descriptor) in set.list().iter().enumerate() {
        if descriptor.public_key().expect("a classical descriptor").key_bytes() == public_key {
            return index as u16;
        }
    }
    panic!("the validator is not in the current set");
}

fn vote_body(
    query_id: u64,
    signature: &[u8; 64],
    idx: u16,
    proposal_hash: &[u8; 32],
) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u32(VOTE).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_raw(signature, 512).expect("signature");
    body.append_u32(VOTE_SIGN_TAG).expect("signed tag");
    body.append_u16(idx).expect("index");
    body.append_raw(proposal_hash, 256).expect("proposal");
    body.into_cell().expect("vote body")
}

/// Exactly the bytes the contract verifies: everything after the signature.
fn vote_preimage(idx: u16, proposal_hash: &[u8; 32]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(38);
    preimage.extend_from_slice(&VOTE_SIGN_TAG.to_be_bytes());
    preimage.extend_from_slice(&idx.to_be_bytes());
    preimage.extend_from_slice(proposal_hash);
    preimage
}

/// Register a proposal and return its hash, which is how every vote refers to it.
fn propose(chain: &mut Chain, param_id: i32, value: u32) -> [u8; 32] {
    use chain_block::{GetRepresentationHash, IBitstring};
    let proposal = proposal_cell(param_id, value);
    let hash: [u8; 32] =
        proposal.hash(0).as_slice()[..32].try_into().expect("a proposal hash is 32 bytes");

    let mut body = chain_block::BuilderData::new();
    body.append_u32(NEW_PROPOSAL).expect("operation");
    body.append_u64(1).expect("query id");
    // Absolute times are converted to a duration by the contract, and the configuration
    // requires a proposal to be stored for at least a million seconds.
    body.append_u32(chain.blockchain.now() + 2_000_000).expect("expiry");
    body.checked_append_reference(proposal).expect("proposal");
    body.append_bit_zero().expect("not a critical parameter");

    let proposer = chain.blockchain.treasury("proposer", 1_000 * TOS).expect("a funded account");
    let result = chain
        .blockchain
        .send_message(proposer.build_message(
            &chain.config_contract,
            100 * TOS,
            true,
            Some(body.into_cell().expect("proposal body")),
        ))
        .expect("the proposal is delivered");
    let tags = replies(&result);
    assert!(
        tags.contains(&PROPOSAL_ACCEPTED),
        "the configuration contract refused the proposal: {tags:02x?}"
    );
    hash
}

#[test]
fn a_validator_votes_for_a_proposal_with_the_key_in_the_current_set() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 42, 0xabcd);

    let voter = &validators[0];
    let idx = index_of(&chain, &voter.public_key);
    let signature: [u8; 64] =
        ed25519_dalek::Signer::sign(&voter.key, &vote_preimage(idx, &proposal)).to_bytes();
    let sender = chain.blockchain.treasury("vote-relay", 100 * TOS).expect("a funded account");
    let result = chain
        .blockchain
        .send_message(sender.build_message(
            &chain.config_contract,
            10 * TOS,
            true,
            Some(vote_body(2, &signature, idx, &proposal)),
        ))
        .expect("the vote is delivered");
    result.expect_success();

    let tags = replies(&result);
    assert!(tags.contains(&VOTE_REGISTERED), "the vote was not registered: {tags:02x?}");
}

#[test]
fn a_vote_signed_by_a_key_that_is_not_at_that_index_is_refused() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 42, 0xabcd);

    let voter = &validators[0];
    let other = &validators[1];
    let idx = index_of(&chain, &voter.public_key);
    assert_ne!(idx, index_of(&chain, &other.public_key), "the two validators share an index");
    // A signature that is valid, over the right proposal and the right index, made by a
    // validator who is not the one at that index.
    let signature: [u8; 64] =
        ed25519_dalek::Signer::sign(&other.key, &vote_preimage(idx, &proposal)).to_bytes();

    let sender = chain.blockchain.treasury("vote-relay", 100 * TOS).expect("a funded account");
    chain
        .blockchain
        .send_message(sender.build_message(
            &chain.config_contract,
            10 * TOS,
            true,
            Some(vote_body(3, &signature, idx, &proposal)),
        ))
        .expect("the vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
}

/// The configuration contract's stored sequence number, which its external path
/// increments on every message it accepts.
fn config_seqno(chain: &Chain) -> u64 {
    let result = chain
        .blockchain
        .run_get_method(&chain.config_contract, "seqno", vec![])
        .expect("the configuration contract answers");
    assert_eq!(result.exit_code, 0, "seqno failed");
    result
        .stack
        .last()
        .expect("a sequence number")
        .as_integer()
        .expect("an integer")
        .to_string()
        .parse()
        .expect("a sequence number")
}

/// The external vote path, which exists today and which the post-quantum design removes.
///
/// It verifies the signature before `accept_message`, so the check has to fit the
/// ordinary external admission credit. A post-quantum verification costs five times that
/// credit before it decodes an operand, which is why this path cannot survive the
/// conversion and is recorded here as it stands rather than as it is remembered.
#[test]
fn a_validator_can_still_vote_through_an_external_message() {
    let (mut chain, validators, _election) = elect_install_and_rotate();
    let proposal = propose(&mut chain, 43, 0x1234);

    let voter = &validators[2];
    let idx = index_of(&chain, &voter.public_key);
    let seqno = config_seqno(&chain) as u32;
    let valid_until = chain.blockchain.now() + 600;

    let mut preimage = Vec::with_capacity(46);
    preimage.extend_from_slice(&VOTE.to_be_bytes());
    preimage.extend_from_slice(&seqno.to_be_bytes());
    preimage.extend_from_slice(&valid_until.to_be_bytes());
    preimage.extend_from_slice(&idx.to_be_bytes());
    preimage.extend_from_slice(&proposal);
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&voter.key, &preimage).to_bytes();

    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_raw(&signature, 512).expect("signature");
    body.append_raw(&preimage, 46 * 8).expect("the signed fields follow the signature");

    let result = chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::external(&chain.config_contract)
                .body(body.into_cell().expect("external vote body"))
                .build(),
        )
        .expect("the external vote is delivered");
    result.expect_success().expect_exit_code(0);

    assert_eq!(
        config_seqno(&chain),
        seqno as u64 + 1,
        "the external path accepted a message without counting it"
    );
}

// ---------------------------------------------------------------------------
// The unilateral administrator
//
// A single key, held off-chain, can change any configuration parameter and replace the
// configuration and elector code, through an external message. The post-quantum design
// removes this rather than converting it, so what it can do today is recorded here.
// ---------------------------------------------------------------------------

/// `perform_action` 0x43665021: change one configuration parameter.
const ADMIN_CHANGE_PARAMETER: u32 = 0x43665021;

/// Put a known administrator key into the configuration contract's storage.
///
/// The zerostate generates that key into a file this test does not read, so the path
/// could not be exercised at all without supplying one. Only the stored key changes; the
/// contract, and every check it makes, is the deployed one.
fn install_admin_key(chain: &mut Chain, public_key: &[u8; 32]) {
    use chain_block::IBitstring;
    let mut account = chain
        .blockchain
        .get_account(&chain.config_contract)
        .expect("the configuration contract is deployed")
        .clone();
    let data = account.get_data().expect("storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let parameters = slice.checked_drain_reference().expect("the parameter dictionary");
    let seqno = slice.get_next_u32().expect("sequence number");
    let _old_key = slice.get_next_bits(256).expect("the administrator key");

    let mut rebuilt = chain_block::BuilderData::new();
    rebuilt.checked_append_reference(parameters).expect("parameters");
    rebuilt.append_u32(seqno).expect("sequence number");
    rebuilt.append_raw(public_key, 256).expect("administrator key");
    rebuilt.checked_append_references_and_data(&slice).expect("the votes");
    account.set_data(rebuilt.into_cell().expect("storage"));
    chain.blockchain.set_account(chain.config_contract.clone(), account);
}

#[test]
fn the_administrator_key_alone_can_change_a_configuration_parameter() {
    let (mut chain, _validators, _election) = elect_install_and_rotate();
    let admin = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
    install_admin_key(&mut chain, &admin.verifying_key().to_bytes());

    let parameter = 77i32;
    assert!(
        !parameter_present(&configuration_from_contract(&chain), parameter as u32),
        "the fixture needs a parameter that is not already set"
    );

    use chain_block::IBitstring;
    let mut value = chain_block::BuilderData::new();
    value.append_u32(0xc0ffee).expect("a value");
    let mut signed = chain_block::BuilderData::new();
    signed.append_u32(ADMIN_CHANGE_PARAMETER).expect("action");
    signed.append_u32(config_seqno(&chain) as u32).expect("sequence number");
    signed.append_u32(chain.blockchain.now() + 600).expect("valid until");
    signed.append_i32(parameter).expect("parameter");
    signed.checked_append_reference(value.into_cell().expect("value")).expect("value");
    let signed_cell = signed.into_cell().expect("the signed part");

    // This path hashes what it verifies, unlike the vote path beside it, which signs the
    // bytes as they are. Two instructions, two meanings, one contract.
    use chain_block::GetRepresentationHash;
    let digest = signed_cell.hash(0);
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&admin, digest.as_slice()).to_bytes();

    let mut body = chain_block::BuilderData::new();
    body.append_raw(&signature, 512).expect("signature");
    body.checked_append_references_and_data(
        &chain_block::SliceData::load_cell(signed_cell).expect("the signed part"),
    )
    .expect("the signed part follows the signature");

    chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::external(&chain.config_contract)
                .body(body.into_cell().expect("administrator message"))
                .build(),
        )
        .expect("the administrator message is delivered")
        .expect_success()
        .expect_exit_code(0);

    assert!(
        parameter_present(&configuration_from_contract(&chain), parameter as u32),
        "one key changed nothing, or the path this test exists to record has already gone"
    );
}

/// A controller policy holding `count` distinct code hashes.
fn controller_policy(count: usize) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut dict = chain_block::HashmapE::with_bit_len(256);
    for index in 0..count {
        let mut key = [0u8; 32];
        key[31] = index as u8;
        dict.set(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(key.to_vec(), 256).expect("a key"),
            )
            .expect("a key slice"),
            &chain_block::SliceData::default(),
        )
        .expect("insert");
    }
    let mut value = chain_block::BuilderData::new();
    match chain_block::HashmapType::data(&dict) {
        Some(root) => {
            value.append_bit_one().expect("a non-empty policy");
            value.checked_append_reference(root.clone()).expect("the codes");
        }
        None => {
            value.append_bit_zero().expect("an empty policy");
        }
    }
    value.into_cell().expect("a controller policy")
}

/// Install a configuration parameter through the administrator path.
fn admin_set_parameter(
    chain: &mut Chain,
    admin: &ed25519_dalek::SigningKey,
    parameter: i32,
    value: chain_block::Cell,
) -> tos_sandbox::SendResult {
    use chain_block::{GetRepresentationHash, IBitstring};
    let mut signed = chain_block::BuilderData::new();
    signed.append_u32(ADMIN_CHANGE_PARAMETER).expect("action");
    signed.append_u32(config_seqno(chain) as u32).expect("sequence number");
    signed.append_u32(chain.blockchain.now() + 600).expect("valid until");
    signed.append_i32(parameter).expect("parameter");
    signed.checked_append_reference(value).expect("value");
    let signed_cell = signed.into_cell().expect("the signed part");
    let digest = signed_cell.hash(0);
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(admin, digest.as_slice()).to_bytes();

    let mut body = chain_block::BuilderData::new();
    body.append_raw(&signature, 512).expect("signature");
    body.checked_append_references_and_data(
        &chain_block::SliceData::load_cell(signed_cell).expect("the signed part"),
    )
    .expect("the signed part follows the signature");

    chain
        .blockchain
        .send_message(
            tos_sandbox::MessageBuilder::external(&chain.config_contract)
                .body(body.into_cell().expect("administrator message"))
                .build(),
        )
        .expect("the administrator message is delivered")
}

/// The ceiling on admitted controller codes is part of the parameter, not a note about it.
///
/// A hashmap carries no cardinality, so a bound that lives only in prose is a bound that
/// is never reached by anything. This is the configuration contract refusing the ninth.
#[test]
fn the_controller_policy_cannot_grow_past_its_ceiling() {
    let (mut chain, _validators, _election) = elect_install_and_rotate();
    let admin = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
    install_admin_key(&mut chain, &admin.verifying_key().to_bytes());

    // Eight is the ceiling, and it is admitted.
    let result = admin_set_parameter(&mut chain, &admin, 47, controller_policy(8));
    assert_eq!(exit_code_of(&result), 0, "a policy at the ceiling was refused");
    assert!(
        parameter_present(&configuration_from_contract(&chain), 47),
        "the policy was not installed"
    );

    // The ninth is not, and the configuration is left as it was.
    let refused = admin_set_parameter(&mut chain, &admin, 47, controller_policy(9));
    assert_ne!(
        exit_code_of(&refused),
        0,
        "a ninth controller code was admitted, so the ceiling is prose"
    );

    // What is installed is still the policy of eight.
    let installed = configuration_from_contract(&chain).config(47).expect("parameter 47").is_some();
    assert!(installed, "the refused policy removed the one that was there");
}

/// The compute-phase exit code of the first transaction a message produced.
fn exit_code_of(result: &tos_sandbox::SendResult) -> i32 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    match transaction.read_description().expect("description") {
        chain_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
            other => panic!("the compute phase did not run: {other:?}"),
        },
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Complaints
//
// A validator of the current set votes, by signature, to punish a validator of a past
// one. The same authority as a configuration vote, in the other contract, and the same
// conversion ahead of it.
// ---------------------------------------------------------------------------

const NEW_COMPLAINT: u32 = 0x52674370;
const COMPLAINT_VOTE: u32 = 0x56744370;
const COMPLAINT_VOTE_SIGN_TAG: u32 = 0x56744350;
const COMPLAINT_ACCEPTED: u32 = 0xf2676350;
/// `send_message_back(.., res + 0xd6745240, ..)`: 1 is a vote counted and not yet
/// decisive, 2 is the vote that carries the complaint and applies the fine.
const COMPLAINT_VOTE_COUNTED: u32 = 0xd6745240 + 1;
const COMPLAINT_CARRIED: u32 = 0xd6745240 + 2;

/// `validator_complaint#bc validator_pubkey:uint256 description:^ComplaintDescr
/// created_at:uint32 severity:uint8 reward_addr:uint256 paid:Tomis suggested_fine:Tomis
/// suggested_fine_part:uint32`
///
/// The elector rewrites the reward address, the creation time and the amount paid before
/// storing it, so the hash a vote refers to is not the hash of what was sent. The test
/// reads that hash out of the contract's own storage rather than recomputing it.
fn complaint_body(query_id: u64, election: u32, accused: &[u8; 32]) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut description = chain_block::BuilderData::new();
    description.append_u32(0).expect("an empty description");

    let mut body = chain_block::BuilderData::new();
    body.append_u32(NEW_COMPLAINT).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_u32(election).expect("the election complained about");
    body.append_i8(0xbcu8 as i8).expect("complaint tag");
    body.append_raw(accused, 256).expect("the accused validator");
    body.checked_append_reference(description.into_cell().expect("description"))
        .expect("description");
    body.append_u32(0).expect("created at, rewritten by the contract");
    body.append_u8(1).expect("severity");
    body.append_raw(&[0u8; 32], 256).expect("reward address, rewritten by the contract");
    body.append_bits(0, 4).expect("paid, rewritten by the contract");
    // The fine has to exceed what the complaint costs to file, or the elector refuses it
    // as not worth hearing, and it has to stay within the stake it would be taken from.
    body.append_bits(8, 4).expect("the length of the suggested fine");
    body.append_u64(500 * TOS).expect("suggested fine");
    body.append_u32(0).expect("suggested fine part");
    body.into_cell().expect("complaint body")
}

/// The hashes of the complaints the elector is holding for an election, which is how a
/// vote names the one it is for.
///
/// `unfreeze_at:uint32 stake_held:uint32 vset_hash:uint256 frozen:HashmapE total:Tomis
/// bonuses:Tomis complaints:HashmapE`, read in that order because the dictionary is at
/// the end of it.
fn complaint_hashes(chain: &Chain, election: u32) -> Vec<[u8; 32]> {
    let past = past_elections(chain);
    let key = chain_block::SliceData::load_builder(
        chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32).expect("key"),
    )
    .expect("key slice");
    let mut record = past.get(key).expect("lookup").expect("a record for that election");
    record.get_next_u32().expect("unfreeze time");
    record.get_next_u32().expect("hold time");
    record.get_next_bits(256).expect("the set this election produced");
    next_dictionary(&mut record, 256);
    for _ in 0..2 {
        // An amount is a length in bytes followed by that many bytes, and a zero amount
        // is a length of zero followed by nothing.
        let bytes = record.get_next_int(4).expect("the length of an amount") as usize;
        if bytes > 0 {
            record.get_next_bits(bytes * 8).expect("an amount");
        }
    }
    let complaints = next_dictionary(&mut record, 256);

    let mut hashes = Vec::new();
    chain_block::HashmapType::iterate_slices(&complaints, |key, _value| {
        let bytes = key.get_bytestring(0);
        hashes.push(bytes[..32].try_into().expect("a complaint hash is 32 bytes"));
        Ok(true)
    })
    .expect("complaints");
    hashes
}

/// What a past election still holds frozen for a validator, which is what a fine is taken
/// from.
fn frozen_stake(chain: &Chain, election: u32, validator: &[u8; 32]) -> u128 {
    let past = past_elections(chain);
    let key = chain_block::SliceData::load_builder(
        chain_block::BuilderData::with_raw(election.to_be_bytes().to_vec(), 32).expect("key"),
    )
    .expect("key slice");
    let mut record = past.get(key).expect("lookup").expect("a record for that election");
    record.get_next_u32().expect("unfreeze time");
    record.get_next_u32().expect("hold time");
    record.get_next_bits(256).expect("the set this election produced");
    let frozen = next_dictionary(&mut record, 256);
    let entry = frozen
        .get(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(validator.to_vec(), 256).expect("key"),
            )
            .expect("key slice"),
        )
        .expect("lookup")
        .expect("the validator is frozen in that election");
    let mut entry = entry;
    entry.get_next_bits(256).expect("controller");
    entry.get_next_u64().expect("weight");
    let bytes = entry.get_next_int(4).expect("the length of the stake") as usize;
    if bytes == 0 {
        return 0;
    }
    let mut stake: u128 = 0;
    for byte in entry.get_next_bits(bytes * 8).expect("the stake") {
        stake = (stake << 8) | byte as u128;
    }
    stake
}

#[test]
fn a_validator_votes_to_punish_a_validator_of_a_past_election() {
    let (mut chain, validators, election) = elect_install_and_rotate();
    let accused = &validators[3];
    let complainant =
        chain.blockchain.treasury("complainant", 1_000 * TOS).expect("a funded account");

    let result = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            300 * TOS,
            true,
            Some(complaint_body(1, election, &accused.public_key)),
        ))
        .expect("the complaint is delivered");
    let tags = replies(&result);
    assert!(tags.contains(&COMPLAINT_ACCEPTED), "the elector refused the complaint: {tags:02x?}");

    let hashes = complaint_hashes(&chain, election);
    assert_eq!(hashes.len(), 1, "exactly one complaint should be registered");
    let complaint = hashes[0];

    let before = frozen_stake(&chain, election, &accused.public_key);
    assert_ne!(before, 0, "the accused should have a frozen stake to be fined from");

    // One vote is counted and decides nothing; the complaint carries once enough weight
    // has voted for it. Both answers are checked, because a contract that accepted the
    // first vote as decisive would be a very different contract.
    let sender = chain.blockchain.treasury("complaint-relay", 100 * TOS).expect("an account");
    let mut carried = false;
    for (round, voter) in validators.iter().take(3).enumerate() {
        let idx = index_of(&chain, &voter.public_key);
        let mut preimage = Vec::with_capacity(42);
        preimage.extend_from_slice(&COMPLAINT_VOTE_SIGN_TAG.to_be_bytes());
        preimage.extend_from_slice(&idx.to_be_bytes());
        preimage.extend_from_slice(&election.to_be_bytes());
        preimage.extend_from_slice(&complaint);
        let signature: [u8; 64] = ed25519_dalek::Signer::sign(&voter.key, &preimage).to_bytes();

        use chain_block::IBitstring;
        let mut body = chain_block::BuilderData::new();
        body.append_u32(COMPLAINT_VOTE).expect("operation");
        body.append_u64(10 + round as u64).expect("query id");
        body.append_raw(&signature, 512).expect("signature");
        body.append_raw(&preimage, 42 * 8).expect("the signed fields");

        let result = chain
            .blockchain
            .send_message(sender.build_message(
                &chain.elector,
                10 * TOS,
                true,
                Some(body.into_cell().expect("vote body")),
            ))
            .expect("the vote is delivered");
        result.expect_success();
        let tags = replies(&result);
        if round == 0 {
            assert!(
                tags.contains(&COMPLAINT_VOTE_COUNTED),
                "the first vote was not counted, or decided on its own: {tags:02x?}"
            );
            assert_eq!(
                frozen_stake(&chain, election, &accused.public_key),
                before,
                "a fine was taken before the complaint carried"
            );
        }
        carried |= tags.contains(&COMPLAINT_CARRIED);
    }

    assert!(carried, "three of four validators voted and the complaint did not carry");
    let after = frozen_stake(&chain, election, &accused.public_key);
    assert_eq!(
        before - after,
        (500 * TOS) as u128,
        "the fine the complaint asked for was not taken from the frozen stake"
    );
}

#[test]
fn a_complaint_vote_signed_by_another_validator_is_refused() {
    let (mut chain, validators, election) = elect_install_and_rotate();
    let accused = &validators[3];
    let complainant =
        chain.blockchain.treasury("complainant-b", 1_000 * TOS).expect("a funded account");
    let result = chain
        .blockchain
        .send_message(complainant.build_message(
            &chain.elector,
            300 * TOS,
            true,
            Some(complaint_body(1, election, &accused.public_key)),
        ))
        .expect("the complaint is delivered");
    assert!(replies(&result).contains(&COMPLAINT_ACCEPTED), "the complaint was refused");
    let complaint = complaint_hashes(&chain, election)[0];

    let voter = &validators[0];
    let other = &validators[1];
    let idx = index_of(&chain, &voter.public_key);
    assert_ne!(idx, index_of(&chain, &other.public_key), "the two validators share an index");
    let mut preimage = Vec::with_capacity(42);
    preimage.extend_from_slice(&COMPLAINT_VOTE_SIGN_TAG.to_be_bytes());
    preimage.extend_from_slice(&idx.to_be_bytes());
    preimage.extend_from_slice(&election.to_be_bytes());
    preimage.extend_from_slice(&complaint);
    // Valid, over the right complaint and the right index, by the wrong validator.
    let signature: [u8; 64] = ed25519_dalek::Signer::sign(&other.key, &preimage).to_bytes();

    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u32(COMPLAINT_VOTE).expect("operation");
    body.append_u64(20).expect("query id");
    body.append_raw(&signature, 512).expect("signature");
    body.append_raw(&preimage, 42 * 8).expect("the signed fields");

    let sender = chain.blockchain.treasury("complaint-relay-b", 100 * TOS).expect("an account");
    chain
        .blockchain
        .send_message(sender.build_message(
            &chain.elector,
            10 * TOS,
            true,
            Some(body.into_cell().expect("vote body")),
        ))
        .expect("the vote is delivered")
        .expect_aborted()
        .expect_exit_code(ERROR_BAD_VOTE_SIGNATURE);
}

// ---------------------------------------------------------------------------
// Post-quantum staking
//
// A separate operation, never a reinterpretation of the classical one. The request
// carries a key and a signature; the contract supplies both identities itself -- the
// validator is the account that sent the message, and the key identity is derived from
// the key presented -- so a request cannot name one validator while carrying another's
// key.
// ---------------------------------------------------------------------------

const PQ_STAKE_OP: u32 = 0x5051_7374;
const PQ_STAKE_SIGN_TAG: u32 = 0x5051_5354;
const ELECTION_CONTEXT: &[u8] = b"TOS-VALIDATOR-ELECTION-v1";
/// A different authorisation's context, used to show a signature cannot cross between them.
const CONFIG_VOTE_CONTEXT: &[u8] = b"TOS-VALIDATOR-CONFIG-VOTE-v1";
const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;
/// `return_stake` reason 7: no transport address was stated.
/// No election is taking stakes: none is open, it is finished, or it has closed.
/// The library refuses a suite it does not admit, before anything reads the key.
const ERROR_UNADMITTED_ALGORITHM: i32 = 61;
const REASON_NO_ELECTION: u32 = 0;
const REASON_BELOW_MINIMUM: u32 = 5;
const REASON_FACTOR_BELOW_ONE: u32 = 6;
const REASON_NO_ADNL: u32 = 7;

/// The key tool from `crypto/pq/tools`. Signing is deliberately absent from the node's
/// libraries, so a test that needs a signature shells out to the tool operators use.
fn key_tool() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PQ_KEY_TOOL") {
        return std::path::PathBuf::from(path);
    }
    let root = std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root")
            .to_path_buf()
    });
    for candidate in ["build-pq-key/tos-pq-key", "build/tos-pq-key"] {
        let path = root.join(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!(
        "the ML-DSA-44 key tool is needed for post-quantum staking: build it with \
         `cmake -S crypto/pq/tools -B build-pq-key && cmake --build build-pq-key`, \
         or point PQ_KEY_TOOL at it"
    );
}

fn run_key_tool(args: &[&str]) -> Vec<String> {
    let out =
        std::process::Command::new(key_tool()).args(args).output().expect("the key tool runs");
    assert!(out.status.success(), "the key tool failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(|line| line.trim().to_string()).collect()
}

/// A post-quantum validator: a key of its own, and the transport address it claims.
struct PqValidator {
    key_file: std::path::PathBuf,
    public_key: Vec<u8>,
    adnl: [u8; 32],
}

impl PqValidator {
    fn new(index: u8) -> Self {
        let key_file = std::env::temp_dir().join(format!("tos-pq-elector-test-{index}.key"));
        if !key_file.exists() {
            run_key_tool(&["keygen", key_file.to_str().expect("path")]);
        }
        let public_key =
            hex::decode(&run_key_tool(&["public", key_file.to_str().expect("path")])[0])
                .expect("hex");
        assert_eq!(public_key.len(), MLDSA44_PUBLIC_KEY_BYTES);
        PqValidator { key_file, public_key, adnl: [0xd0 ^ index; 32] }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_under(message, ELECTION_CONTEXT)
    }

    fn sign_under(&self, message: &[u8], context: &[u8]) -> Vec<u8> {
        let signature = hex::decode(
            &run_key_tool(&[
                "sign",
                self.key_file.to_str().expect("path"),
                &hex::encode(message),
                &hex::encode(context),
            ])[0],
        )
        .expect("hex");
        assert_eq!(signature.len(), 2420);
        signature
    }

    fn key_id(&self) -> chain_block::UInt256 {
        chain_block::derive_consensus_key_id(1, &self.public_key)
    }
}

fn stored_bytes(bytes: &[u8]) -> chain_block::Cell {
    chain_block::pq_bytes::pack_pq_bytes(bytes, chain_block::pq_bytes::PQ_BYTES_HARD_MAX)
        .expect("bytes of admitted length")
}

/// The 114 bytes a stake request signs, built here independently of the contract.
fn pq_stake_preimage(
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    validator_id: &chain_block::UInt256,
    key_id: &chain_block::UInt256,
    adnl: &[u8; 32],
) -> Vec<u8> {
    pq_stake_preimage_for(global_id, stake_at, max_factor, validator_id, 1, key_id, adnl)
}

/// The same bytes with the suite stated explicitly, so a signature can be made over a
/// suite other than the one the request carries.
#[allow(clippy::too_many_arguments)]
fn pq_stake_preimage_for(
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    validator_id: &chain_block::UInt256,
    algorithm_id: u16,
    key_id: &chain_block::UInt256,
    adnl: &[u8; 32],
) -> Vec<u8> {
    chain_block::pq_elector::stake_preimage(
        global_id,
        stake_at,
        max_factor,
        validator_id,
        algorithm_id,
        key_id,
        &chain_block::UInt256::from(*adnl),
    )
}

/// A proof of what a sender was deployed as: the state init's own bits, with a pruned
/// branch in place of each child.
fn controller_proof(chain: &Chain, who: &tos_sandbox::Treasury) -> chain_block::Cell {
    use chain_block::{GetRepresentationHash, IBitstring, Serializable};
    let account = chain.blockchain.get_account(who.address()).expect("the sender exists");
    let state_init = account.state_init().expect("the sender was deployed with a state init");
    let root = state_init.write_to_new_cell().expect("state init").into_cell().expect("cell");
    let mut partial = chain_block::BuilderData::with_raw(root.data().to_vec(), root.bit_length())
        .expect("the root's own bits");
    for index in 0..root.references_count() {
        let child = root.reference(index).expect("a child");
        let mut branch = chain_block::BuilderData::new();
        branch.set_type(chain_block::CellType::PrunedBranch);
        branch.append_u8(u8::from(chain_block::CellType::PrunedBranch)).expect("the type byte");
        branch.append_u8(1).expect("one stored hash, at merkle depth zero");
        branch.append_raw(child.repr_hash().as_slice(), 256).expect("the pruned hash");
        branch.append_u16(child.repr_depth()).expect("the pruned depth");
        partial
            .checked_append_reference(branch.into_cell().expect("a pruned branch"))
            .expect("a pruned child");
    }
    partial.into_cell().expect("a controller proof")
}

/// The code every sandbox account is deployed with, which is what the fixture admits.
///
/// One admitted code and many accounts is the shape of the real rule; the controller
/// contract's own behaviour is exercised in its own file, not here.
fn admit_sender_code(chain: &mut Chain, who: &tos_sandbox::Treasury) {
    use chain_block::{GetRepresentationHash, IBitstring};
    let account = chain.blockchain.get_account(who.address()).expect("the sender exists");
    let state_init = account.state_init().expect("a state init");
    let code_hash = state_init.code().expect("code").repr_hash();

    let mut dict = chain_block::HashmapE::with_bit_len(256);
    dict.set(
        chain_block::SliceData::load_builder(
            chain_block::BuilderData::with_raw(code_hash.as_slice().to_vec(), 256).expect("a key"),
        )
        .expect("a key slice"),
        &chain_block::SliceData::default(),
    )
    .expect("insert");
    let mut value = chain_block::BuilderData::new();
    value.append_bit_one().expect("a non-empty policy");
    value
        .checked_append_reference(
            chain_block::HashmapType::data(&dict).expect("a non-empty dictionary").clone(),
        )
        .expect("the codes");

    let mut config = chain.blockchain.config_params().clone();
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParamAny(
            47,
            value.into_cell().expect("a controller policy"),
        ))
        .expect("the policy is installed");
    chain.blockchain.set_config(config).expect("the configuration is replaced");
}

fn pq_stake_body(
    query_id: u64,
    validator: &PqValidator,
    stake_at: u32,
    max_factor: u32,
    signature: &[u8],
    proof: Option<chain_block::Cell>,
) -> chain_block::Cell {
    use chain_block::IBitstring;
    let mut body = chain_block::BuilderData::new();
    body.append_u32(PQ_STAKE_OP).expect("operation");
    body.append_u64(query_id).expect("query id");
    body.append_u16(1).expect("algorithm");
    body.checked_append_reference(stored_bytes(&validator.public_key)).expect("public key");
    body.append_u32(stake_at).expect("election");
    body.append_u32(max_factor).expect("max factor");
    body.append_raw(&validator.adnl, 256).expect("adnl address");
    body.checked_append_reference(stored_bytes(signature)).expect("signature");
    match proof {
        Some(cell) => {
            body.append_bit_one().expect("a proof is present");
            body.checked_append_reference(cell).expect("the controller proof");
        }
        None => {
            body.append_bit_zero().expect("no proof");
        }
    }
    body.into_cell().expect("stake body")
}

/// The post-quantum instruction is gated on global version 16, and the zerostate declares
/// 14. Raising it here is what N3 assumes and the activation gate will make true; the
/// classical tests above stay on the zerostate's version, which is what keeps them
/// evidence about the chain as it is.
fn raise_to_post_quantum_version(chain: &mut Chain) {
    let mut config = chain.blockchain.config_params().clone();
    let version = match config.config(8).expect("parameter 8") {
        Some(chain_block::ConfigParamEnum::ConfigParam8(v)) => v.global_version,
        _ => panic!("the chain states no global version"),
    };
    assert!(version.version < 16, "the fixture is raising a version that is already there");
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam8(chain_block::ConfigParam8 {
            global_version: chain_block::GlobalVersion { version: 16, ..version },
        }))
        .expect("set the global version");
    chain.blockchain.set_config(config).expect("the chain adopts the version");

    // A post-quantum stake is admitted only from an account born with a controller code
    // the configuration admits. Every sandbox account shares one code, so admitting it
    // admits the senders these tests use -- one code, many accounts, which is the shape
    // of the real rule. What a real controller does with that authority is exercised in
    // `validator_controller_sandbox.rs`.
    let probe = chain.blockchain.treasury("controller-policy-probe", TOS).expect("an account");
    admit_sender_code(chain, &probe);
}

/// Send a post-quantum stake, signing for whichever sender is named.
fn pq_stake_from(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    signed_for: &tos_sandbox::Treasury,
    validator: &PqValidator,
    election: u32,
    query_id: u64,
    value: u64,
) -> tos_sandbox::SendResult {
    pq_stake_with_max_factor(chain, from, signed_for, validator, election, query_id, value, 0x10000)
}

/// The same stake, signed and sent with a stated maximum stake factor, so a request that
/// is well formed apart from that factor can be built.
#[allow(clippy::too_many_arguments)]
fn pq_stake_with_max_factor(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    signed_for: &tos_sandbox::Treasury,
    validator: &PqValidator,
    election: u32,
    query_id: u64,
    value: u64,
    max_factor: u32,
) -> tos_sandbox::SendResult {
    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id, so nothing can sign for it"),
    };
    let validator_id =
        chain_block::UInt256::from_slice(&signed_for.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage(
        global_id,
        election,
        max_factor,
        &validator_id,
        &validator.key_id(),
        &validator.adnl,
    );
    let signature = validator.sign(&preimage);
    // A first registration proves what its sender was deployed as; a controller the book
    // already knows is re-checked against the policy instead.
    let proof = Some(controller_proof(chain, from));
    chain
        .blockchain
        .send_message(from.build_message(
            &chain.elector,
            value,
            true,
            Some(pq_stake_body(query_id, validator, election, max_factor, &signature, proof)),
        ))
        .expect("the stake is delivered")
}

fn pq_stake(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    validator: &PqValidator,
    election: u32,
    query_id: u64,
    value: u64,
) -> tos_sandbox::SendResult {
    let sender = from.clone();
    pq_stake_from(chain, from, &sender, validator, election, query_id, value)
}

/// The election's post-quantum book: members by controller, and the reverse index.
fn pq_book(chain: &Chain) -> (chain_block::HashmapE, chain_block::HashmapE) {
    let account = chain.blockchain.get_account(&chain.elector).expect("the elector is deployed");
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let elect = next_dictionary(&mut slice, 32);
    let root = chain_block::HashmapType::data(&elect).expect("an active election").clone();
    let mut es = chain_block::SliceData::load_cell(root).expect("the election");
    es.get_next_u32().expect("elect_at");
    es.get_next_u32().expect("elect_close");
    for _ in 0..2 {
        let bytes = es.get_next_int(4).expect("an amount length") as usize;
        if bytes > 0 {
            es.get_next_bits(bytes * 8).expect("an amount");
        }
    }
    next_dictionary(&mut es, 256); // classical members
    es.get_next_bit().expect("failed");
    es.get_next_bit().expect("finished");
    let members = next_dictionary(&mut es, 256);
    let key_owner = next_dictionary(&mut es, 256);
    (members, key_owner)
}

/// What a post-quantum controller has placed, according to its own member record.
fn pq_stake_of(chain: &Chain, controller: &tos_sandbox::Treasury) -> u128 {
    let (members, _) = pq_book(chain);
    let mut record = members
        .get(controller.address().address().clone())
        .expect("lookup")
        .expect("the controller is registered");
    let bytes = record.get_next_int(4).expect("a stake length") as usize;
    let mut stake = 0u128;
    if bytes > 0 {
        for byte in record.get_next_bits(bytes * 8).expect("a stake") {
            stake = (stake << 8) | u128::from(byte);
        }
    }
    stake
}

fn pq_member_key_id(
    chain: &Chain,
    controller: &tos_sandbox::Treasury,
) -> Option<chain_block::UInt256> {
    let (members, _) = pq_book(chain);
    let record = members.get(controller.address().address().clone()).expect("lookup")?;
    let mut record = record;
    let bytes = record.get_next_int(4).expect("stake length") as usize;
    if bytes > 0 {
        record.get_next_bits(bytes * 8).expect("stake");
    }
    record.get_next_u32().expect("registered at");
    record.get_next_u32().expect("max factor");
    record.get_next_u16().expect("algorithm");
    Some(chain_block::UInt256::from_slice(&record.get_next_bits(256).expect("key id")))
}

fn pq_key_holder(chain: &Chain, key_id: &chain_block::UInt256) -> Option<chain_block::UInt256> {
    let (_, key_owner) = pq_book(chain);
    let owner = key_owner
        .get(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(key_id.as_slice().to_vec(), 256).expect("key"),
            )
            .expect("key slice"),
        )
        .expect("lookup")?;
    let mut owner = owner;
    Some(chain_block::UInt256::from_slice(&owner.get_next_bits(256).expect("an owner")))
}

#[test]
fn a_signed_post_quantum_stake_registers_the_sender_as_the_validator() {
    let (mut chain, treasury, election) = open_election("pq-validator-a", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(0);

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    for (_, tx) in &result.transactions {
        eprintln!("tx: {:?}", tx.read_description().expect("description"));
    }
    result.expect_exit_code(0);
    assert_eq!(reply(&result), (STAKE_ACCEPTED, 0), "a correctly signed stake was refused");

    let controller =
        chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0));
    assert_eq!(
        pq_member_key_id(&chain, &treasury),
        Some(validator.key_id()),
        "the member record does not hold the key that was registered"
    );
    assert_eq!(
        pq_key_holder(&chain, &validator.key_id()),
        Some(controller),
        "the key was not claimed by the account that sent the stake"
    );
}

/// What the compute phase of the first transaction spent.
fn compute_gas(result: &tos_sandbox::SendResult) -> u64 {
    let (_, transaction) = result.transactions.first().expect("a transaction");
    match transaction.read_description().expect("description") {
        chain_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
            chain_block::TrComputePhase::Vm(vm) => vm.gas_used.as_u64(),
            other => panic!("the compute phase did not run: {other:?}"),
        },
        other => panic!("not an ordinary transaction: {other:?}"),
    }
}

#[test]
fn a_post_quantum_stake_signed_by_another_key_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-validator-b", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(1);
    let impostor = PqValidator::new(2);

    // The request carries the validator's key, and a signature by a key that is not it.
    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("no network id"),
    };
    let validator_id =
        chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage(
        global_id,
        election,
        0x10000,
        &validator_id,
        &validator.key_id(),
        &validator.adnl,
    );
    let signature = impostor.sign(&preimage);
    let proof = controller_proof(&chain, &treasury);
    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(1, &validator, election, 0x10000, &signature, Some(proof))),
        ))
        .expect("the stake is delivered");

    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake signed by another key was accepted, or refused for another reason"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "a refused stake was registered anyway");
}

#[test]
fn a_post_quantum_stake_signed_for_another_sender_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-validator-c", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let elsewhere = chain.blockchain.treasury("pq-validator-c-elsewhere", TOS).expect("an account");
    let validator = PqValidator::new(3);

    // Signed correctly, by the right key, for a different sender. The validator identity
    // is the account the elector sees, so this signature authorises nothing here.
    let result =
        pq_stake_from(&mut chain, &treasury, &elsewhere, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BAD_SIGNATURE),
        "a stake signed for another sender was accepted"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None);
}

#[test]
fn a_key_already_registered_by_another_controller_is_returned() {
    let (mut chain, first, election) = open_election("pq-validator-d", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let second =
        chain.blockchain.treasury("pq-validator-d-second", 40_000 * TOS).expect("an account");
    let validator = PqValidator::new(4);

    assert_eq!(
        reply(&pq_stake(&mut chain, &first, &validator, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );
    // The second controller signs correctly for itself, with the same consensus key. Only
    // the rule that a key belongs to one controller can refuse this.
    let result = pq_stake(&mut chain, &second, &validator, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "two controllers registered the same consensus key"
    );
    assert_eq!(
        pq_key_holder(&chain, &validator.key_id()),
        Some(chain_block::UInt256::from_slice(&first.address().address().get_bytestring(0))),
        "the refused registration moved the key"
    );
}

/// A key released by a rotation is registrable by the controller that was refused it.
///
/// The book and its reverse index are two halves of one fact, and the half that decides
/// admission is the index. Removing a key from it on rotation is only meaningful if the
/// removal is what a later registration sees; an index that merely looked empty to a
/// getter, while the member record still spoke for the key, would leave the key
/// permanently unusable by anyone.
#[test]
fn a_key_released_by_a_rotation_is_registrable_by_the_controller_it_was_refused_to() {
    let (mut chain, first, election) = open_election("pq-release", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let second = chain.blockchain.treasury("pq-release-second", 60_000 * TOS).expect("an account");
    let contested = PqValidator::new(12);
    let rotated = PqValidator::new(13);

    assert_eq!(
        reply(&pq_stake(&mut chain, &first, &contested, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the first controller could not register the contested key"
    );
    assert_eq!(
        reply(&pq_stake(&mut chain, &second, &contested, election, 2, 11_000 * TOS)),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "the second controller took a key that was already held"
    );

    assert_eq!(
        reply(&pq_stake(&mut chain, &first, &rotated, election, 3, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the holder could not rotate away from the contested key"
    );
    assert_eq!(
        reply(&pq_stake(&mut chain, &second, &contested, election, 4, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the released key stayed unusable by anyone"
    );

    let first_id = chain_block::UInt256::from_slice(&first.address().address().get_bytestring(0));
    let second_id = chain_block::UInt256::from_slice(&second.address().address().get_bytestring(0));
    assert_eq!(pq_member_key_id(&chain, &first), Some(rotated.key_id()));
    assert_eq!(pq_member_key_id(&chain, &second), Some(contested.key_id()));
    assert_eq!(pq_key_holder(&chain, &rotated.key_id()), Some(first_id));
    assert_eq!(
        pq_key_holder(&chain, &contested.key_id()),
        Some(second_id),
        "the index and the member records disagree about who holds the contested key"
    );
}

#[test]
fn a_controller_rotates_its_key_and_releases_the_one_it_held() {
    let (mut chain, treasury, election) = open_election("pq-validator-e", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let held = PqValidator::new(5);
    let rotated = PqValidator::new(6);

    let first = pq_stake(&mut chain, &treasury, &held, election, 1, 11_000 * TOS);
    assert_eq!(reply(&first), (STAKE_ACCEPTED, 0));
    let registration_gas = compute_gas(&first);

    let second = pq_stake(&mut chain, &treasury, &rotated, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&second),
        (STAKE_ACCEPTED, 0),
        "a rotation by the registered controller was refused"
    );
    let rotation_gas = compute_gas(&second);

    assert_eq!(
        pq_member_key_id(&chain, &treasury),
        Some(rotated.key_id()),
        "the member record still holds the key it rotated away from"
    );
    assert_eq!(
        pq_key_holder(&chain, &held.key_id()),
        None,
        "the released key is still claimed, so nobody can ever register it"
    );
    assert_eq!(
        pq_key_holder(&chain, &rotated.key_id()),
        Some(chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0)))
    );

    // The deferred measurements: a whole stake transaction, and a rotation, which does
    // the same work plus the removal from the reverse index.
    eprintln!("post-quantum stake: {registration_gas} gas; rotation: {rotation_gas} gas");
    // The elector is a special account, allowed seventy million gas by the zerostate's
    // masterchain prices. The point of the figure is how far under that it is.
    assert!(
        rotation_gas < 1_000_000,
        "a rotation costs {rotation_gas} gas, over what an ordinary transaction may spend"
    );
    assert!(
        rotation_gas >= registration_gas,
        "a rotation does strictly more work than a registration but cost less"
    );
}

/// Rewrite the open election with `book_fields` of the post-quantum book still present,
/// each of them an empty dictionary.
///
/// Zero is the storage an upgrade leaves behind: the configuration contract may replace
/// the elector's code while an election is open, and the upgrade hook sets the new code
/// without migrating a single cell, so the first thing the new code reads is an election
/// the old code wrote. One is a shape no version has ever written, and is here to show
/// that the election is read as one of the two shapes that exist and never as something
/// in between.
fn rewrite_election_with_book_fields(chain: &mut Chain, book_fields: usize) {
    use chain_block::IBitstring;
    let mut account =
        chain.blockchain.get_account(&chain.elector).expect("the elector is deployed").clone();
    let data = account.get_data().expect("the elector has storage");
    let mut slice = chain_block::SliceData::load_cell(data).expect("storage");
    let elect = next_dictionary(&mut slice, 32);
    let root = chain_block::HashmapType::data(&elect).expect("an active election").clone();
    let mut es = chain_block::SliceData::load_cell(root).expect("the election");

    let mut legacy = chain_block::BuilderData::new();
    legacy.append_u32(es.get_next_u32().expect("elect_at")).expect("elect_at");
    legacy.append_u32(es.get_next_u32().expect("elect_close")).expect("elect_close");
    for _ in 0..2 {
        let bytes = es.get_next_int(4).expect("an amount length") as usize;
        legacy.append_bits(bytes, 4).expect("an amount length");
        if bytes > 0 {
            let amount = es.get_next_bits(bytes * 8).expect("an amount");
            legacy.append_raw(&amount, bytes * 8).expect("an amount");
        }
    }
    for field in ["the members dictionary", "failed", "finished"] {
        if es.get_next_bit().expect(field) {
            legacy.append_bit_one().expect(field);
            if field == "the members dictionary" {
                let members = es.checked_drain_reference().expect("the members");
                legacy.checked_append_reference(members).expect("the members");
            }
        } else {
            legacy.append_bit_zero().expect(field);
        }
    }
    for _ in 0..book_fields {
        legacy.append_bit_zero().expect("an empty book dictionary");
    }

    let mut rebuilt = chain_block::BuilderData::new();
    rebuilt.append_bit_one().expect("an active election");
    rebuilt
        .checked_append_reference(legacy.into_cell().expect("the election"))
        .expect("the election");
    rebuilt.checked_append_references_and_data(&slice).expect("the rest of the storage");
    account.set_data(rebuilt.into_cell().expect("storage"));
    chain.blockchain.set_account(chain.elector.clone(), account);
}

#[test]
fn an_election_opened_before_the_upgrade_is_read_and_written_again() {
    let (mut chain, treasury, election) = open_election("legacy-elect", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let classical = Validator::new(0xf1);

    let opening = stake(&mut chain, &treasury, &classical, election, 1, 11_000 * TOS);
    assert_eq!(reply(&opening), (STAKE_ACCEPTED, 0), "the fixture needs a member");
    let placed = stake_of(&chain, &classical.public_key);
    rewrite_election_with_book_fields(&mut chain, 0);

    // Every entry point reads the election first, so an unreadable one stops the elector
    // altogether: no stake is accepted and no election ever closes.
    assert_eq!(
        declared_total_stake(&chain),
        placed,
        "an election opened by the previous code could not be read back"
    );

    let validator = PqValidator::new(9);
    let result = pq_stake(&mut chain, &treasury, &validator, election, 2, 12_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_ACCEPTED, 0),
        "the elector stopped working on the storage an upgrade leaves behind"
    );
    assert_eq!(
        pq_member_key_id(&chain, &treasury),
        Some(validator.key_id()),
        "the book was not created for an election that was opened without one"
    );
}

/// A stake for an election that is not the open one, refused for a reason that is
/// decided without looking at the key or the signature.
///
/// Anyone can send such a message, and the elector pays for what it does with it out of
/// the masterchain block's gas. Verifying a post-quantum signature is an order of
/// magnitude more expensive than everything else this contract does, so if it happened
/// before the cheap refusals, every one of those messages would cost the chain a
/// verification it never needed.
#[test]
fn a_stake_refused_without_its_key_does_not_pay_for_a_verification() {
    let (mut chain, treasury, election) = open_election("pq-refusal-cost", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(11);

    let refused = pq_stake(&mut chain, &treasury, &validator, election + 1, 1, 11_000 * TOS);
    assert_eq!(
        reply(&refused),
        (STAKE_RETURNED, REASON_WRONG_ELECTION),
        "the fixture must be refused for its election and nothing else"
    );
    let refusal = compute_gas(&refused);

    let accepted = pq_stake(&mut chain, &treasury, &validator, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&accepted),
        (STAKE_ACCEPTED, 0),
        "the fixture needs a registration to compare"
    );
    let registration = compute_gas(&accepted);

    let classical = Validator::new(0xf7);
    let classical_refused = stake(&mut chain, &treasury, &classical, election + 1, 3, 11_000 * TOS);
    assert_eq!(reply(&classical_refused), (STAKE_RETURNED, REASON_WRONG_ELECTION));
    let classical_refusal = compute_gas(&classical_refused);

    assert!(
        refusal * 4 < registration,
        "refusing a stake for its election costs {refusal} gas against {registration} for a \
         registration, so the verification is being paid for before the refusal"
    );
    assert!(
        refusal < classical_refusal * 2,
        "the same refusal costs {refusal} gas on the post-quantum path and \
         {classical_refusal} on the classical one, though neither needs a key"
    );
}

#[test]
fn half_a_post_quantum_book_is_refused_rather_than_read_as_empty() {
    let (mut chain, treasury, election) = open_election("legacy-partial", 40_000 * TOS);
    let classical = Validator::new(0xf3);
    let opening = stake(&mut chain, &treasury, &classical, election, 1, 11_000 * TOS);
    assert_eq!(reply(&opening), (STAKE_ACCEPTED, 0), "the fixture needs a member");

    // Neither version of the elector ever wrote one dictionary of the book. Reading such
    // an election as though the book were absent would hide the half that is there, so it
    // must throw instead: the two shapes that exist are the only ones accepted.
    rewrite_election_with_book_fields(&mut chain, 1);
    let result = chain
        .blockchain
        .run_get_method(&chain.elector, "participant_list_extended", vec![])
        .expect("the elector answers");
    assert_ne!(
        result.exit_code, 0,
        "an election in a shape no version ever wrote was read as a valid one"
    );
}

#[test]
fn a_post_quantum_top_up_adds_only_the_money_it_brings_to_the_election_total() {
    let (mut chain, treasury, election) = open_election("pq-validator-g", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(8);

    let first = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(reply(&first), (STAKE_ACCEPTED, 0), "the first stake was refused");
    assert_eq!(
        declared_total_stake(&chain),
        pq_stake_of(&chain, &treasury),
        "a single registration already disagrees with what the member holds"
    );

    let second = pq_stake(&mut chain, &treasury, &validator, election, 2, 12_000 * TOS);
    assert_eq!(reply(&second), (STAKE_ACCEPTED, 0), "topping up an own stake was refused");
    assert_eq!(
        pq_stake_of(&chain, &treasury),
        (23_000 * TOS - 2 * TOS) as u128,
        "two stakes from one controller must accumulate, less the two confirmations"
    );

    // The election closes on this running total, so counting a top-up twice lets an
    // election reach the minimum total stake on money nobody placed, and raises the
    // floor under which a later stake from anyone else is refused as too small.
    assert_eq!(
        declared_total_stake(&chain),
        pq_stake_of(&chain, &treasury),
        "the election counts more stake than its only member placed"
    );
}

/// The refusals that the cheap checks are responsible for, now that they run before the
/// verification. A reordering that made one of them unreachable would leave a request the
/// contract intends to refuse being refused by something else, or not at all.
#[test]
fn a_stake_stating_a_factor_below_one_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-factor", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(14);

    let result = pq_stake_with_max_factor(
        &mut chain,
        &treasury,
        &treasury,
        &validator,
        election,
        1,
        11_000 * TOS,
        0x10000 - 1,
    );
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_FACTOR_BELOW_ONE),
        "a validator asked to be weighted below the stake it placed"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

#[test]
fn a_stake_below_the_minimum_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-minimum", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(15);

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 2 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_BELOW_MINIMUM),
        "a stake under the minimum was registered"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

/// The window between an election's closing time and the tick that conducts it.
///
/// Nothing runs the elector on a schedule of its own: it is ticked, and the tick that
/// finds `now() >= elect_close` is what conducts the election and marks it finished.
/// Admitting a stake, or a rotation, for as long as that tick has not landed would make
/// membership depend on scheduling rather than on the election's own boundary.
/// Every distinct cell in a tree, and the bits they hold.
fn tree_size(root: &chain_block::Cell) -> (usize, usize) {
    fn walk(
        cell: &chain_block::Cell,
        seen: &mut std::collections::HashSet<chain_block::UInt256>,
        bits: &mut usize,
    ) {
        if !seen.insert(cell.repr_hash()) {
            return;
        }
        *bits += cell.bit_length();
        for index in 0..cell.references_count() {
            walk(&cell.reference(index).expect("a reference"), seen, bits);
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut bits = 0;
    walk(root, &mut seen, &mut bits);
    (seen.len(), bits)
}

/// What a stake actually costs to carry, measured on the request the contract now reads.
///
/// The design was sized against an estimate of this message before the request had its
/// final shape. The figures below are the shape that shipped, so a change to the carrier
/// has to be re-approved rather than absorbed.
#[test]
fn a_stake_request_is_the_size_the_design_was_sized_for() {
    let validator = PqValidator::new(23);
    let bare = pq_stake_body(1, &validator, 1_789_434_000, 0x10000, &vec![0u8; 2420], None);
    assert_eq!(
        tree_size(&bare),
        (34, 30_353),
        "a stake carrying no controller proof changed shape"
    );
}

/// The weight factor a member registered with, as its own record holds it.
fn pq_member_max_factor(chain: &Chain, controller: &tos_sandbox::Treasury) -> u32 {
    let (members, _) = pq_book(chain);
    let mut record = members
        .get(controller.address().address().clone())
        .expect("lookup")
        .expect("the controller is registered");
    let bytes = record.get_next_int(4).expect("a stake length") as usize;
    if bytes > 0 {
        record.get_next_bits(bytes * 8).expect("a stake");
    }
    record.get_next_u32().expect("registered at");
    record.get_next_u32().expect("max factor")
}

/// A stake states the weight factor it wants, and that statement is both what the
/// signature covers and what the book records.
///
/// Signing a field is not the same as committing the request's value of it: a contract
/// that built its preimage from a constant would still refuse every signature made over a
/// different one, and every negative case would pass. Only a request carrying a value
/// other than the default can tell the two apart.
#[test]
fn a_stake_registers_the_weight_factor_it_asked_for() {
    let (mut chain, treasury, election) = open_election("pq-factor-kept", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(19);
    let asked = 0x2_5000;

    let result = pq_stake_with_max_factor(
        &mut chain,
        &treasury,
        &treasury,
        &validator,
        election,
        1,
        11_000 * TOS,
        asked,
    );
    assert_eq!(
        reply(&result),
        (STAKE_ACCEPTED, 0),
        "a stake asking for a weight factor other than the default was refused"
    );
    assert_eq!(
        pq_member_max_factor(&chain, &treasury),
        asked,
        "the book recorded a weight factor the request did not ask for"
    );
}

/// The fields the preimage commits to, so that what is signed can be made to differ from
/// what is sent while everything else stays valid.
#[derive(Clone)]
struct SignedFields {
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    algorithm_id: u16,
    adnl: [u8; 32],
    key_id: chain_block::UInt256,
}

/// Send a well-formed stake whose signature was made over `signed` and under `context`.
///
/// The request itself is always the valid one, so the contract reaches the verification
/// with nothing else to object to, and each case isolates one field of the preimage.
fn pq_stake_signed_over(
    chain: &mut Chain,
    from: &tos_sandbox::Treasury,
    validator: &PqValidator,
    election: u32,
    signed: &SignedFields,
    context: &[u8],
) -> tos_sandbox::SendResult {
    let validator_id =
        chain_block::UInt256::from_slice(&from.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage_for(
        signed.global_id,
        signed.stake_at,
        signed.max_factor,
        &validator_id,
        signed.algorithm_id,
        &signed.key_id,
        &signed.adnl,
    );
    let signature = validator.sign_under(&preimage, context);
    chain
        .blockchain
        .send_message(from.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(
                1,
                validator,
                election,
                0x10000,
                &signature,
                Some(controller_proof(chain, from)),
            )),
        ))
        .expect("the stake is delivered")
}

/// Each field of the preimage, changed on its own, must cost the signature its validity.
///
/// The request is valid in every case; only what was signed differs. A field the contract
/// reads from the request but leaves out of the bytes it verifies would be a field an
/// authorised signature does not actually authorise, and this is the test that says which
/// fields those bytes cover.
#[test]
fn every_signed_field_of_a_stake_is_covered_by_its_signature() {
    let (mut chain, treasury, election) = open_election("pq-binding", 200_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(17);
    let other = PqValidator::new(18);

    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id"),
    };
    let honest = SignedFields {
        global_id,
        stake_at: election,
        max_factor: 0x10000,
        algorithm_id: 1,
        adnl: validator.adnl,
        key_id: validator.key_id(),
    };

    // The fixture has to be able to succeed, or every case below would pass for nothing.
    let accepted = pq_stake_signed_over(
        &mut chain,
        &treasury,
        &validator,
        election,
        &honest,
        ELECTION_CONTEXT,
    );
    assert_eq!(reply(&accepted), (STAKE_ACCEPTED, 0), "the honest fixture was refused");

    let cases: Vec<(&str, SignedFields, &[u8])> = vec![
        (
            "another network",
            SignedFields { global_id: global_id ^ 1, ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        (
            "another election",
            SignedFields { stake_at: election - 1, ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        (
            "another weight factor",
            SignedFields { max_factor: 0x20000, ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        (
            "another transport address",
            SignedFields { adnl: [0x5e; 32], ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        (
            "another key",
            SignedFields { key_id: other.key_id(), ..honest.clone() },
            ELECTION_CONTEXT,
        ),
        // While one suite is admitted this case cannot tell a preimage that commits the
        // request's suite from one that commits the constant 1, because they are the same
        // value. What distinguishes them is a request carrying a second admitted suite,
        // which is the positive case to add on the day there is one.
        ("another suite", SignedFields { algorithm_id: 7, ..honest.clone() }, ELECTION_CONTEXT),
        ("another purpose", honest.clone(), CONFIG_VOTE_CONTEXT),
    ];

    for (what, signed, context) in cases {
        let result =
            pq_stake_signed_over(&mut chain, &treasury, &validator, election, &signed, context);
        assert_eq!(
            reply(&result),
            (STAKE_RETURNED, REASON_BAD_SIGNATURE),
            "a stake signed for {what} was accepted, so that field is not covered"
        );
    }
}

/// A rotation that is refused leaves the controller exactly as it was.
///
/// The refusal happens between reading the book and writing it, so the question is
/// whether anything was released on the way to it: a controller left holding neither its
/// old key nor the new one would be a validator nobody can reach, and a key released
/// without being replaced is one another controller may take.
#[test]
fn a_refused_rotation_leaves_both_controllers_as_they_were() {
    let (mut chain, mine, election) = open_election("pq-atomic", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let theirs = chain.blockchain.treasury("pq-atomic-other", 60_000 * TOS).expect("an account");
    let held = PqValidator::new(20);
    let wanted = PqValidator::new(21);

    assert_eq!(
        reply(&pq_stake(&mut chain, &mine, &held, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );
    assert_eq!(
        reply(&pq_stake(&mut chain, &theirs, &wanted, election, 2, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0)
    );
    let total_before = declared_total_stake(&chain);

    // A rotation to a key the other controller holds. It cannot be granted.
    assert_eq!(
        reply(&pq_stake(&mut chain, &mine, &wanted, election, 3, 11_000 * TOS)),
        (STAKE_RETURNED, REASON_ANOTHER_ADDRESS),
        "a controller rotated onto a key another one holds"
    );

    let mine_id = chain_block::UInt256::from_slice(&mine.address().address().get_bytestring(0));
    let theirs_id = chain_block::UInt256::from_slice(&theirs.address().address().get_bytestring(0));
    assert_eq!(
        pq_member_key_id(&chain, &mine),
        Some(held.key_id()),
        "the refused rotation moved the controller off the key it held"
    );
    assert_eq!(
        pq_key_holder(&chain, &held.key_id()),
        Some(mine_id),
        "the refused rotation released the key it was rotating away from"
    );
    assert_eq!(
        pq_key_holder(&chain, &wanted.key_id()),
        Some(theirs_id),
        "the refused rotation took the key from the controller that holds it"
    );
    assert_eq!(
        declared_total_stake(&chain),
        total_before,
        "the refused rotation was counted into the election total"
    );
}

/// A request naming a suite the contract does not admit is refused before it is read as
/// a key.
///
/// One suite is admitted, and a second would be a protocol change rather than a
/// configuration value. The guard that says so has to be reachable from a request, or it
/// is a claim about a constant instead of a rule about what arrives.
#[test]
fn a_stake_naming_an_unadmitted_suite_is_refused() {
    use chain_block::IBitstring;
    let (mut chain, treasury, election) = open_election("pq-suite", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(24);

    let mut body = chain_block::BuilderData::new();
    body.append_u32(PQ_STAKE_OP).expect("operation");
    body.append_u64(1).expect("query id");
    body.append_u16(7).expect("a suite that is not admitted");
    body.checked_append_reference(stored_bytes(&validator.public_key)).expect("public key");
    body.append_u32(election).expect("election");
    body.append_u32(0x10000).expect("max factor");
    body.append_raw(&validator.adnl, 256).expect("adnl address");
    body.checked_append_reference(stored_bytes(&vec![0u8; 2420])).expect("signature");
    body.append_bit_one().expect("a proof is present");
    body.checked_append_reference(controller_proof(&chain, &treasury))
        .expect("the controller proof");

    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(body.into_cell().expect("stake body")),
        ))
        .expect("the stake is delivered");
    result.expect_exit_code(ERROR_UNADMITTED_ALGORITHM);
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

#[test]
fn a_stake_after_the_election_closes_is_returned_before_the_tick_conducts_it() {
    let (mut chain, treasury, election) = open_election("pq-after-close", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(16);

    chain.blockchain.set_now(election - chain.elect_end_before);
    // Deliberately no tick: the election is closed by the clock and not yet by its state.
    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_NO_ELECTION),
        "a stake was admitted to an election that may already be conducted"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");
}

/// Reasons the elector refuses a stake over the controller it came from.
const REASON_PROOF_MISSING: u32 = 8;
const REASON_PROOF_MISMATCH: u32 = 9;
const REASON_CODE_NOT_ADMITTED: u32 = 10;
const REASON_NO_POLICY: u32 = 11;
const REASON_CODE_RETIRED: u32 = 12;

/// Replace the admitted controller codes with `codes`, or remove the policy entirely.
fn set_policy(chain: &mut Chain, codes: &[chain_block::UInt256]) {
    use chain_block::IBitstring;
    let mut config = chain.blockchain.config_params().clone();
    let mut value = chain_block::BuilderData::new();
    let mut dict = chain_block::HashmapE::with_bit_len(256);
    for code in codes {
        dict.set(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(code.as_slice().to_vec(), 256).expect("a key"),
            )
            .expect("a key slice"),
            &chain_block::SliceData::default(),
        )
        .expect("insert");
    }
    match chain_block::HashmapType::data(&dict) {
        Some(root) => {
            value.append_bit_one().expect("a non-empty policy");
            value.checked_append_reference(root.clone()).expect("the codes");
        }
        None => {
            value.append_bit_zero().expect("an empty policy");
        }
    }
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParamAny(
            47,
            value.into_cell().expect("a controller policy"),
        ))
        .expect("the policy is installed");
    chain.blockchain.set_config(config).expect("the configuration is replaced");
}

/// The code an account was deployed with.
fn sender_code_hash(chain: &Chain, who: &tos_sandbox::Treasury) -> chain_block::UInt256 {
    use chain_block::GetRepresentationHash;
    let account = chain.blockchain.get_account(who.address()).expect("the sender exists");
    account.state_init().expect("a state init").code().expect("code").repr_hash()
}

/// An account whose birth code nothing admits cannot obtain validator authority, however
/// correct everything else about its request is.
#[test]
fn a_stake_from_an_unadmitted_controller_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-unadmitted", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(25);

    // A policy that admits some other code: the sender's is well formed and unlisted.
    set_policy(&mut chain, &[chain_block::UInt256::from_slice(&[0x11; 32])]);
    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_CODE_NOT_ADMITTED),
        "an account nothing admits obtained validator authority"
    );
    assert_eq!(pq_member_key_id(&chain, &treasury), None, "the refused stake registered anyway");

    // No policy at all admits nobody, rather than everybody.
    let mut config = chain.blockchain.config_params().clone();
    config
        .config_params
        .remove(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(47u32.to_be_bytes().to_vec(), 32)
                    .expect("a key"),
            )
            .expect("a key slice"),
        )
        .expect("remove the policy");
    chain.blockchain.set_config(config).expect("the configuration is replaced");
    let result = pq_stake(&mut chain, &treasury, &validator, election, 2, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_NO_POLICY),
        "with no policy installed the elector admitted a controller"
    );
}

/// A proof that does not reconstruct the sender's own address proves nothing about it.
#[test]
fn a_stake_carrying_another_accounts_proof_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-foreign-proof", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let other = chain.blockchain.treasury("pq-foreign-proof-other", TOS).expect("an account");
    let validator = PqValidator::new(26);

    let global_id = match chain.blockchain.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        _ => panic!("the chain states no network id"),
    };
    let validator_id =
        chain_block::UInt256::from_slice(&treasury.address().address().get_bytestring(0));
    let preimage = pq_stake_preimage(
        global_id,
        election,
        0x10000,
        &validator_id,
        &validator.key_id(),
        &validator.adnl,
    );
    let signature = validator.sign(&preimage);
    let foreign = controller_proof(&chain, &other);
    let result = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(1, &validator, election, 0x10000, &signature, Some(foreign))),
        ))
        .expect("the stake is delivered");
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_PROOF_MISMATCH),
        "a proof of another account admitted this one"
    );

    // And a first registration with no proof at all says so, rather than being admitted.
    let bare = chain
        .blockchain
        .send_message(treasury.build_message(
            &chain.elector,
            11_000 * TOS,
            true,
            Some(pq_stake_body(2, &validator, election, 0x10000, &signature, None)),
        ))
        .expect("the stake is delivered");
    assert_eq!(
        reply(&bare),
        (STAKE_RETURNED, REASON_PROOF_MISSING),
        "a first registration without a proof was admitted"
    );
}

/// Retiring a controller code stops the controllers already using it, not only new ones.
#[test]
fn retiring_a_controller_code_stops_the_members_that_used_it() {
    let (mut chain, treasury, election) = open_election("pq-retire", 60_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let validator = PqValidator::new(27);
    let rotated = PqValidator::new(28);

    assert_eq!(
        reply(&pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "the fixture needs a registered member"
    );
    let placed = pq_stake_of(&chain, &treasury);

    // The code this member was admitted under is retired.
    set_policy(&mut chain, &[chain_block::UInt256::from_slice(&[0x11; 32])]);

    let topped = pq_stake(&mut chain, &treasury, &validator, election, 2, 12_000 * TOS);
    assert_eq!(
        reply(&topped),
        (STAKE_RETURNED, REASON_CODE_RETIRED),
        "a member whose controller code was retired could still top up"
    );
    let rotation = pq_stake(&mut chain, &treasury, &rotated, election, 3, 12_000 * TOS);
    assert_eq!(
        reply(&rotation),
        (STAKE_RETURNED, REASON_CODE_RETIRED),
        "a member whose controller code was retired could still rotate its key"
    );

    assert_eq!(pq_stake_of(&chain, &treasury), placed, "a refused action changed the member");
    assert_eq!(
        pq_member_key_id(&chain, &treasury),
        Some(validator.key_id()),
        "a refused rotation moved the member off its key"
    );

    // Admitting it again restores what it could do.
    let code = sender_code_hash(&chain, &treasury);
    set_policy(&mut chain, &[code]);
    assert_eq!(
        reply(&pq_stake(&mut chain, &treasury, &validator, election, 4, 12_000 * TOS)),
        (STAKE_ACCEPTED, 0),
        "re-admitting the code did not restore the member"
    );
}

#[test]
fn a_post_quantum_stake_without_a_transport_address_is_returned() {
    let (mut chain, treasury, election) = open_election("pq-validator-f", 40_000 * TOS);
    raise_to_post_quantum_version(&mut chain);
    let mut validator = PqValidator::new(7);
    validator.adnl = [0u8; 32];

    let result = pq_stake(&mut chain, &treasury, &validator, election, 1, 11_000 * TOS);
    assert_eq!(
        reply(&result),
        (STAKE_RETURNED, REASON_NO_ADNL),
        "a validator registered without a transport address, so nothing could reach it"
    );
}
