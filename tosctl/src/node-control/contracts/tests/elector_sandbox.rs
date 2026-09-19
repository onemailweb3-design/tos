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
