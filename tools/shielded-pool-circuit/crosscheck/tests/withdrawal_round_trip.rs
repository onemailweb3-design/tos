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
//! Nothing in the cascade is arranged. The pool sends the payout because its
//! own handler decided to; the destination fails because it throws; the bounce
//! is the executor's; and the pool recovers because it authenticated the
//! record that came back.

mod support;

use shielded_pool_circuit_crosscheck::pool::{DENOMINATION, WITHDRAWAL_FEE};
use support::{Withdrawal, ACCEPTER, REFUSER};

fn withdraw_to(name: &'static str, source: &'static str) -> support::Outcome {
    support::run(&Withdrawal {
        denominations: &[DENOMINATION],
        amount: DENOMINATION,
        destination_name: name,
        destination_source: source,
        age: None,
        before_transact: Default::default(),
    })
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
        "a successful withdrawal: {} gas; withdrew {DENOMINATION} and paid {WITHDRAWAL_FEE} \
         in fees; the bounce returned {recovered}",
        outcome.gas
    );

    /// Section 14.1. The recovery runs under this, bought by an ACCEPT that
    /// the withdrawal fee already paid for.
    const BOUNCE_GAS_CEILING: i64 = 290_000;
    assert_eq!(outcome.recovery_exit, 0, "the recovery itself failed");
    eprintln!(
        "the recovery: {} gas, {}% of the {BOUNCE_GAS_CEILING} bounce ceiling",
        outcome.recovery_gas,
        outcome.recovery_gas * 100 / BOUNCE_GAS_CEILING
    );
    assert!(
        outcome.recovery_gas < BOUNCE_GAS_CEILING,
        "the recovery uses {} gas and does not fit its own ceiling",
        outcome.recovery_gas
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
    eprintln!("a withdrawal that was taken: {} gas", outcome.gas);
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

/// What the chain actually stores for one private transaction.
///
/// Section 19 asks nothing about this, but every proof-system comparison
/// does: a proof is only large or small next to the message it travels in.
#[test]
fn the_size_of_one_private_transaction() {
    let outcome = withdraw_to("size_refuser", REFUSER);
    eprintln!("one transact body: {} bytes", outcome.body_bytes);
    assert!(outcome.body_bytes > 0, "the body weighed nothing");
}
