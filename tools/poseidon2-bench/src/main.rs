/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! B1: what POSEIDON2_PERM8 and POSEIDON2_HASH7 should cost.
//!
//! Gas is a relative quantity. An absolute time for one instruction says
//! nothing on its own, so this prices the two new instructions against
//! instructions whose gas price is already fixed -- and fixed, in the case of
//! the BLS ones, by measurement on the same curve over the same field with the
//! same library. If Poseidon2 takes half as long as a G1 addition on this
//! machine, then at a G1 addition's 3,900 gas it is worth about 1,950.
//!
//! Each instruction is run in a real VM inside a loop, and an identical loop
//! that does everything except the instruction is subtracted. What is left is
//! the instruction, including the stack and field-element handling a contract
//! actually pays for -- not just the primitive underneath it.
//!
//! **This measures this host.** The profile requires the target CPU, so what
//! comes out here is a candidate and a method, not a frozen tariff.

use std::time::{Duration, Instant};

use chain_block::{tos_method_id, Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 17;

/// An instruction, and the price it already carries if it has one.
struct Subject {
    name: &'static str,
    // The gas price in `crypto/vm/vm.h`, or `None` for the ones being priced.
    price: Option<i64>,
    // FunC for one repetition. It must leave the stack as it found it.
    body: &'static str,
    // The same shape without the instruction, so the loop and the operand
    // building are subtracted rather than attributed to the instruction.
    baseline: &'static str,
}

/// The subjects. Each `body` builds its operands and runs the instruction; the
/// matching `baseline` builds the same operands and does not.
///
/// Operand building is deliberately inside both, because an instruction that
/// needs eight field elements off the stack is not comparable to one that
/// needs two unless the difference is subtracted the same way for both.
fn subjects() -> Vec<Subject> {
    vec![
        Subject {
            name: "POSEIDON2_PERM8",
            price: None,
            body: "p_perm8(a, a, a, a, a, a, a, a)",
            baseline: "p_eight(a, a, a, a, a, a, a, a)",
        },
        Subject {
            name: "POSEIDON2_HASH7",
            price: None,
            body: "p_hash7(a, a, a, a, a, a, a, a)",
            baseline: "p_eight_drop7(a, a, a, a, a, a, a, a)",
        },
        Subject {
            name: "BLS_G1_ADD",
            price: Some(3900),
            body: "p_g1_add(g1, g1)",
            baseline: "p_two_slices(g1, g1)",
        },
        Subject {
            name: "BLS_G1_NEG",
            price: Some(750),
            body: "p_g1_neg(g1)",
            baseline: "p_one_slice(g1)",
        },
        Subject {
            name: "BLS_G1_INGROUP",
            price: Some(2950),
            body: "p_g1_in_group(g1)",
            baseline: "p_one_slice(g1)",
        },
        // CHKSIGNU was here, and was dropped. It was the one anchor whose
        // cost is not point decompression, which is exactly why it was
        // wanted -- but the two VMs do not do the same work for it. Given
        // the same invalid signature they charge the same gas and take
        // 67 ns and 32,441 ns respectively: the C++ one rejects it before
        // verifying and the Rust one does not. An anchor the two
        // implementations disagree about by four hundred times cannot
        // calibrate either of them.
        //
        // Restoring it means passing a signature that actually verifies, so
        // that both do the whole job. That is worth doing; it is not worth
        // doing by pretending the current one measures verification.
        Subject {
            name: "BLS_G2_ADD",
            price: Some(6100),
            body: "p_g2_add(g2, g2)",
            baseline: "p_two_slices(g2, g2)",
        },
    ]
}

/// The probe.
///
/// Two rules shape it, and the first was learned the hard way: a FunC call
/// whose results are unused and whose function is not `impure` is *removed*,
/// so an uninstrumented benchmark measures an empty loop and reports that the
/// instruction is free. Everything here is `impure`, and every result is fed
/// back into the next iteration so that nothing can be dropped or hoisted.
fn probe_source() -> String {
    let mut source = String::from(
        r#"
;; The instructions under test, and same-arity functions that do everything
;; except the instruction. All impure: a call whose result is unused is
;; otherwise eliminated, and the benchmark would time an empty loop.
int p_perm8(int a, int b, int c, int d, int e, int f, int g, int h) impure
  asm "POSEIDON2_PERM8 7 BLKDROP";
int p_eight(int a, int b, int c, int d, int e, int f, int g, int h) impure
  asm "7 BLKDROP";
int p_hash7(int d0, int a, int b, int c, int d, int e, int f, int g) impure
  asm "POSEIDON2_HASH7";
int p_eight_drop7(int d0, int a, int b, int c, int d, int e, int f, int g) impure
  asm "7 BLKDROP";

;; The BLS subjects return an integer taken from the resulting point, so the
;; value feeds the loop; the baseline takes the same integer from an operand,
;; so the extraction is paid for on both sides and cancels.
int p_g1_add(slice a, slice b) impure asm "BLS_G1_ADD 64 PLDU";
int p_g2_add(slice a, slice b) impure asm "BLS_G2_ADD 64 PLDU";
int p_two_slices(slice a, slice b) impure asm "DROP 64 PLDU";
int p_g1_neg(slice a) impure asm "BLS_G1_NEG 64 PLDU";
int p_g1_in_group(slice a) impure asm "BLS_G1_INGROUP";
int p_one_slice(slice a) impure asm "64 PLDU";

;; Ed25519 verification: a fourth anchor whose cost is not decompression, so
;; agreement with the BLS ones is evidence rather than a shared artefact. The
;; signature does not verify, which costs the same work: the check fails at the
;; end, not at the start.
int p_chksignu(int hash, slice signature, int key) impure asm "CHKSIGNU";
int p_chksignu_base(int hash, slice signature, int key) impure asm "2 BLKDROP";

;; A real point on each curve rather than bytes that happen to decode.
slice g1() asm "BLS_G1_ZERO";
slice g2() asm "BLS_G2_ZERO";

"#,
    );
    for subject in subjects() {
        for (suffix, code) in [("", subject.body), ("_base", subject.baseline)] {
            source.push_str(&format!(
                r#"
int {name}{suffix}(int rounds) method_id {{
  int a = 12345678901234567890;
  slice g1 = g1();
  slice g2 = g2();
  slice sig = begin_cell().store_uint(0, 256).store_uint(0, 256).end_cell().begin_parse();
  int i = 0;
  while (i < rounds) {{
    a = {code};
    i = i + 1;
  }}
  ;; Returned so the accumulator is observable and the loop cannot be
  ;; optimised away as dead.
  return a;
}}
"#,
                name = subject.name.to_lowercase(),
                suffix = suffix,
                code = code,
            ));
        }
    }
    source.push_str("() recv_internal(int a, cell b, slice c) impure { }\n");
    source.push_str("() recv_external(slice a) impure { }\n");
    source
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rounds: u32 =
        std::env::args().nth(1).map(|value| value.parse()).transpose()?.unwrap_or(2_000);
    let repeats: usize =
        std::env::args().nth(2).map(|value| value.parse()).transpose()?.unwrap_or(7);
    // The tariff the VMs currently carry, so the report can say whether it is
    // still inside the bracket. Passed in rather than read from the VM: a tool
    // that reads the number it is judging cannot judge it.
    let current_price: u32 =
        std::env::args().nth(3).map(|value| value.parse()).transpose()?.unwrap_or(3_500);

    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
    bc.set_workchain(0);
    let payer = bc.treasury("bench", 1_000 * TOS)?;
    let path = std::env::temp_dir().join("tos_poseidon2_bench.fc");
    std::fs::write(&path, probe_source())?;
    let stdlib = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crypto/smartcont/stdlib.fc");
    let code = compile_func(&[stdlib, path])?;
    let si = StateInit::with_code_and_data(code, Cell::default());
    let hash = si.write_to_new_cell().and_then(|builder| builder.into_cell())?.hash(0);
    let addr = MsgAddressInt::with_params(0, hash)?;
    bc.send_message(
        MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build(),
    )?
    .expect_success();

    // The compiled code, run in a VM this benchmark sets up. The sandbox's
    // get-method helper caps gas at 1,000,000, which at three thousand gas an
    // instruction would hold about three hundred rounds -- far too few to time
    // a nanosecond-scale operation through. This is the same setup with a
    // limit that does not bind.
    let account = bc.get_account(&addr).ok_or("the probe account")?;
    let probe_code = account.get_code().ok_or("the probe code")?;
    let probe_data = account.get_data().unwrap_or_default();

    // The same compiled probe, written out so the C++ VM can run the exact
    // same bytecode. Comparing two implementations on two different programs
    // would compare the programs.
    if let Ok(path) = std::env::var("POSEIDON2_BENCH_DUMP_CODE") {
        let boc = chain_block::write_boc(&probe_code)?;
        std::fs::write(&path, &boc)?;
        eprintln!("wrote the probe code to {path} ({} bytes)", boc.len());
        for subject in subjects() {
            eprintln!(
                "  method {:<20} id {}",
                subject.name.to_lowercase(),
                tos_method_id(&subject.name.to_lowercase())
            );
            eprintln!(
                "  method {:<20} id {}",
                format!("{}_base", subject.name.to_lowercase()),
                tos_method_id(&format!("{}_base", subject.name.to_lowercase()))
            );
        }
    }

    // One execution of one method.
    let once = |method: &str| -> Result<(Duration, i64, i32), Box<dyn std::error::Error>> {
        let method_id = tos_vm::stack::integer::IntegerData::from_u32(tos_method_id(method));
        let mut storage = vec![tos_vm::stack::StackItem::int(
            tos_vm::stack::integer::IntegerData::from_u32(rounds),
        )];
        storage.push(tos_vm::stack::StackItem::int(method_id));
        let stack = tos_vm::stack::Stack::with_storage(storage);
        let mut ctrls = tos_vm::stack::savelist::SaveList::new();
        let info = tos_vm::SmartContractInfo::default();
        ctrls.put(7, info.as_temp_data_item())?;
        ctrls.put(4, tos_vm::stack::StackItem::Cell(probe_data.clone()))?;
        let gas =
            tos_vm::executor::gas::gas_state::Gas::new(i64::MAX / 4, 0, i64::MAX / 4, i64::MAX / 4);
        let mut vm = tos_vm::executor::Engine::with_capabilities(u64::MAX).setup_checked(
            probe_code.clone(),
            ctrls,
            stack,
            gas,
            vec![],
        )?;
        vm.set_block_version(ACTIVE_VERSION);
        let started = Instant::now();
        let result = vm.execute();
        let elapsed = started.elapsed();
        let exit = match result {
            Ok(code) => code,
            Err(error) => tos_vm::error::tvm_exception_or_custom_code(&error),
        };
        Ok((elapsed, vm.gas_used(), exit))
    };

    // One subject, measured against its own baseline.
    //
    // The two are measured back to back inside each repeat rather than in
    // separate passes. A shared machine drifts, and a drift that lands on one
    // pass and not the other is subtracted straight into the answer -- which
    // is how a first version of this reported that an instruction took
    // negative time.
    //
    // The per-repeat difference is then minimised rather than averaged: the
    // work takes what it takes, and every source of interference makes a
    // sample longer.
    let measure = |method: &str| -> Result<(f64, i64), Box<dyn std::error::Error>> {
        let base = format!("{method}_base");
        let _ = once(method)?;
        let _ = once(&base)?;
        let mut best = f64::MAX;
        let mut gas_per_op = 0;
        for _ in 0..repeats {
            let (with, with_gas, with_exit) = once(method)?;
            let (without, without_gas, without_exit) = once(&base)?;
            if with_exit != 0 || without_exit != 0 {
                return Err(format!("{method} exited {with_exit}/{without_exit}").into());
            }
            let per_op = (with.as_nanos() as f64 - without.as_nanos() as f64) / f64::from(rounds);
            best = best.min(per_op);
            gas_per_op = (with_gas - without_gas) / i64::from(rounds);
        }
        Ok((best, gas_per_op))
    };

    println!("host: {rounds} rounds, best of {repeats}\n");
    println!(
        "{:<18}{:>10}{:>10}{:>12}{:>14}",
        "instruction", "ns/op", "gas/op", "known gas", "ns per gas"
    );

    let mut anchors: Vec<(&str, f64, i64)> = Vec::new();
    let mut unpriced: Vec<(&str, f64)> = Vec::new();
    for subject in subjects() {
        let name = subject.name.to_lowercase();
        // The gas difference confirms the instruction ran at all, which is
        // the failure this benchmark had first: a call whose result is unused
        // and which is not impure is removed, and the loop times nothing.
        let (per_op, gas_per_op) = measure(&name)?;
        match subject.price {
            Some(price) => {
                println!(
                    "{:<18}{:>10.1}{:>10}{:>12}{:>14.4}",
                    subject.name,
                    per_op,
                    gas_per_op,
                    price,
                    per_op / price as f64
                );
                anchors.push((subject.name, per_op, price));
            }
            None => {
                println!(
                    "{:<18}{:>10.1}{:>10}{:>12}{:>14}",
                    subject.name, per_op, gas_per_op, "?", "?"
                );
                unpriced.push((subject.name, per_op));
            }
        }
    }

    // An anchor whose own price is far from its own cost cannot price
    // anything else. The spread among the anchors is the precision available:
    // no derived number can be tighter than the table it is derived from.
    let ns_per_gas: Vec<f64> = anchors.iter().map(|(_, ns, price)| ns / *price as f64).collect();
    let tightest = ns_per_gas.iter().cloned().fold(f64::MAX, f64::min);
    let loosest = ns_per_gas.iter().cloned().fold(0.0, f64::max);
    let usable: Vec<&(&str, f64, i64)> = anchors
        .iter()
        // An anchor more than an order of magnitude off the others is not
        // measuring the same thing. BLS_G1_NEG is the case in point: it flips
        // a sign bit on compressed bytes and never decompresses, so its price
        // was not set by what it costs.
        .filter(|(_, ns, price)| ns / *price as f64 > loosest / 10.0)
        .collect();

    println!("\nimplied price, by anchor:");
    println!("{:<18}{:<18}{:>12}{:>10}", "instruction", "against", "implied gas", "used");
    for (name, per_op) in &unpriced {
        for (anchor, anchor_ns, anchor_price) in &anchors {
            let implied = per_op / anchor_ns * (*anchor_price as f64);
            let used = usable.iter().any(|(candidate, _, _)| candidate == anchor);
            println!(
                "{name:<18}{anchor:<18}{implied:>12.0}{:>10}",
                if used { "yes" } else { "no" }
            );
        }
    }

    let used_ns_per_gas: Vec<f64> =
        usable.iter().map(|(_, ns, price)| ns / *price as f64).collect();
    let used_low = used_ns_per_gas.iter().cloned().fold(f64::MAX, f64::min);
    let used_high = used_ns_per_gas.iter().cloned().fold(0.0, f64::max);
    println!(
        "\nthe anchors used agree with each other only to within {:.2}x ({:.1} to {:.1} ns per gas),",
        used_high / used_low,
        used_low,
        used_high
    );
    println!("so nothing derived from them is more precise than that.");
    println!(
        "the excluded anchor sits at {tightest:.2} ns per gas, {:.0}x off the rest.\n",
        used_low / tightest
    );

    println!("{:<18}{:>14}{:>14}{:>10}  {}", "instruction", "low", "high", "current", "verdict");
    for (name, per_op) in &unpriced {
        let implied: Vec<f64> = usable
            .iter()
            .map(|(_, anchor_ns, anchor_price)| per_op / anchor_ns * (*anchor_price as f64))
            .collect();
        let low = implied.iter().cloned().fold(f64::MAX, f64::min);
        let high = implied.iter().cloned().fold(0.0, f64::max);
        // Above the bracket is the safe side and is where a rounded-up tariff
        // belongs; below it is the one that matters, because underpricing an
        // instruction is a denial-of-service surface.
        let current = f64::from(current_price);
        let verdict = if current < low {
            "BELOW the bracket"
        } else if current > high {
            "above, rounded up"
        } else {
            "inside"
        };
        println!("{name:<18}{low:>14.0}{high:>14.0}{current_price:>10}  {verdict}");
    }
    println!("\nThis is one host and one VM. The profile requires the target CPU,");
    println!("and a tariff must cover the slower of the two implementations, so");
    println!("this is a candidate and a method rather than a number to freeze.");
    Ok(())
}
