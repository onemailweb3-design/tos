/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What one commitment-tree append costs as the tree fills up.
//!
//! `frontier_append` hashes a fixed twelve nodes whatever the index, but it
//! reads `digit + 1` frontier slots per level, and the digits come from the
//! leaf index in base seven. An append near genesis therefore reads the
//! smallest number of slots the function can ever read, and every gas figure
//! measured against a fresh pool understates a mature one.
//!
//! This probe calls the function directly so the growth can be measured
//! without minting two billion notes: `fill` builds the frontier store a pool
//! at `index` would hold, and `append_gas` reports what appending there costs.

use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};
use tos_vm::stack::integer::IntegerData;
use tos_vm::stack::StackItem;

use crate::{library_dir, stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

const PROBE: &str = r#"
;; The frontier store a pool that has appended `index` leaves would hold: at
;; every level, the slots below and including that level's digit are occupied.
;; The values are arbitrary because only their presence costs anything; what
;; they are changes no dictionary work.
cell f_fill(int index) method_id {
  cell frontier = new_dict();
  int stride = 1;
  int level = 0;
  while (level < tree_depth()) {
    int digit = (index / stride) % tree_arity();
    int position = 0;
    while (position <= digit) {
      frontier = frontier_set(frontier, level, position, 0x51ed0000 + (level * 7) + position);
      position = position + 1;
    }
    stride = stride * tree_arity();
    level = level + 1;
  }
  return frontier;
}

;; The measured call. The returned root is discarded by the caller, but it is
;; returned rather than dropped so no part of the append can be eliminated.
(cell, int) f_append(cell frontier, int index, int leaf) method_id {
  return frontier_append(frontier, index, leaf);
}

;; The digit sum, which is what decides how many slots the append reads.
int f_digit_sum(int index) method_id {
  int total = 0;
  int stride = 1;
  int level = 0;
  while (level < tree_depth()) {
    total = total + ((index / stride) % tree_arity());
    stride = stride * tree_arity();
    level = level + 1;
  }
  return total;
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

pub struct FrontierProbe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl FrontierProbe {
    pub fn deploy() -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("frontier_deployer", 1_000 * TOS)?;
        let library = library_dir();
        let probe_path = std::env::temp_dir().join("tos_shielded_frontier_probe.fc");
        std::fs::write(&probe_path, PROBE)
            .map_err(|error| CrossCheckError::Sandbox(format!("write probe: {error}")))?;
        let code = compile_func(&[
            stdlib_path(),
            library.join("domains.fc"),
            library.join("empty-roots.fc"),
            library.join("notes.fc"),
            library.join("tree.fc"),
            probe_path,
        ])?;
        let si = StateInit::with_code_and_data(code, Cell::default());
        let addr_hash = si
            .write_to_new_cell()
            .and_then(|builder| builder.into_cell())
            .map_err(|error| CrossCheckError::Sandbox(format!("state init: {error}")))?
            .hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash)
            .map_err(|error| CrossCheckError::Sandbox(format!("address: {error}")))?;
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )?
        .expect_success();
        Ok(Self { bc, addr })
    }

    fn integer(value: &str) -> Result<StackItem> {
        IntegerData::from_str_radix(value, 10)
            .map(StackItem::integer)
            .map_err(|error| CrossCheckError::Fixture(format!("{value}: {error}")))
    }

    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<(Vec<StackItem>, i64)> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!("{method} exited {}", result.exit_code)));
        }
        Ok((result.stack, result.gas_used))
    }

    /// The frontier store of a pool holding `index` notes.
    pub fn fill(&self, index: u64) -> Result<Cell> {
        let (stack, _) = self.call("f_fill", vec![Self::integer(&index.to_string())?])?;
        let top = stack.last().ok_or_else(|| CrossCheckError::Vm("no frontier".to_string()))?;
        top.as_cell()
            .map(Clone::clone)
            .map_err(|error| CrossCheckError::Vm(format!("frontier: {error}")))
    }

    /// The digit sum of `index` in base seven, which is the count the append's
    /// dictionary work is proportional to.
    pub fn digit_sum(&self, index: u64) -> Result<u64> {
        let (stack, _) = self.call("f_digit_sum", vec![Self::integer(&index.to_string())?])?;
        let top = stack.last().ok_or_else(|| CrossCheckError::Vm("no sum".to_string()))?;
        top.as_integer()
            .map_err(|error| CrossCheckError::Vm(format!("sum: {error}")))?
            .to_string()
            .parse()
            .map_err(|error| CrossCheckError::Vm(format!("sum: {error}")))
    }

    /// The gas one append at `index` costs against that pool's frontier.
    pub fn append_gas(&self, index: u64) -> Result<i64> {
        let frontier = self.fill(index)?;
        let (_, gas) = self.call(
            "f_append",
            vec![
                StackItem::cell(frontier),
                Self::integer(&index.to_string())?,
                Self::integer("12345678901234567890")?,
            ],
        )?;
        Ok(gas)
    }
}
