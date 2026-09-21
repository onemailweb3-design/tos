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

;; --- what the dictionary itself costs -------------------------------------
;; The frontier's key space is exactly 0..83, dense and known at compile time,
;; yet it is stored in a sparse HashmapE. These three price the operations an
;; append is made of, so the question "is a second instruction needed, or is
;; the container wrong" can be answered with numbers.

int f_reads(cell frontier, int rounds) method_id {
  int acc = 0;
  int i = 0;
  while (i < rounds) {
    acc = acc + frontier_get(frontier, i % tree_depth(), i % tree_arity());
    i = i + 1;
  }
  return acc;
}

cell f_writes(cell frontier, int rounds) method_id {
  int i = 0;
  while (i < rounds) {
    frontier = frontier_set(frontier, i % tree_depth(), i % tree_arity(), 0x1234 + i);
    i = i + 1;
  }
  return frontier;
}

;; The same eighty-four values as a flat chain of cells, three to a cell, read
;; by walking rather than by key. This is what a dense container costs.
cell f_flat_build() method_id {
  cell chain = begin_cell().end_cell();
  int i = 0;
  while (i < 28) {
    chain = begin_cell()
      .store_uint(0x1234 + i * 3, 256)
      .store_uint(0x1235 + i * 3, 256)
      .store_uint(0x1236 + i * 3, 256)
      .store_ref(chain)
      .end_cell();
    i = i + 1;
  }
  return chain;
}

int f_flat_reads(cell chain, int rounds) method_id {
  int acc = 0;
  int i = 0;
  while (i < rounds) {
    slice s = chain.begin_parse();
    acc = acc + s~load_uint(256);
    i = i + 1;
  }
  return acc;
}


;; --- the same fold against a flat, level-ordered layout ---------------------
;; A level is three cells because a cell holds 1023 bits and a field element
;; is 256: values 0-2, then 3-5, then 6. The level cells carry a reference to
;; the next level, so the whole store is walked in the order an append walks
;; it and nothing is addressed by key.
;;
;; This is a prototype for measurement. It is not the contract's layout.

(int, int, int, int, int, int, int, cell) flat_read(cell node, int last) inline_ref {
  slice a = node.begin_parse();
  int v0 = a~load_uint(256);
  int v1 = a~load_uint(256);
  int v2 = a~load_uint(256);
  cell b = a~load_ref();
  cell next = last ? null() : a~load_ref();
  slice bs = b.begin_parse();
  int v3 = bs~load_uint(256);
  int v4 = bs~load_uint(256);
  int v5 = bs~load_uint(256);
  slice cs = bs~load_ref().begin_parse();
  int v6 = cs~load_uint(256);
  return (v0, v1, v2, v3, v4, v5, v6, next);
}

cell flat_build_level(tuple v, cell next, int last) inline_ref {
  cell c = begin_cell().store_uint(v.at(6), 256).end_cell();
  cell b = begin_cell()
    .store_uint(v.at(3), 256).store_uint(v.at(4), 256).store_uint(v.at(5), 256)
    .store_ref(c).end_cell();
  builder a = begin_cell()
    .store_uint(v.at(0), 256).store_uint(v.at(1), 256).store_uint(v.at(2), 256)
    .store_ref(b);
  ifnot (last) { a = a.store_ref(next); }
  return a.end_cell();
}

;; Level `l` of a pool at `index`, filled the way the dictionary version fills
;; it: slots up to that level's digit hold values, the rest are zero.
cell flat_fill(int index) method_id {
  cell next = null();
  int level = tree_depth() - 1;
  while (level >= 0) {
    int stride = 1;
    int i = 0;
    while (i < level) { stride = stride * tree_arity(); i = i + 1; }
    int digit = (index / stride) % tree_arity();
    tuple v = empty_tuple();
    int slot = 0;
    while (slot < tree_arity()) {
      v = v.tpush(slot <= digit ? 0x51ed0000 + (level * 7) + slot : 0);
      slot = slot + 1;
    }
    next = flat_build_level(v, next, level == (tree_depth() - 1));
    level = level - 1;
  }
  return next;
}

;; The measured call: the same twelve-level fold, reading and rebuilding the
;; flat store instead of a dictionary.
(cell, int) flat_append(cell frontier, int index, int leaf) impure {
  ;; Down: read every level, place the carry, hash, and keep the new values.
  tuple levels = empty_tuple();
  int carry = leaf;
  int stride = 1;
  int level = 0;
  cell node = frontier;
  while (level < tree_depth()) {
    (int v0, int v1, int v2, int v3, int v4, int v5, int v6, cell next) =
      flat_read(node, level == (tree_depth() - 1));
    int digit = (index / stride) % tree_arity();
    int empty = empty_root_at(level);
    int c0 = digit == 0 ? carry : (digit >= 0 ? v0 : empty);
    int c1 = digit == 1 ? carry : (digit >= 1 ? v1 : empty);
    int c2 = digit == 2 ? carry : (digit >= 2 ? v2 : empty);
    int c3 = digit == 3 ? carry : (digit >= 3 ? v3 : empty);
    int c4 = digit == 4 ? carry : (digit >= 4 ? v4 : empty);
    int c5 = digit == 5 ? carry : (digit >= 5 ? v5 : empty);
    int c6 = digit == 6 ? carry : (digit >= 6 ? v6 : empty);
    tuple v = empty_tuple();
    v = v.tpush(c0); v = v.tpush(c1); v = v.tpush(c2); v = v.tpush(c3);
    v = v.tpush(c4); v = v.tpush(c5); v = v.tpush(c6);
    levels = levels.tpush(v);
    carry = commit_node(c0, c1, c2, c3, c4, c5, c6);
    stride = stride * tree_arity();
    node = next;
    level = level + 1;
  }
  ;; Up: the store is rebuilt from the deepest level, because each level holds
  ;; a reference to the next.
  cell rebuilt = null();
  level = tree_depth() - 1;
  while (level >= 0) {
    rebuilt = flat_build_level(levels.at(level), rebuilt, level == (tree_depth() - 1));
    level = level - 1;
  }
  return (rebuilt, carry);
}

(cell, int) f_flat_append(cell frontier, int index, int leaf) method_id {
  return flat_append(frontier, index, leaf);
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

    /// The gas `rounds` dictionary reads cost against a frontier of that age.
    pub fn dict_read_gas(&self, index: u64, rounds: u64) -> Result<i64> {
        let frontier = self.fill(index)?;
        let (_, gas) = self.call(
            "f_reads",
            vec![StackItem::cell(frontier), Self::integer(&rounds.to_string())?],
        )?;
        Ok(gas)
    }

    /// The same for writes.
    pub fn dict_write_gas(&self, index: u64, rounds: u64) -> Result<i64> {
        let frontier = self.fill(index)?;
        let (_, gas) = self.call(
            "f_writes",
            vec![StackItem::cell(frontier), Self::integer(&rounds.to_string())?],
        )?;
        Ok(gas)
    }

    /// What the same values cost to read from a flat cell chain.
    pub fn flat_read_gas(&self, rounds: u64) -> Result<i64> {
        let (stack, _) = self.call("f_flat_build", vec![])?;
        let chain = stack
            .last()
            .ok_or_else(|| CrossCheckError::Vm("no chain".to_string()))?
            .as_cell()
            .map(Clone::clone)
            .map_err(|error| CrossCheckError::Vm(format!("chain: {error}")))?;
        let (_, gas) = self.call(
            "f_flat_reads",
            vec![StackItem::cell(chain), Self::integer(&rounds.to_string())?],
        )?;
        Ok(gas)
    }

    /// The flat store for a pool at `index`.
    pub fn flat_fill(&self, index: u64) -> Result<Cell> {
        let (stack, _) = self.call("flat_fill", vec![Self::integer(&index.to_string())?])?;
        stack
            .last()
            .ok_or_else(|| CrossCheckError::Vm("no store".to_string()))?
            .as_cell()
            .map(Clone::clone)
            .map_err(|error| CrossCheckError::Vm(format!("store: {error}")))
    }

    /// The gas the same fold costs against the flat store.
    pub fn flat_append_gas(&self, index: u64) -> Result<i64> {
        let frontier = self.flat_fill(index)?;
        let (_, gas) = self.call(
            "f_flat_append",
            vec![
                StackItem::cell(frontier),
                Self::integer(&index.to_string())?,
                Self::integer("12345678901234567890")?,
            ],
        )?;
        Ok(gas)
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
