/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sections 4 and 5 of the V1 implementation profile, run in the VM: the note
//! commitments and nullifiers, and the 7-ary depth-12 commitment tree with its
//! canonical frontier store.
//!
//! Two of the checks here are worth more than the rest. The frontier is an
//! incremental algorithm; the test also rebuilds the whole tree from every leaf
//! and requires the two to agree, which is a genuinely different computation
//! rather than the same one written twice. And the empty-subtree ladder is
//! generated rather than recomputed on chain, so the test recomputes it from
//! the permutation and requires the generated table to match.
//!
//! What this cannot establish: that these formulas are the ones the circuit
//! will enforce. The FunC here and the reference below were both written from
//! section 4, so a misreading of the profile would be reproduced in both. The
//! cross-check that settles it is the circuit (WP-C), which does not exist yet.

use std::collections::BTreeMap;

use chain_block::poseidon2::permute;
use chain_block::poseidon2_kat::{DOMAINS, EMPTY_ROOTS};
use chain_block::{
    BuilderData, Cell, HashmapE, HashmapType, IBitstring, MsgAddressInt, Serializable, StateInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const DEPTH: usize = 12;
const ARITY: usize = 7;

type Field = [u8; 32];

// ---------------------------------------------------------------------------
// Reference: section 4 and section 5 written out directly.

fn domain(label: &str) -> Field {
    DOMAINS
        .iter()
        .find(|(name, _)| *name == label)
        .unwrap_or_else(|| panic!("unknown domain label {label}"))
        .1
}

fn h7(domain: Field, args: [Field; 7]) -> Field {
    let mut state = [[0u8; 32]; 8];
    state[0] = domain;
    state[1..].copy_from_slice(&args);
    permute(&state)[0]
}

fn small(value: u64) -> Field {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

const ZERO: Field = [0u8; 32];

fn owner_commitment(
    owner_nf_key_hash: Field,
    pq_auth_key_hash: Field,
    note_secret: Field,
) -> Field {
    h7(
        domain("OWNER-COMMITMENT"),
        [owner_nf_key_hash, pq_auth_key_hash, note_secret, ZERO, ZERO, ZERO, ZERO],
    )
}

fn note_body_commitment(owner: Field, amount: Field, output_data_hash: Field) -> Field {
    h7(domain("NOTE-BODY"), [owner, amount, output_data_hash, ZERO, ZERO, ZERO, ZERO])
}

fn note_commitment(body: Field, leaf_index: Field) -> Field {
    h7(domain("NOTE-COMMITMENT"), [body, leaf_index, ZERO, ZERO, ZERO, ZERO, ZERO])
}

fn nullifier(body: Field, owner_nf_key: Field) -> Field {
    h7(domain("NULLIFIER"), [body, owner_nf_key, ZERO, ZERO, ZERO, ZERO, ZERO])
}

fn phantom_nullifier(intent_nonce: Field, input_slot: Field, pq_auth_key_hash: Field) -> Field {
    h7(
        domain("PHANTOM-NULLIFIER"),
        [intent_nonce, input_slot, pq_auth_key_hash, ZERO, ZERO, ZERO, ZERO],
    )
}

fn commit_node(children: [Field; 7]) -> Field {
    h7(domain("COMMIT-NODE"), children)
}

/// EMPTY_ROOT[0] = 0, EMPTY_ROOT[level+1] = COMMIT-NODE of seven copies.
fn recomputed_empty_roots() -> Vec<Field> {
    let mut out = vec![ZERO];
    for level in 0..DEPTH {
        out.push(commit_node([out[level]; 7]));
    }
    out
}

/// The whole tree from every leaf, level by level. This shares the hash with
/// the frontier and nothing else: it never looks at a stored frontier slot and
/// never depends on the order the leaves arrived in.
fn naive_root(leaves: &[Field], empty: &[Field]) -> Field {
    let mut level_nodes = leaves.to_vec();
    for level in 0..DEPTH {
        while level_nodes.len() % ARITY != 0 {
            level_nodes.push(empty[level]);
        }
        let mut next = Vec::with_capacity(level_nodes.len() / ARITY);
        for group in level_nodes.chunks(ARITY) {
            let mut children = [ZERO; 7];
            children.copy_from_slice(group);
            next.push(commit_node(children));
        }
        if next.is_empty() {
            next.push(empty[level + 1]);
        }
        level_nodes = next;
    }
    assert_eq!(level_nodes.len(), 1, "the tree did not reduce to a single root");
    level_nodes[0]
}

/// The incremental algorithm of section 5.1, over a plain map so that the
/// contract's dictionary encoding is not part of the reference.
fn reference_append(
    frontier: &mut BTreeMap<(usize, usize), Field>,
    index: u64,
    leaf: Field,
    empty: &[Field],
) -> Field {
    let mut carry = leaf;
    let mut stride = 1u64;
    for level in 0..DEPTH {
        let digit = ((index / stride) % ARITY as u64) as usize;
        if carry == ZERO {
            frontier.remove(&(level, digit));
        } else {
            frontier.insert((level, digit), carry);
        }
        let mut children = [empty[level]; 7];
        for (position, slot) in children.iter_mut().enumerate() {
            if position <= digit {
                *slot = frontier.get(&(level, position)).copied().unwrap_or(ZERO);
            }
        }
        carry = commit_node(children);
        stride *= ARITY as u64;
    }
    carry
}

// ---------------------------------------------------------------------------

fn dec(bytes: &Field) -> String {
    let mut digits = vec![0u8];
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

const PROBE: &str = r#"
int p_owner_commitment(int a, int b, int c) method_id { return owner_commitment(a, b, c); }
int p_note_body(int a, int b, int c) method_id { return note_body_commitment(a, b, c); }
int p_note_commitment(int a, int b) method_id { return note_commitment(a, b); }
int p_nullifier(int a, int b) method_id { return nullifier(a, b); }
int p_phantom(int a, int b, int c) method_id { return phantom_nullifier(a, b, c); }
int p_reduce(int d) method_id { return reduce_to_field(d); }
int p_empty_root(int level) method_id { return empty_root_at(level); }
int p_commit_node(int c0, int c1, int c2, int c3, int c4, int c5, int c6) method_id {
  return commit_node(c0, c1, c2, c3, c4, c5, c6);
}
(cell, int) p_append(cell frontier, int index, int leaf) method_id {
  return frontier_append(frontier, index, leaf);
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        let payer = bc.treasury("deployer", 1_000 * TOS).expect("treasury");
        // Derived from this crate's own location, never from TOS_ROOT: that
        // variable points at the checkout holding the compiler, which in a
        // worktree is a different tree, and this suite would then silently
        // test another checkout's FunC instead of its own.
        let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded");
        let probe_path = std::env::temp_dir().join("tos_shielded_notes_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[
            format!("{library}/domains.fc").into(),
            format!("{library}/empty-roots.fc").into(),
            format!("{library}/notes.fc").into(),
            format!("{library}/tree.fc").into(),
            probe_path,
        ])
        .expect("compile the shielded library (needs build/crypto/func)");
        let mut data = BuilderData::new();
        data.append_u32(0).unwrap();
        let si = StateInit::with_code_and_data(code, data.into_cell().unwrap());
        let addr_hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let addr = MsgAddressInt::with_params(0, addr_hash).unwrap();
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr }
    }

    fn field_args(values: &[Field]) -> Vec<StackItem> {
        values
            .iter()
            .map(|value| {
                StackItem::integer(
                    IntegerData::from_str_radix(&dec(value), 10).expect("argument as integer"),
                )
            })
            .collect()
    }

    fn call_field(&self, method: &str, args: &[Field]) -> Field {
        let result = self
            .bc
            .run_get_method(&self.addr, method, Self::field_args(args))
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
        let text = result
            .stack
            .last()
            .expect("a result")
            .as_integer()
            .unwrap_or_else(|_| panic!("{method}: non-integer"))
            .to_string();
        let value = from_dec(&text);
        // The round trip is the guard, not the length: a 256-bit result that
        // was truncated on the way back would not come back to the same string.
        assert_eq!(dec(&value), text, "{method}: the decimal round trip is not exact");
        value
    }

    /// Returns the updated frontier store and the new root.
    fn append(&self, frontier: Option<Cell>, index: u64, leaf: Field) -> (Option<Cell>, Field) {
        let mut args = vec![match frontier {
            Some(cell) => StackItem::Cell(cell),
            None => StackItem::None,
        }];
        args.push(StackItem::int(index as i64));
        args.extend(Self::field_args(&[leaf]));
        let result =
            self.bc.run_get_method(&self.addr, "p_append", args).expect("p_append should run");
        assert_eq!(result.exit_code, 0, "p_append exited {}", result.exit_code);
        assert_eq!(result.stack.len(), 2, "p_append must return a store and a root");
        let root = from_dec(&result.stack[1].as_integer().expect("root is an integer").to_string());
        let store = result.stack[0].as_cell().ok().cloned();
        (store, root)
    }

    fn append_exit_code(&self, index_bits: &str, leaf: Field) -> i32 {
        let args = vec![
            StackItem::None,
            StackItem::integer(IntegerData::from_str_radix(index_bits, 10).expect("index")),
            Self::field_args(&[leaf]).remove(0),
        ];
        self.bc.run_get_method(&self.addr, "p_append", args).expect("p_append should run").exit_code
    }
}

fn from_dec(text: &str) -> Field {
    let mut out = [0u8; 32];
    for ch in text.bytes() {
        let mut carry = (ch - b'0') as u32;
        for byte in out.iter_mut().rev() {
            let value = (*byte as u32) * 10 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        assert_eq!(carry, 0, "value does not fit in 256 bits: {text}");
    }
    out
}

/// Every stored entry, as (level, position) -> value, with the encoding checked
/// rather than assumed.
fn read_frontier(store: &Option<Cell>) -> BTreeMap<(usize, usize), Field> {
    let mut out = BTreeMap::new();
    let Some(cell) = store else { return out };
    let dict = HashmapE::with_hashmap(7, Some(cell.clone()));
    HashmapType::iterate_slices(&dict, |mut key, mut value| {
        assert_eq!(key.remaining_bits(), 7, "a frontier key is not seven bits");
        let index = key.get_next_int(7).expect("key bits") as usize;
        assert!(index < DEPTH * ARITY, "frontier key {index} is outside 0..83");
        assert_eq!(value.remaining_bits(), 256, "a frontier value is not 256 bits");
        assert_eq!(value.remaining_references(), 0, "a frontier value carries a reference");
        let mut bytes = [0u8; 32];
        for byte in bytes.iter_mut() {
            *byte = value.get_next_byte().expect("value byte");
        }
        assert_ne!(bytes, ZERO, "canonical state must not store an explicit zero");
        out.insert((index / ARITY, index % ARITY), bytes);
        Ok(true)
    })
    .expect("iterate the frontier store");
    out
}

// ---------------------------------------------------------------------------

#[test]
fn the_generated_empty_root_ladder_is_what_the_permutation_produces() {
    let recomputed = recomputed_empty_roots();
    assert_eq!(recomputed.len(), EMPTY_ROOTS.len(), "the ladder changed length");
    for (level, value) in recomputed.iter().enumerate() {
        assert_eq!(
            *value, EMPTY_ROOTS[level],
            "EMPTY_ROOT[{level}] in the generated table is not what the permutation gives"
        );
    }
    assert_eq!(recomputed[0], ZERO, "the empty leaf must be field zero");
    for level in 1..recomputed.len() {
        assert_ne!(recomputed[level], recomputed[level - 1], "two levels share an empty root");
    }

    let probe = Probe::deploy();
    for (level, value) in recomputed.iter().enumerate() {
        assert_eq!(
            probe.call_field("p_empty_root", &[small(level as u64)]),
            *value,
            "the contract's EMPTY_ROOT[{level}] disagrees"
        );
    }
}

#[test]
fn each_commitment_matches_the_profile_and_binds_every_argument() {
    let probe = Probe::deploy();
    let a = small(11);
    let b = small(22);
    let c = small(33);

    let owner = owner_commitment(a, b, c);
    assert_eq!(probe.call_field("p_owner_commitment", &[a, b, c]), owner);
    // These really are 256-bit values, so the comparisons above are not
    // comparing two truncated zeros.
    assert!(dec(&owner).len() > 70, "the commitment is not a full-width field element");
    let body = note_body_commitment(owner, small(5 * TOS), small(77));
    assert_eq!(probe.call_field("p_note_body", &[owner, small(5 * TOS), small(77)]), body);
    assert_eq!(
        probe.call_field("p_note_commitment", &[body, small(3)]),
        note_commitment(body, small(3))
    );
    assert_eq!(probe.call_field("p_nullifier", &[body, a]), nullifier(body, a));
    assert_eq!(
        probe.call_field("p_phantom", &[small(9), small(1), b]),
        phantom_nullifier(small(9), small(1), b)
    );

    // Every argument has to reach the output, or the commitment is not binding.
    for slot in 0..3 {
        let mut args = [a, b, c];
        args[slot] = small(99);
        assert_ne!(
            probe.call_field("p_owner_commitment", &args),
            owner,
            "owner commitment ignores argument {slot}"
        );
    }
    assert_ne!(
        note_body_commitment(owner, small(5 * TOS), small(77)),
        note_body_commitment(owner, small(5 * TOS + 1), small(77)),
        "the amount is not bound into the note body"
    );
    assert_ne!(
        note_commitment(body, small(3)),
        note_commitment(body, small(4)),
        "the leaf index is not bound into the note commitment"
    );

    // The domains separate the structures: the same three values under four
    // different labels must not collide.
    let same = [a, b, c, ZERO, ZERO, ZERO, ZERO];
    let mut produced = vec![
        h7(domain("OWNER-COMMITMENT"), same),
        h7(domain("NOTE-BODY"), same),
        h7(domain("PHANTOM-NULLIFIER"), same),
        h7(domain("COMMIT-NODE"), same),
    ];
    produced.sort();
    produced.dedup();
    assert_eq!(produced.len(), 4, "two domains produced the same value for the same inputs");

    // The zero padding is part of the definition, not slack.
    assert_ne!(
        h7(domain("NOTE-COMMITMENT"), [body, small(3), ZERO, ZERO, ZERO, ZERO, ZERO]),
        h7(domain("NOTE-COMMITMENT"), [body, small(3), small(1), ZERO, ZERO, ZERO, ZERO]),
        "a padding lane does not reach the output"
    );
}

#[test]
fn hashing_into_the_field_is_a_reduction_and_only_a_reduction() {
    let probe = Probe::deploy();
    let modulus =
        from_dec("52435875175126190479447740508185965837690552500527637822603658699938581184513");
    assert_eq!(probe.call_field("p_reduce", &[small(7)]), small(7), "a small value moved");
    assert_eq!(
        probe.call_field("p_reduce", &[modulus]),
        ZERO,
        "the modulus did not reduce to zero"
    );
    let mut above = modulus;
    above[31] += 4; // the modulus ends in 0x01
    assert_eq!(probe.call_field("p_reduce", &[above]), small(4), "reduction is not modular");
}

#[test]
fn the_frontier_agrees_with_rebuilding_the_whole_tree() {
    let probe = Probe::deploy();
    let empty = recomputed_empty_roots();

    // The empty tree's root is the ladder's top, before anything is appended.
    assert_eq!(naive_root(&[], &empty), empty[DEPTH], "an empty tree is not the empty root");

    let mut store: Option<Cell> = None;
    let mut reference_frontier: BTreeMap<(usize, usize), Field> = BTreeMap::new();
    let mut leaves: Vec<Field> = Vec::new();

    // Fifty leaves crosses the first group boundary at 7 and the second at 49.
    for index in 0..50u64 {
        let leaf = note_commitment(small(1000 + index), small(index));
        let (next_store, contract_root) = probe.append(store.clone(), index, leaf);
        let reference_root = reference_append(&mut reference_frontier, index, leaf, &empty);
        leaves.push(leaf);

        assert_eq!(
            contract_root, reference_root,
            "at leaf {index} the contract and the incremental reference disagree"
        );
        assert_eq!(
            contract_root,
            naive_root(&leaves, &empty),
            "at leaf {index} the frontier disagrees with rebuilding the tree from every leaf"
        );
        assert_ne!(contract_root, empty[DEPTH], "the root did not move off the empty root");

        // The store stays canonical and stays in agreement with the reference.
        let stored = read_frontier(&next_store);
        assert_eq!(
            stored, reference_frontier,
            "at leaf {index} the stored frontier is not the reference frontier"
        );
        store = next_store;
    }

    // Order independence is not claimed by the profile and is not true of the
    // frontier: what is claimed is that the root after n appends is the tree of
    // those n leaves, which is what the check above asserts at every step.
    assert_eq!(leaves.len(), 50);
}

/// The one path that reaches the "store no explicit zero" rule. A commitment is
/// never zero in practice, so without this the rule would be written down and
/// never executed.
#[test]
fn a_zero_valued_slot_is_absent_rather_than_stored() {
    let probe = Probe::deploy();
    let empty = recomputed_empty_roots();

    let (store, root) = probe.append(None, 0, ZERO);
    assert_eq!(
        root, empty[DEPTH],
        "a zero leaf is the empty leaf, so the root must still be the empty root"
    );
    let stored = read_frontier(&store);
    assert!(
        !stored.contains_key(&(0, 0)),
        "the zero carry was stored explicitly; canonical state must omit it"
    );
    // Every level above the leaf carries a real value, so the store is not
    // simply empty and the assertion above is not vacuous.
    assert_eq!(stored.len(), DEPTH - 1, "levels above the leaf should each hold one entry");

    // And a later non-zero append at the same slot must bring the entry back.
    let (store, root) = probe.append(store, 0, small(5));
    assert_ne!(root, empty[DEPTH], "overwriting the zero leaf did not change the root");
    assert_eq!(
        read_frontier(&store).get(&(0, 0)),
        Some(&small(5)),
        "the slot did not come back when a non-zero value was written"
    );
}

#[test]
fn the_capacity_sentinel_is_refused() {
    let probe = Probe::deploy();
    let leaf = small(1);
    assert_eq!(probe.append_exit_code("4294967296", leaf), 92, "2^32 was accepted as an index");
    assert_eq!(
        probe.append_exit_code("4294967295", leaf),
        0,
        "the last representable index was refused"
    );
    assert_eq!(probe.append_exit_code("-1", leaf), 91, "a negative index was accepted");
}
