/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
//! Canonical bounded-bytes -> cell tree (PQBytes), the exact counterpart of
//! crypto/pq/pq-bytes.cpp. ML-DSA-44 public keys (1312 B) and signatures (2420 B)
//! exceed the 127-byte cell payload, so they are stored as a greedy 127-byte snake:
//! the root cell holds the u32 length, data cells are full except the last. A given
//! byte string encodes to exactly one tree; unpack rejects oversize and any
//! non-canonical tree. Cross-language parity is locked by the shared vector fixture
//! test/pq-mldsa44/pq-bytes-vectors.txt (generated authoritatively by the C++ side).

use crate::{fail, BuilderData, Cell, IBitstring, Result, SliceData};

pub const PQ_BYTES_CHUNK: usize = 127;

pub fn pack_pq_bytes(data: &[u8], max_bytes: usize) -> Result<Cell> {
    let len = data.len();
    if len > max_bytes || max_bytes > 0xffff_ffff {
        fail!("pq-bytes: oversize")
    }
    let mut next: Option<Cell> = None;
    if len > 0 {
        let nchunks = len.div_ceil(PQ_BYTES_CHUNK);
        for i in (0..nchunks).rev() {
            let off = i * PQ_BYTES_CHUNK;
            let n = core::cmp::min(PQ_BYTES_CHUNK, len - off);
            let mut b = BuilderData::new();
            b.append_raw(&data[off..off + n], n * 8)?;
            if let Some(c) = next.take() {
                b.checked_append_reference(c)?;
            }
            next = Some(b.into_cell()?);
        }
    }
    let mut root = BuilderData::new();
    root.append_bits(len, 32)?;
    if let Some(c) = next {
        root.checked_append_reference(c)?;
    }
    root.into_cell()
}

pub fn unpack_pq_bytes(root: &Cell, max_bytes: usize) -> Result<Vec<u8>> {
    let mut cs = SliceData::load_cell_ref(root)?;
    if cs.remaining_bits() != 32 {
        fail!("pq-bytes: root bits")
    }
    let len = cs.get_next_int(32)? as usize;
    if len > max_bytes {
        fail!("pq-bytes: oversize")
    }
    if len == 0 {
        if cs.remaining_references() != 0 {
            fail!("pq-bytes: empty with ref")
        }
        return Ok(Vec::new());
    }
    if cs.remaining_references() != 1 {
        fail!("pq-bytes: root ref")
    }
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut cur = cs.checked_drain_reference()?;
    loop {
        let mut dc = SliceData::load_cell(cur)?;
        let n = core::cmp::min(PQ_BYTES_CHUNK, len - out.len());
        if dc.remaining_bits() != n * 8 {
            fail!("pq-bytes: chunk bits")
        }
        out.extend_from_slice(&dc.get_next_bytes(n)?);
        if out.len() == len {
            if dc.remaining_references() != 0 {
                fail!("pq-bytes: trailing ref")
            }
            break;
        }
        if dc.remaining_references() != 1 {
            fail!("pq-bytes: chunk ref")
        }
        cur = dc.checked_drain_reference()?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_single_root_boc;

    #[test]
    fn shared_vectors_match_cpp() {
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test/pq-mldsa44/pq-bytes-vectors.txt");
        let text = std::fs::read_to_string(path).expect("shared vector fixture");
        let mut count = 0;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(' ').collect();
            assert_eq!(parts.len(), 3, "bad fixture line");
            let input = hex::decode(parts[0]).unwrap();
            let root_hex = parts[1];
            let boc = hex::decode(parts[2]).unwrap();

            // The C++-produced BOC decodes to a cell with the recorded hash, and unpacks
            // to the input -> Rust decode agrees with the C++ encoding.
            let cell = read_single_root_boc(&boc).unwrap();
            assert_eq!(cell.repr_hash().as_hex_string(), root_hex);
            assert_eq!(unpack_pq_bytes(&cell, 2420).unwrap(), input);
            // Rust encode of the same input yields the identical cell -> byte-exact parity.
            let packed = pack_pq_bytes(&input, 2420).unwrap();
            assert_eq!(packed.repr_hash().as_hex_string(), root_hex);
            count += 1;
        }
        assert!(count >= 8, "expected the full vector set");
    }

    #[test]
    fn oversize_and_canonical_negatives() {
        assert!(pack_pq_bytes(&vec![0u8; 2421], 2420).is_err());
        let p = pack_pq_bytes(&vec![7u8; 2420], 2420).unwrap();
        assert!(unpack_pq_bytes(&p, 1312).is_err());
        // non-full middle chunk (100 instead of 127) must be rejected
        let mut c2 = BuilderData::new();
        c2.append_raw(&vec![1u8; 127], 127 * 8).unwrap();
        let mut c1 = BuilderData::new();
        c1.append_raw(&vec![1u8; 100], 100 * 8).unwrap();
        c1.checked_append_reference(c2.into_cell().unwrap()).unwrap();
        let mut root = BuilderData::new();
        root.append_bits(227, 32).unwrap();
        root.checked_append_reference(c1.into_cell().unwrap()).unwrap();
        assert!(unpack_pq_bytes(&root.into_cell().unwrap(), 2420).is_err());
    }
}
