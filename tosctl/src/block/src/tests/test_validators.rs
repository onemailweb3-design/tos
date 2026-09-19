/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;
use crate::{
    blocks::Block, config_params::ConfigParamEnum, merkle_proof::MerkleProof,
    signature::BlockProof, write_read_and_assert, ShardIdent, BASE_WORKCHAIN_ID, MASTERCHAIN_ID,
};

#[test]
fn test_validator_info_new_default() {
    let vi = ValidatorInfo::default();
    let vi2 = ValidatorInfo::default();

    assert_eq!(vi, vi2);
    write_read_and_assert(vi);
}

#[test]
fn test_validator_info_new_with() {
    let vi = ValidatorInfo::with_params(1, 2, false);

    assert_ne!(vi, ValidatorInfo::with_params(3, 2, true));
    write_read_and_assert(vi);
}

#[test]
fn test_validator_base_info_new_default() {
    let vi = ValidatorBaseInfo::new();
    let vi2 = ValidatorBaseInfo::default();

    assert_eq!(vi, vi2);
    write_read_and_assert(vi);
}

#[test]
fn test_validator_base_info_new_with() {
    let vi = ValidatorBaseInfo::with_params(1, 2);

    assert_ne!(vi, ValidatorBaseInfo::with_params(3, 2));
    write_read_and_assert(vi);
}

#[test]
fn test_validator_desc_new_default() {
    let vd = ValidatorDescr::new();
    let vd2 = ValidatorDescr::default();

    assert_eq!(vd, vd2);
    write_read_and_assert(vd);
}

#[test]
fn test_validator_desc_info_new_with() {
    let keypair = crate::Ed25519KeyOption::generate().unwrap();
    let key = SigPubKey::from_bytes(keypair.pub_key().unwrap()).unwrap();
    let vd = ValidatorDescr::with_params(key.clone(), 2121212121, None);

    assert_ne!(vd, ValidatorDescr::with_params(key, 2, None));
    write_read_and_assert(vd);
}

#[test]
fn test_validator_set_serialize() {
    let mut list = vec![];
    for n in 0..20 {
        let keypair = crate::Ed25519KeyOption::generate().unwrap();
        let key = SigPubKey::from_bytes(keypair.pub_key().unwrap()).unwrap();
        let vd = ValidatorDescr::with_params(key, n, None);
        list.push(vd);
    }

    let vset = ValidatorSet::new(0, 100, 1, list).unwrap();

    write_read_and_assert(vset);
}

fn check_block_proof(key_block_file_name: &str, proof_file_name: &str) {
    let key_block = Block::construct_from_file(key_block_file_name).unwrap();
    let proof = BlockProof::construct_from_file(proof_file_name).unwrap();

    let merkle_proof = MerkleProof::construct_from_cell(proof.root.clone()).unwrap();
    let block_virt_root = merkle_proof.proof.virtualize(1);
    let virt_block = Block::construct_from_cell(block_virt_root).unwrap();

    let config =
        key_block.read_extra().unwrap().read_custom().unwrap().unwrap().config().unwrap().clone();

    let cp34 = config.config(34).unwrap().unwrap();
    let cur_validator_set = if let ConfigParamEnum::ConfigParam34(vs) = cp34 {
        vs.cur_validators
    } else {
        unreachable!()
    };

    let cp28 = config.config(28).unwrap().unwrap();
    let cc_config =
        if let ConfigParamEnum::ConfigParam28(ccc) = cp28 { ccc } else { unreachable!() };

    let virt_info = virt_block.read_info().unwrap();

    let (validators, hash_short) = cur_validator_set
        .calc_subset(
            &cc_config,
            proof.proof_for.shard_id.shard_prefix_with_tag(),
            proof.proof_for.shard_id.workchain_id(),
            proof
                .signatures
                .as_ref()
                .map(|s| s.validator_info().catchain_seqno)
                .unwrap_or_else(|| virt_info.gen_catchain_seqno()),
        )
        .unwrap();

    if let Some(signatures) = proof.signatures.as_ref() {
        assert_eq!(signatures.validator_info().catchain_seqno, virt_info.gen_catchain_seqno());

        assert_eq!(signatures.validator_info().validator_list_hash_short, hash_short);

        let pure_signatures = signatures.pure_signatures();

        let data =
            Block::build_data_for_sign(&proof.proof_for.root_hash, &proof.proof_for.file_hash);
        let weight = pure_signatures.check_signatures(&validators, &data).unwrap();
        assert_eq!(weight, pure_signatures.weight());
    } else {
        assert_eq!(virt_info.gen_validator_list_hash_short(), hash_short);
    }
}

#[test]
fn test_calc_mc_subset() {
    check_block_proof(
        "src/tests/data/test_calc_subset/key_block__no_shuffle",
        "src/tests/data/test_calc_subset/proof__no_shuffle",
    );
}

#[test]
fn test_calc_mc_subset_shuffle() {
    check_block_proof(
        "src/tests/data/test_calc_subset/key_block__shuffle",
        "src/tests/data/test_calc_subset/proof__shuffle",
    );
}

#[test]
fn test_calc_shard_subset() {
    check_block_proof(
        "src/tests/data/test_calc_shard_subset/key_block",
        "src/tests/data/test_calc_shard_subset/proof_4377252",
    );
}

#[test]
fn test_isolate_mc_validators() {
    let key_block =
        Block::construct_from_file("src/tests/data/test_calc_subset/key_block__shuffle").unwrap();
    let config =
        key_block.read_extra().unwrap().read_custom().unwrap().unwrap().config().unwrap().clone();

    let cp34 = config.config(34).unwrap().unwrap();
    let cur_validator_set = if let ConfigParamEnum::ConfigParam34(vs) = cp34 {
        vs.cur_validators
    } else {
        unreachable!()
    };

    let cp28 = config.config(28).unwrap().unwrap();
    let mut cc_config =
        if let ConfigParamEnum::ConfigParam28(ccc) = cp28 { ccc } else { unreachable!() };
    cc_config.isolate_mc_validators = true;

    // calc subsets for shardes and check it does not contain main validators

    let (main_validators, _) = cur_validator_set
        .calc_subset(
            &cc_config,
            ShardIdent::masterchain().shard_prefix_with_tag(),
            MASTERCHAIN_ID,
            123,
        )
        .unwrap();

    println!("main validators");
    for v in main_validators.iter() {
        println!("{:x}", v.adnl_addr.as_ref().unwrap());
    }

    for shard in 0..16 {
        let shard =
            ShardIdent::with_tagged_prefix(BASE_WORKCHAIN_ID, (shard << 60) | (8 << 56)).unwrap();
        let (shard_validators, _) = cur_validator_set
            .calc_subset(&cc_config, shard.shard_prefix_with_tag(), BASE_WORKCHAIN_ID, 123)
            .unwrap();

        println!("shard {} validators", shard);
        for v in shard_validators.iter() {
            println!("{:x}", v.adnl_addr.as_ref().unwrap());
        }

        for sv in shard_validators.iter() {
            for mv in main_validators.iter() {
                assert_ne!(sv.public_key().unwrap(), mv.public_key().unwrap())
            }
        }
    }
}

// The accepted ValidatorDescr constructor set is shared with the C++ side through
// test/pq-native/validator-descr-tags.tsv. One implementation accepting a tag the
// other rejects is a consensus split, so both read the same file.
//
// Each rejected tag is given a body that is well formed for the 0x73 shape, so the
// tag is the only possible reason for refusal; otherwise the test would pass for
// the wrong reason.
#[test]
fn accepted_descriptor_tags_match_the_shared_set() {
    fn descriptor_bytes(tag: u8) -> SliceData {
        let mut b = BuilderData::new();
        b.append_u8(tag).unwrap();
        if tag == 0xb3 {
            // the post-quantum shape
            UInt256::from([1u8; 32]).write_to(&mut b).unwrap();
            b.append_bits(1, 16).unwrap();
            UInt256::from([2u8; 32]).write_to(&mut b).unwrap();
            b.checked_append_reference(pack_pq_bytes(&vec![3u8; 1312], PQ_BYTES_HARD_MAX).unwrap())
                .unwrap();
            1234u64.write_to(&mut b).unwrap();
            UInt256::from([9u8; 32]).write_to(&mut b).unwrap();
        } else {
            // the classical shape; 0x53 carries no adnl_addr
            SigPubKey::from_bytes(&[7u8; 32]).unwrap().write_to(&mut b).unwrap();
            1234u64.write_to(&mut b).unwrap();
            if tag != 0x53 {
                UInt256::from([9u8; 32]).write_to(&mut b).unwrap();
            }
        }
        SliceData::load_builder(b).unwrap()
    }

    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test/pq-native/validator-descr-tags.tsv");
    let text = std::fs::read_to_string(path).expect("shared descriptor tag set");
    let mut checked = 0;
    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        let tag = u8::from_str_radix(f.next().expect("tag"), 16).expect("hex tag");
        let verdict = f.next().expect("verdict");

        let mut cs = descriptor_bytes(tag);
        let parsed = ValidatorDescr::construct_from(&mut cs);
        match verdict {
            "accept" => assert!(parsed.is_ok(), "tag 0x{:02x} must be accepted", tag),
            "reject" => assert!(parsed.is_err(), "tag 0x{:02x} must be rejected", tag),
            other => panic!("unknown verdict {other}"),
        }
        checked += 1;
    }
    assert!(checked >= 6, "expected the full shared tag set, saw {checked}");

    // The writer must never produce a tag outside the accepted set.
    for adnl in [None, Some(UInt256::from([9u8; 32]))] {
        let d = ValidatorDescr::with_params(SigPubKey::from_bytes(&[7u8; 32]).unwrap(), 1, adnl);
        let mut b = BuilderData::new();
        d.write_to(&mut b).unwrap();
        let emitted = SliceData::load_builder(b).unwrap().get_next_byte().unwrap();
        assert!(emitted == 0x53 || emitted == 0x73, "writer emitted 0x{emitted:02x}");
    }
}

fn sample_pq_key() -> PqConsensusKey {
    PqConsensusKey {
        validator_id: UInt256::from([1u8; 32]),
        algorithm_id: 1,
        key_id: UInt256::from([2u8; 32]),
        public_key: vec![3u8; 1312],
    }
}

// A post-quantum descriptor survives a full encode/decode cycle with every field
// intact, including the 1312-byte key that has to travel through the bounded-bytes
// cell encoding because it cannot fit inline.
#[test]
fn pq_descriptor_round_trip() {
    let descr = ValidatorDescr::with_pq_params(sample_pq_key(), 4242, UInt256::from([9u8; 32]));

    let mut b = BuilderData::new();
    descr.write_to(&mut b).unwrap();
    let mut cs = SliceData::load_builder(b).unwrap();
    let back = ValidatorDescr::construct_from(&mut cs).unwrap();

    assert_eq!(back, descr);
    let key = back.pq_key().expect("post-quantum key");
    assert_eq!(key.validator_id, UInt256::from([1u8; 32]));
    assert_eq!(key.algorithm_id, 1);
    assert_eq!(key.key_id, UInt256::from([2u8; 32]));
    assert_eq!(key.public_key.len(), 1312);
    assert_eq!(back.weight, 4242);
    assert_eq!(back.adnl_addr, Some(UInt256::from([9u8; 32])));

    // The classical accessor refuses rather than inventing an Ed25519 key.
    assert!(back.public_key().is_err());

    // A post-quantum descriptor without an explicit ADNL address cannot be written,
    // because an ADNL identity is never derived from a consensus key.
    let no_adnl = ValidatorDescr {
        key: ValidatorKey::Pq(sample_pq_key()),
        weight: 1,
        adnl_addr: None,
        prev_weight_sum: 0,
    };
    assert!(no_adnl.write_to(&mut BuilderData::new()).is_err());

    // The writer emits the frozen tag.
    let mut b = BuilderData::new();
    descr.write_to(&mut b).unwrap();
    assert_eq!(SliceData::load_builder(b).unwrap().get_next_byte().unwrap(), 0xb3);
}

// The post-quantum descriptor bytes are produced authoritatively by the C++ side and
// recorded in test/pq-native/validator-descr-vectors.txt. Rust must decode each one to
// the same fields and re-encode to the identical cell, so neither implementation can
// change the wire format without the other noticing.
#[test]
fn pq_descriptor_matches_shared_cpp_vectors() {
    use crate::read_single_root_boc;

    fn u256(hex_str: &str) -> UInt256 {
        let mut a = [0u8; 32];
        a.copy_from_slice(&hex::decode(hex_str).unwrap());
        UInt256::from(a)
    }

    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test/pq-native/validator-descr-vectors.txt");
    let text = std::fs::read_to_string(path).expect("shared descriptor vectors");
    let mut checked = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f.len(), 8, "bad vector line");
        let (vid, alg) = (u256(f[0]), f[1].parse::<u16>().unwrap());
        let (kid, public_key) = (u256(f[2]), hex::decode(f[3]).unwrap());
        let (weight, adnl) = (f[4].parse::<u64>().unwrap(), u256(f[5]));
        let (root_hex, boc) = (f[6], hex::decode(f[7]).unwrap());

        // The C++-produced cell decodes to exactly the recorded fields.
        let cell = read_single_root_boc(&boc).unwrap();
        assert_eq!(cell.repr_hash().as_hex_string(), root_hex);
        let mut cs = SliceData::load_cell_ref(&cell).unwrap();
        let descr = ValidatorDescr::construct_from(&mut cs).unwrap();
        let key = descr.pq_key().expect("post-quantum key");
        assert_eq!(key.validator_id, vid);
        assert_eq!(key.algorithm_id, alg);
        assert_eq!(key.key_id, kid);
        assert_eq!(key.public_key, public_key);
        assert_eq!(descr.weight, weight);
        assert_eq!(descr.adnl_addr, Some(adnl));

        // Re-encoding the same fields in Rust yields the identical cell.
        let mut b = BuilderData::new();
        descr.write_to(&mut b).unwrap();
        assert_eq!(b.into_cell().unwrap().repr_hash().as_hex_string(), root_hex);
        checked += 1;
    }
    assert!(checked >= 3, "expected the full vector set, saw {checked}");
}
