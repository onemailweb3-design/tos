#!/usr/bin/env python3
"""Check real signing transcripts with a second Ed25519 implementation.

Legacy preimages are reconstructed from constructor schemas, and legacy BOCs
and signatures must match the frozen public fixtures. The optional OpenSSL
ML-DSA check is a separate, explicitly requested interoperability measurement.
"""
import argparse
import ctypes
import ctypes.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[2]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sodium_verifier():
    name = ctypes.util.find_library('sodium')
    require(bool(name), 'libsodium is required; do not silently skip independent verification')
    library = ctypes.CDLL(name)
    library.sodium_init.restype = ctypes.c_int
    require(library.sodium_init() >= 0, 'libsodium initialization failed')
    fn = library.crypto_sign_verify_detached
    fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p]
    fn.restype = ctypes.c_int

    def verify(key, message, signature):
        if len(key) != 32 or len(signature) != 64:
            return False
        return fn(ctypes.create_string_buffer(signature), ctypes.create_string_buffer(message),
                  len(message), ctypes.create_string_buffer(key)) == 0
    return verify


def tag(schema):
    return struct.pack('<I', zlib.crc32(schema.encode('ascii')))


def wrapped(inner):
    require(len(inner) < 254, 'unexpected fixture size')
    sized = bytes([len(inner)]) + inner
    sized += bytes((-len(sized)) % 4)
    return tag('consensus.dataToSign session_id:int256 data:bytes = consensus.DataToSign') + bytes([0x42])*32 + sized


def der(tag_number, contents):
    n = len(contents)
    length = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([tag_number]) + length + contents


def openssl_mldsa(key, message, signature, expect_valid):
    # AlgorithmIdentifier id-ml-dsa-44, no parameters; raw public key BIT STRING.
    oid = der(6, bytes.fromhex('608648016503040311'))
    spki = der(0x30, der(0x30, oid) + der(3, b'\0'+key))
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, data in [('key.der', spki), ('message', message), ('signature', signature)]:
            (root/name).write_bytes(data)
        command = ['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER',
                   '-inkey', str(root/'key.der'), '-in', str(root/'message'), '-sigfile', str(root/'signature'),
                   '-pkeyopt', 'context-string:TOS-VAL-AUTH-EXPERIMENT/v1']
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        require((result.returncode == 0) == expect_valid,
                'independent ML-DSA result differs: '+result.stderr[:200])


def check(production: Path, experimental: Path, mldsa: bool):
    golden = json.loads((Path(__file__).with_name('legacy-golden.json')).read_text())['records']
    legacy = {}
    production_checks = []
    for line in production.read_text().splitlines():
        fields = line.split('\t')
        if fields[0] in ('VECTOR', 'BOC'):
            identity = fields[0]+':'+fields[1]
            require(identity not in legacy, 'duplicate legacy record')
            legacy[identity] = fields[2:]
        if fields[0] == 'PASS': production_checks.append(fields[1])
    require(legacy == golden, 'legacy preimage/signature/BOC drift')
    require(len(production_checks) >= 140, 'missing production entrypoint checks')
    vectors = {name.split(':')[1]: [bytes.fromhex(x) for x in fields]
               for name, fields in legacy.items() if name.startswith('VECTOR:')}
    require(set(vectors) == {'proposal', 'notarize', 'finalize', 'skip', 'ordinary-proof'}, 'missing signing domains')
    candidate = vectors['proposal'][1][37:77]
    require(candidate[:4] == tag('consensus.candidateId slot:int hash:int256 = consensus.CandidateId'), 'candidate tag')
    require(candidate[4:8] == struct.pack('<I', 7), 'candidate slot')
    require(vectors['proposal'][1] == wrapped(candidate), 'proposal preimage')
    for name in ('notarize', 'finalize'):
        inner = tag(f'consensus.simplex.{name}Vote id:consensus.CandidateId = consensus.simplex.UnsignedVote') + candidate
        require(vectors[name][1] == wrapped(inner), name+' preimage')
    inner = tag('consensus.simplex.skipVote slot:int = consensus.simplex.UnsignedVote') + struct.pack('<I', 7)
    require(vectors['skip'][1] == wrapped(inner), 'skip preimage')
    ordinary = tag('tos.blockId root_cell_hash:int256 file_hash:int256 = tos.BlockId') + bytes([0x31])*32 + bytes([0x32])*32
    require(vectors['ordinary-proof'][1] == ordinary, 'ordinary proof must not acquire a session wrapper')
    verify = sodium_verifier()
    independent_ed = 0
    for key, message, signature in vectors.values():
        require(verify(key, message, signature), 'libsodium rejects native legacy signature')
        require(not verify(key, message+b'x', signature), 'independent negative control did not fail')
        independent_ed += 2
    pq_checked, experimental_checks, signatures = 0, [], []
    for line in experimental.read_text().splitlines():
        fields = line.split('\t')
        if fields[0] == 'PASS': experimental_checks.append(fields[1])
        if fields[0] != 'VECTOR': continue
        require(len(fields) == 6, 'malformed experimental transcript')
        _, label, scheme, key, message, signature = fields
        key, message, signature = map(bytes.fromhex, (key, message, signature))
        require(message.startswith(b'TOS-VALIDATOR-AUTH-EXPERIMENT/v1'), 'an experiment used an unmarked transcript')
        if scheme == 'ed25519':
            require(verify(key, message, signature), 'libsodium rejects experimental Ed25519 signature')
            require(not verify(key, message+b'x', signature), 'experimental independent negative control did not fail')
            independent_ed += 2
        elif scheme == 'mldsa44':
            require(len(key) == 1312 and len(signature) == 2420, 'wrong ML-DSA profile')
            if mldsa:
                openssl_mldsa(key, message, signature, True)
                openssl_mldsa(key, message+b'x', signature, False)
                pq_checked += 2
        else:
            raise ValueError('unknown transcript scheme')
        signatures.append((label, scheme))
    require(len(experimental_checks) >= 300 and len(signatures) == 5, 'missing isolated signature evidence')
    return {'success': True, 'production_assertions': len(production_checks),
            'experimental_assertions': len(experimental_checks), 'legacy_vectors_and_bocs': len(legacy),
            'independent_ed25519_checks': independent_ed, 'independent_mldsa_checks': pq_checked,
            'scope': 'entrypoint regressions and isolated candidate authentication, not network activation'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('production', type=Path)
    parser.add_argument('experimental', type=Path)
    parser.add_argument('--openssl-mldsa', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.production, args.experimental, args.openssl_mldsa)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps(result))
