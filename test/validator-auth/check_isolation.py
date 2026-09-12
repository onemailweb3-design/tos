#!/usr/bin/env python3
"""Keep experimental authentication unreachable from production translation units.

This is an accidental-linkage/source inventory gate, not a proof against a
malicious build system and not a throughput benchmark. It records actual source
hashes so a reviewer can compare the audited production boundary with the base.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = [
    'validator/consensus/types.cpp', 'validator/consensus/types.h',
    'validator/consensus/simplex/votes.cpp', 'validator/consensus/simplex/certificate.cpp',
    'validator/consensus/simplex/pool.cpp', 'validator/consensus/block-producer.cpp',
    'validator/consensus/bridge.cpp', 'validator/manager.cpp',
    'validator/impl/check-proof.cpp', 'validator/impl/accept-block.cpp',
    'validator/impl/top-shard-descr.cpp', 'validator/impl/liteserver.cpp',
    'validator/validate-broadcast.cpp', 'crypto/block/signature-set.cpp',
    'crypto/block/validator-set.cpp', 'crypto/block/check-proof.cpp',
    'crypto/block/mc-config.cpp', 'crypto/block/block.tlb',
    'crypto/smartcont/elector-code.fc', 'crypto/smartcont/config-code.fc',
    'keyring/keyring.h', 'keyring/keyring.cpp', 'keys/keys.cpp', 'keys/encryptor.cpp',
    'tl/generate/scheme/tos_api.tl', 'tl/generate/scheme/lite_api.tl',
    'tosctl/src/block/src/signature.rs', 'tos/quorum.h',
]


def check(root):
    violations = []
    experimental = (root/'validator/auth/experimental.h').resolve()
    for directory in ('validator','crypto','keys','keyring','adnl','overlay','validator-engine'):
        for path in (root/directory).rglob('*'):
            if not path.is_file() or path.suffix not in ('.cpp','.c','.h','.hpp'):
                continue
            text = path.read_text(errors='strict')
            # Match on where an include resolves, not on how it is spelled.
            # This tree writes the repository-relative form, but a production
            # .cpp added beside the header would use the ordinary same-directory
            # form, #include "experimental.h", and a pattern searching the text
            # for auth/experimental.h would let it through. Both roots are tried
            # because both are legitimate and either one reaches the header.
            for spelled in re.findall(r'#\s*include\s*[<"]([^>"\n]+)[>"]', text):
                if any((base/spelled).resolve() == experimental for base in (path.parent, root)):
                    violations.append(str(path.relative_to(root)))
            if 'tos_validator_auth_test_' in text:
                violations.append(str(path.relative_to(root))+': test signer')
    cmake = (root/'test/CMakeLists.txt').read_text()
    if not re.search(r'option\(TOS_BUILD_VALIDATOR_AUTH_TESTS\s+"[^"]*"\s+OFF\)',cmake):
        violations.append('experimental build option is not default-off')
    for path in root.rglob('CMakeLists.txt'):
        if 'third-party' in path.parts or path == root/'test/validator-auth/CMakeLists.txt':
            continue
        text = path.read_text()
        if 'validator-auth-test-signer' in text:
            violations.append(str(path.relative_to(root))+': signer library outside test build')
    if violations:
        raise ValueError('experimental production linkage: '+repr(violations))
    return {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in PRODUCTION}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    files = check(ROOT)
    commit = subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,text=True,capture_output=True)
    report = {'success':True,'source_commit':commit.stdout.strip() if commit.returncode==0 else None,
              'production_source_sha256':files,
              'claim':'no test backend linked or experimental verifier included in production sources'}
    args.out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(f'PASS: experimental isolation; {len(files)} production files inventoried')
