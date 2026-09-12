#!/usr/bin/env python3
"""A killed guard must compile, run, and fail an assertion, not crash or time out."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = 'test-validator-auth-production'
EXPERIMENTAL = 'test-validator-auth-experimental'
MUTANTS = [
    ('live-peer-verification', 'validator/consensus/types.cpp',
     'return enc.move_as_ok()->check_signature(signed_data, signature).is_ok();',
     '(void)enc.move_as_ok()->check_signature(signed_data, signature); return true;', PRODUCTION),
    ('live-duplicate-signer', 'validator/consensus/simplex/certificate.cpp',
     'if (voted[who]) {', 'if (false) {', PRODUCTION),
    ('live-quorum-boundary', 'validator/consensus/simplex/certificate.cpp',
     'voted_weight < tos::quorum_threshold(bus.total_weight)',
     'voted_weight <= tos::quorum_threshold(bus.total_weight)', PRODUCTION),
    ('legacy-proof-preimage', 'crypto/block/signature-set.cpp',
     'tos::create_serialize_tl_object<tos::tos_api::tos_blockId>(block_id.root_hash, block_id.file_hash)',
     'tos::create_serialize_tl_object<tos::tos_api::tos_blockId>(block_id.root_hash, block_id.root_hash)', PRODUCTION),
    ('candidate-required-crypto', 'validator/auth/experimental.h',
     'if (outcome != CryptoResult::valid)', 'if (false)', EXPERIMENTAL),
    ('candidate-network-binding', 'validator/auth/experimental.h',
     'integer(out, static_cast<std::uint32_t>(context.network), 4);',
     'integer(out, 0, 4);', EXPERIMENTAL),
    ('candidate-roster-binding', 'validator/auth/experimental.h',
     'append(out, registry.commitment());', 'append(out, Digest{});', EXPERIMENTAL),
    ('candidate-aggregate-budget', 'validator/auth/experimental.h',
     'component.bytes.size() > max_certificate_bytes - bytes', 'false', EXPERIMENTAL),
]


def execute(build, name):
    return subprocess.run([str(build/'test/validator-auth'/name)],
                          capture_output=True, text=True, timeout=120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8:
        raise ValueError('bounded build parallelism required')
    build, out = args.build.resolve(), args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    logs = out.parent/'mutation-logs'
    logs.mkdir(exist_ok=True)
    baselines = {}
    def compile_target(name, logfile):
        with logfile.open('w') as log:
            subprocess.run(['cmake', '--build', str(build), '--target', name, '-j'+str(args.jobs)],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1800)
    for target in (PRODUCTION, EXPERIMENTAL):
        compile_target(target, logs/(target+'-baseline.log'))
        baseline = execute(build, target)
        if baseline.returncode != 0 or 'SUMMARY\t' not in baseline.stdout:
            raise RuntimeError('baseline failed: '+baseline.stderr[-1000:])
        baselines[target] = baseline.stdout
    reports = []
    for name, filename, before, after, target in MUTANTS:
        path = ROOT/filename
        original = path.read_bytes()
        text = original.decode()
        if text.count(before) != 1:
            raise ValueError('mutation anchor must occur exactly once: '+name)
        try:
            path.write_text(text.replace(before, after))
            compile_target(target, logs/(name+'-build.log'))
            result = execute(build, target)
            (logs/(name+'-stdout.txt')).write_text(result.stdout)
            (logs/(name+'-stderr.txt')).write_text(result.stderr)
            if result.returncode != 1 or 'FAIL' not in result.stderr:
                raise RuntimeError('survived, crashed, or did not fail an assertion: '+name)
            reports.append({'guard':name,'killed':True,'compile_succeeded':True,
                            'assertion':result.stderr.strip()[:400],
                            'original_sha256':hashlib.sha256(original).hexdigest()})
        finally:
            path.write_bytes(original)
            compile_target(target, logs/(name+'-restored-build.log'))
            restored = execute(build, target)
            if restored.returncode != 0 or restored.stdout != baselines[target]:
                raise RuntimeError('restored baseline differs: '+name)
        print('KILLED', name, flush=True)
    out.write_text(json.dumps(reports, indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
