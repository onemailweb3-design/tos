"""Prove the inventoried production and historical-fixture bytes are unchanged."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def check(root, expected):
    actual = {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in expected}
    if actual != expected:
        raise ValueError('production/historical boundary changed')
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    baseline = json.loads((ROOT/'test/validator-auth-p0/production-baseline.json').read_text())
    actual = check(ROOT, baseline['source_sha256'])
    # A silent inventory is not evidence: prove it detects a changed byte.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); (root/'probe').write_bytes(b'original')
        expected = {'probe': hashlib.sha256(b'original').hexdigest()}
        check(root, expected); (root/'probe').write_bytes(b'changed')
        try:
            check(root, expected)
        except ValueError:
            pass
        else:
            raise RuntimeError('boundary negative control survived')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dict(success=True, base=baseline['base'], source_sha256=actual,
                                       negative_control='one changed byte rejected'), indent=2)+'\n')
    print('PASS:', len(actual), 'production/historical files unchanged; negative control rejected')


if __name__ == '__main__':
    main()
