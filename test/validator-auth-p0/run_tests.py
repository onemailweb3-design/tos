"""Execute the reference tests and retain architecture-comparable test identities."""
import argparse
import json
from pathlib import Path
import unittest


def identifiers(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from identifiers(item)
        else:
            yield item.id()


def main(destination):
    here = Path(__file__).resolve().parent
    suite = unittest.defaultTestLoader.discover(str(here), pattern='test_*.py')
    tests = sorted(identifiers(suite))
    if not tests or len(tests) != len(set(tests)):
        raise RuntimeError('empty or duplicate test inventory')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    successful = result.wasSuccessful() and not result.skipped and result.testsRun == len(tests)
    report = dict(success=successful, tests_run=result.testsRun, test_ids=tests,
                  failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
                  scope='reference codec/lifecycle/API and SQL, not production P0 integration')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    return successful


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(0 if main(args.out) else 1)
