#!/usr/bin/env python3
"""Prove the isolation guard rejects what it claims to reject.

The eight mutations exercise the cryptographic and quorum checks. Nothing
exercised the guard that keeps the experimental header out of production, and a
guard nobody tests is one that can stop guarding without anyone noticing -- as
this one had: it matched the text `auth/experimental.h`, so a production file
beside the header writing the ordinary `#include "experimental.h"` reached the
same header and was reported clean.

Synthetic trees only. Nothing here compiles or links anything.
"""
import importlib.util
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT/'test/validator-auth/check_isolation.py'

spec = importlib.util.spec_from_file_location('isolation_guard', GUARD)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def tree(root, extra=None):
    """The smallest tree the guard accepts: its inventory, and a default-off option."""
    for name in guard.PRODUCTION:
        target = root/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('// inventory placeholder\n')
    (root/'test').mkdir(parents=True, exist_ok=True)
    (root/'test/CMakeLists.txt').write_text(
        'option(TOS_BUILD_VALIDATOR_AUTH_TESTS "test only" OFF)\n')
    header = root/'validator/auth/experimental.h'
    header.parent.mkdir(parents=True, exist_ok=True)
    header.write_text('// sibling header\n')
    for name, text in (extra or {}).items():
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def run(extra=None):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        tree(root, extra)
        try:
            guard.check(root)
        except ValueError as refusal:
            return str(refusal)
        return None


def main() -> int:
    failures = []

    def expect_clean(label, extra=None):
        refusal = run(extra)
        if refusal is not None:
            failures.append(f'{label}: guard refused a clean tree: {refusal}')
        else:
            print(f'PASS\t{label}')

    def expect_refused(label, extra):
        if run(extra) is None:
            failures.append(f'{label}: guard accepted a violation')
        else:
            print(f'PASS\t{label}')

    expect_clean('clean-tree-accepted')

    # Every spelling that reaches the header from a production file, and from
    # more than one directory. Fixtures that all sit beside the header cannot
    # see a root being missed: the same-directory form is what the original
    # pattern let through, and the library-relative form from a subdirectory is
    # what the first attempt at fixing it let through, because
    # validator/CMakeLists.txt puts validator/ on the include path.
    for label, where, spelled in (
            ('qualified', 'validator/auth', 'validator/auth/experimental.h'),
            ('same-directory', 'validator/auth', 'experimental.h'),
            ('dot-relative', 'validator/auth', './experimental.h'),
            ('parent-relative', 'validator/consensus', '../auth/experimental.h'),
            ('library-relative', 'validator/consensus', 'auth/experimental.h'),
            ('library-relative-angled', 'validator/consensus', '<auth/experimental.h>'),
            ('qualified-from-subdirectory', 'validator/consensus', 'validator/auth/experimental.h'),
            ('angled', 'validator/auth', '<validator/auth/experimental.h>')):
        include = spelled if spelled.startswith('<') else f'"{spelled}"'
        expect_refused(f'include-{label}-refused',
                       {f'{where}/probe.cpp': f'#include {include}\n'})

    # A header of the same name elsewhere is a different file and must not trip
    # the guard, or the guard becomes a name filter rather than a path check.
    expect_clean('unrelated-header-of-the-same-name-accepted',
                 {'validator/other/experimental.h': '// unrelated\n',
                  'validator/other/user.cpp': '#include "experimental.h"\n'})

    expect_refused('test-signer-symbol-refused',
                   {'validator/probe.cpp': 'void tos_validator_auth_test_sign();\n'})
    expect_refused('build-option-not-default-off-refused',
                   {'test/CMakeLists.txt':
                    'option(TOS_BUILD_VALIDATOR_AUTH_TESTS "test only" ON)\n'})

    for failure in failures:
        print(f'FAIL\t{failure}')
    print(f'SUMMARY\t{12 - len(failures)}\tisolation guard self-checks')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
