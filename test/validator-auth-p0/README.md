# P0 profile executable specification

These tests exercise a **reference** codec and C0 verifier. They are not production
C++/Rust integration, a native TL-B/BOC implementation or a deployed signer.
`golden.json.gz` is compressed fixture storage, not a network encoding. Decompress
it with `gzip -dc test/validator-auth-p0/golden.json.gz`; the CI artifact includes
the uncompressed JSON for review. Seeds are intentionally public test seeds.

```sh
python3 test/validator-auth-p0/contract_artifacts.py
python3 -m unittest discover -s test/validator-auth-p0 -p 'test_*.py' -v
python3 test/validator-auth-p0/check_production.py --out artifacts/production-boundary.json
python3 test/validator-auth-p0/mutations.py --out artifacts/p0-mutations.json
cmake -S third-party/tl-parser -B build-p0-schema -G Ninja
cmake --build build-p0-schema -j2
python3 test/validator-auth-p0/check_schema.py \
  --tl-parser build-p0-schema/tl-parser --out artifacts/p0-schema.json
```

Python 3.10+ and an OpenSSL CLI supporting Pure Ed25519 are required. No Python
package download is needed. The C parser uses ordinary CMake/C compiler tools.
Tests regenerate signatures in memory with OpenSSL and require equality with the
frozen full bytes. Verification uses a separately implemented public-data Edwards
arithmetic oracle with the profile's exact acceptance rules. The oracle is not
constant-time and MUST NOT be used with production secret material.

The test suites include boundary/subcase loops; CI logs the exact method count. Five role fixtures each
contain three real Ed25519 signatures. The administration fixture demonstrates
bytes and signatures only, not owner approval or on-chain operation execution.
Future-sized signature fields and the four-way byte tree are structural tests,
not post-quantum cryptographic or native BOC tests.

The mutation checks operate on the reference Python/SQL logic, not production
consensus code. Every altered source must parse and produce a named assertion
failure, not crash, time out or fail import. Every restored baseline must pass.
The native TL parser compiles combined current/proposed schemas and must reject
an undefined type. The proposed TL-B fragment remains a reviewed layout whose
native generator/BOC gates are explicitly required by the implementation plan.

The SQL test executes the DDL against an actual database, closes and reopens it,
and checks immutable public records, non-reusable capacity and terminal results.
This does **not** prove power-loss persistence, multi-host fencing, hardware
anti-rollback or that the future service enforces every lifecycle transition.

Golden replacement is deliberately explicit: `vectors.py --write <output.json>`.
Review any byte change before replacing the compressed corpus. A new approved
profile requires newly reviewed vectors; silently regenerating them in CI would
remove the compatibility test.


## Lifecycle/API evidence and regeneration

canonical-schema.json is read directly by reference.py. contract_artifacts.py
checks its complete type/method graph, exact generated WIRE view and profile
artifact hashes. The profile binds documents/schema, while vectors bind profile;
there is no cyclic hash of the vectors back into the profile.

lifecycle-api-golden.json includes every ordered binary type and lifecycle states
at 199/200/201 around a scheduled transition. Structural API vectors are not
claims that their sample proof bytes authenticate. Executable semantic pairs cover
all 13 methods; real service permit/receipt signature checks use the independent
Ed25519 oracle. Lifecycle tests cover register/rotate/retire/cancel, rejection
atomicity, nonce/CAS, same-slot conflict, epoch history, exact boundary, replay,
unrelated updates, immutable snapshots and four separate authorization checks.

Mutations run the named discriminating test where another affected positive
scenario could raise an expected refusal. They must produce assertion failures,
never count import/syntax errors, exceptions or crashes as a killed guard. Full
restored suites pass after every mutation. The production-baseline.json hashes
were taken from the specified base commit; check_production.py compares actual
bytes and includes a changed-byte negative control. No production fixture is
regenerated when the new candidate profile fingerprint changes.

For an intentionally revised candidate, run contract_artifacts.py --write, then
vectors.py to an explicit output and review the diff before gzip with mtime=0.
For the lifecycle/API corpus, explicitly call test_lifecycle_api.golden() and
write its JSON; tests never overwrite committed fixtures. Review schema, generated
view, profile and golden changes as one artifact set.
