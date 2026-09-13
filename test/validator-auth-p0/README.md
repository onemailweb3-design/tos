# P0 profile executable specification

These tests exercise a **reference** codec and C0 verifier. They are not production
C++/Rust integration, a native TL-B/BOC implementation or a deployed signer.
`golden.json.gz` is compressed fixture storage, not a network encoding. Decompress
it with `gzip -dc test/validator-auth-p0/golden.json.gz`; the CI artifact includes
the uncompressed JSON for review. Seeds are intentionally public test seeds.

```sh
python3 test/validator-auth-p0/test_profile.py -v
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

The 17 unittest methods include boundary/subcase loops. Five role fixtures each
contain three real Ed25519 signatures. The administration fixture demonstrates
bytes and signatures only, not owner approval or on-chain operation execution.
Future-sized signature fields and the four-way byte tree are structural tests,
not post-quantum cryptographic or native BOC tests.

Eight mutation checks operate on the reference Python/SQL logic, not production
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
