# N6 status for review

This document records durable evidence for the N6 measurement scaffolding. It
does not contain release measurements or launch parameters. Release evidence is
still refused until the N5 closure artifact names the exact measured commit and
closes all three registered gaps.

## N6.0 measurement contract

Implementation commits:

- `d82489a21de53f8603e374715b33bba6ac97eae0` — manifest contract, bounded trace and metric schemas, exact byte accounting, and six registered gates.
- `6839808bd9b5b9e8342e6f78f1db64bebebbd7e4` — disabled instrumentation path reduced to one atomic load and a branch before locks, reference-count traffic, or clock reads.
- `876aa506220b11dcf9622394ef79ed2be53a9efe` — removed the unused public locking sink accessor.

Registered gates:

- `n6-metric-schema`
- `n6-manifest-completeness`
- `n6-monotonic-timestamps`
- `n6-low-cardinality`
- `n6-size-accounting`
- `n6-instrumentation-byte-equivalence`

Mutation evidence, run individually and restored before the next mutation:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Replace exact serialized broadcast bytes with `signature_count * 96` | `n6-size-accounting` | `N6_SIZE_ACCOUNTING_FAILURE: recorded finality bytes differ from production serialization` |
| Compute duration from the wall-clock coordinate | `n6-monotonic-timestamps` | `N6_MONOTONIC_TIMESTAMP_FAILURE: forward steady interval was refused` |
| Omit `git_commit` from the generated manifest | `n6-manifest-completeness` | `pq_measurement_manifest.ManifestError: manifest missing required field git_commit` |
| Add `validator_id` to the registered `messages_total` labels | `n6-low-cardinality` | `N6_LOW_CARDINALITY_FAILURE: registered schema contains a forbidden high-cardinality label` |
| Evaluate a lazy trace-id provider while measurement is disabled | `n6-disabled-instrumentation-cost` | `N6_DISABLED_INSTRUMENTATION_COST_FAILURE: disabled instrumentation evaluated the trace-id provider` |

## N6.1 acceptance criteria scaffolding

Implementation commit:

- `5e26fe41205a12ce22a900b04c4c80611bd2d328` — machine-readable criteria schema, release-placeholder refusal, and live manifest input hashes.

Registered gate: `n6-acceptance-criteria`.

The canonical scaffolding input is `doc/pq-native/N6-ACCEPTANCE-CRITERIA.json`.
Its positive thresholds deliberately remain zero and its hardware profile is
`OWNER_REVIEW_REQUIRED`; both conditions are refused in release mode. These are
not launch values. The owner must commit independently justified thresholds and
the reviewed release hardware profile before any release-grade run.

Mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Let release mode accept zero positive thresholds | `n6-acceptance-criteria` | `N6_ACCEPTANCE_CRITERIA_FAILURE: zero thresholds were interpreted as unlimited for a release-grade run` |
| Disable the acceptance-criteria hash comparison against an already generated manifest | `n6-acceptance-criteria` | `N6_ACCEPTANCE_CRITERIA_FAILURE: changed criteria matched a manifest that was not regenerated` |

The criteria file hash at the N6.1 implementation commit is
`e975d7bf7cd69f43880411f04db62dfcd1e52a5c110e63f3248639c3fdfb3cc3`.

### Threshold proposal and criteria-path deviation

`N6-ACCEPTANCE-CRITERIA-PROPOSAL.json` derives review formulas from the
authoritative ConfigParam30 timings, production verifier/query deadlines and
the enforced N5 pending-finality resource bounds. It does not populate the
live criteria and does not use an N6 measurement as the source of a threshold.
Exactly two decision classes remain with the owner: the target release
hardware profile and the headroom fractions applied to the source envelopes.
The hardware profile must name the CPU governor and whether turbo/boost is
enabled, in addition to CPU model, memory, storage and network link. A
throttling governor changes sustained latency and tail variance, so a release
timing claim without that frequency policy cannot be attributed to the code.

Frequency-policy mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Remove `turbo_or_boost_enabled` from the proposed release-hardware profile | `n6-threshold-proposal` | `N6_THRESHOLD_PROPOSAL_FAILURE: release hardware proposal does not pin CPU governor and turbo/boost policy` |
| Omit the observed governor from the diagnostic result | `n6-microbench-results` | `N6_MICROBENCH_RESULTS_FAILURE: CPU affinity/frequency/governor provenance is incomplete` |

The design document names `memo/pq-native/N6-ACCEPTANCE-CRITERIA.json`; the
canonical implementation intentionally lives at
`doc/pq-native/N6-ACCEPTANCE-CRITERIA.json` in this repository. The measurement
manifest pins this repository's Git commit. Keeping its criteria input in the
same repository makes the file content and its SHA-256 reproducible from that
commit; a memo-repository file could not be pinned by the recorded commit. This
is a deliberate design-path deviation, not a second criteria source.

## N6.2 diagnostic feasibility measurement

`N6-MICROBENCH-RESULTS.json` records a Release-build diagnostic run at exact
commit `d1e971eadc4bcc3462be04139b5aca7163123788`. The runner pinned affinity to
CPUs 0-15 and recorded the observed CPU model, frequency and `powersave`
governor without changing either frequency or governor. The result is marked
`DIAGNOSTIC_FEASIBILITY_ONLY`; it is not eligible as release evidence and does
not evaluate the owner's still-unset acceptance thresholds.

Registered gate: `n6-microbench-results` (label `source-guard`). It checks the
measured commit and benchmark-source binding, Release/native-ML-DSA build
identity, host provenance, complete operation and signer matrices, percentile
sample discipline, frozen carrier maximum, and the open worker-pool decision.

The worst expected launch proof measurement is the 100-signer row. Its actual
serialized BlockProof size and single-thread callback stall are facts in the
JSON result; they are not a worker-pool decision. That decision remains
`OPEN_UNTIL_OWNER_ACCEPTS_NONZERO_CRITERIA` and no production offload was made.

Mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Reduce a real single-operation sample count from 10,000 to 99 while retaining its `p99_us` | `n6-microbench-results` | `N6_MICROBENCH_RESULTS_FAILURE: mldsa44_sign claims p99 from only 99 samples` |

## N6.3 diagnostic multi-process cluster scaffold

Implementation commit:

- `9b39d0963` — local and remote-command process backends with one manifest/result format, per-process DB/identity/port/log/trace/resource isolation, live finality tracing, and the release lite-client route.

Registered gates:

- `n6-cluster-runner`
- `n6-live-finality-overlay`
- `n6-lite-framed-tcp`

The live-finality gate starts four PQ Genesis validators and a distinct
non-validator consumer. It accepts evidence only when the same canonical
transport id is sent by one process, received through production Plumtree by a
different process, and reaches the manager's trusted PQ verification-success
point. Payload size, propagation, receiver queueing and verification time are
recorded as separate diagnostic fields. The lite gate invokes the release
`lite-client` and requires a fetched proof to validate through its production
`AdnlExtClient`/`AdnlExtServer` framed-TCP route; RLDP is not substituted.

The remote backend is a caller-supplied command protocol. SSH, cloud
provisioning and artifact staging remain external concerns rather than
consensus-test dependencies. Cross-host propagation requires externally
synchronized clocks; the manifest states that condition, while queueing and
verification use per-process monotonic time.

Mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Delete the manager's successful PQ verification trace | `n6-live-finality-overlay` | `N6_LIVE_FINALITY_OVERLAY_FAILURE: no finality payload crossed from one process through Plumtree to a different process and completed trusted PQ verification` |
| Replace the release client's `AdnlExtClient::create` route | `n6-cluster-runner` | `N6_LITE_FRAMED_TCP_FAILURE: release lite-client no longer uses AdnlExtClient` |

All N6.3 output remains `DIAGNOSTIC_SCAFFOLDING_ONLY`, explicitly ineligible
for release evidence, and makes no consensus-correctness verdict while the
Merkle sequencing diagnosis and parked N5 gaps remain open.

## Evidence boundary

The N6.2 result above is diagnostic feasibility evidence only. No release-grade
measurement, threshold verdict, launch-cap freeze, or Genesis release evidence
has been produced on this branch.
