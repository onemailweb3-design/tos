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

Release mode also consults
`N6-OPEN-CORRECTNESS-QUESTIONS.json` before the N5-closure, dirty-tree and
acceptance-criteria checks.  The registry retains every known question after
resolution: an open entry carries its observation and closure condition, while
a resolved entry must add `resolved_by` evidence rather than disappear.  The
required-id list is cross-checked against the entries, and the initial Merkle
base-state mismatch is also pinned by the manifest code, so deleting its entry
or only one side of the registry fails closed.

The seeded open question records the failure observed at `efd22ce46` in
`validator/consensus/chain-state.cpp:123`: a candidate's state update was
applied to a base root it was not produced against.  It closes only with
run-derived evidence identifying whether production consensus or the fixture
selected the mismatched pair, plus a regression guard for that demonstrated
ordering.  Source inspection alone is not closure evidence.  While it remains
open, RELEASE mode refuses by name with
`release-grade measurement refuses open correctness questions: merkle-base-state-mismatch`.

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
The owner has accepted the nine headroom fractions recorded in the proposal;
their formulas resolve to the proposed timing, utilization and backpressure
limits there. The target release hardware profile remains outstanding.
The hardware profile must name the CPU governor and whether turbo/boost is
enabled, in addition to CPU model, memory, storage and network link. A
throttling governor changes sustained latency and tail variance, so a release
timing claim without that frequency policy cannot be attributed to the code.
The live criteria intentionally retain `OWNER_REVIEW_REQUIRED` and zero
thresholds until that profile is supplied. Accepted fractions alone are not a
complete acceptance contract, so they are not copied piecemeal into the live
file.

Proposal mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Remove `turbo_or_boost_enabled` from the proposed release-hardware profile | `n6-threshold-proposal` | `N6_THRESHOLD_PROPOSAL_FAILURE: release hardware proposal does not pin CPU governor and turbo/boost policy` |
| Omit the observed governor from the diagnostic result | `n6-microbench-results` | `N6_MICROBENCH_RESULTS_FAILURE: CPU affinity/frequency/governor provenance is incomplete` |
| Change the accepted headroom status back to undecided | `n6-threshold-proposal` | `N6_THRESHOLD_PROPOSAL_FAILURE: owner-accepted headroom fractions changed or are not marked accepted` |

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

The accepted authority-classification proposal is 80 ms, derived as one fifth
of the 400 ms target block slot. The committed diagnostic 400-validator memo
miss has p99 `387.511 us` in `N6-MICROBENCH-RESULTS.json`, giving about 206x
margin. (The earlier conversational estimate of about 220 us and 360x is not
the committed result, so it is not used as durable evidence.) This large
margin is a feasibility finding: the proposed launch requirement is
comfortably achievable. It is not permission to tighten the criterion toward
the observed run, which would violate the top-down rule and
`thresholds_moved_to_fit_results`. Nor is it evidence that authority
classification did not regress: a criterion with this margin would still pass
after a hundred-fold slowdown. Launch acceptance criteria decide whether the
release still has its required operating envelope; section 13's regression
detectors must make smaller performance changes visible.

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

## N6 performance-regression smoke

Registered gate: `n6-microbench-smoke` (label `n6-microbench-smoke`). The
branch/PR workflow builds its Release executable before selecting the label
with `--no-tests=error`; it is not a source guard and cannot pass from a
configure-only build.

The smoke subset exercises production ML-DSA signing and verification, 21-
and 100-signer N4 certificate verification, frozen 21/100-signer #13 and
BlockProof BOC sizes, 21-signer #13 verification, and lite SignatureSet
verification. Exact frozen sizes, verifier-boundary operation counts and the
401-signer structural refusal are deterministic failures. Timing uses 100
samples and same-run single-verification normalization; only the configured
large ratios fail, so ordinary scheduler noise and small changes do not turn
ordinary CI red. This is regression evidence, not release acceptance or a
replacement for the dedicated same-machine scheduled benchmark in section
13.2.

The exact-size expectations come directly from the existing frozen
`block-signature-carrier-measurements.tsv` rows rather than a copied smoke
baseline. The smoke baseline contains only operation-count and normalized
large-regression policy.

Mutation evidence:

| Mutation | Outcome |
|---|---|
| Increase frozen `n5_13_boc_21` by one byte | Red: `N6_MICROBENCH_SMOKE_FAILURE: size vector n5_13_boc_21 changed: expected 53788, got 53787` |
| Add one extra ML-DSA verification to every 21-signer #13 verification | Red: `N6_MICROBENCH_SMOKE_FAILURE: operation count drift for proof_verify_21: expected 2100, got 2200` |
| Raise both production 400-signer guards to 401 | Red: `N6_MICROBENCH_SMOKE_FAILURE: structural cap was not enforced: maximum=400 tested=401 refused=False` |
| Increase the 21-signer certificate p95 result by 3% | Green: ordinary small timing movement remains below the configured large-regression ratio |
| Set the normalized 21-signer certificate p95 ratio to 4.0 | Red: `N6_MICROBENCH_SMOKE_FAILURE: large timing regression certificate_verify_21_per_signature_over_single_verify_p95: normalized p95 4.000 exceeds 3.000` |

## Evidence boundary

The N6.2 result above is diagnostic feasibility evidence only. No release-grade
measurement, threshold verdict, launch-cap freeze, or Genesis release evidence
has been produced on this branch.

## Open release-measurement gaps

`N6-OPEN-MEASUREMENT-GAPS.json` is a fail-closed release registry parallel to
the correctness-question registry. Its required ids cannot be removed by
deleting a gap, and a resolved entry must retain `resolved_by` evidence.
Release mode currently refuses both registered gaps by name:

- `release-scale-matrix-unmeasured`: the required 21/32/64/100 matrix remains
  unchanged and unmeasured. This 6-core KVM guest has 11.68 GiB RAM; 21
  colocated validators would reserve about 8.0 GiB for the N5 pending-finality
  budget alone. Closure requires the section 0.5 topology: one validator per
  reviewed host or VM, at the exact N5-complete measured commit.
- `carrier-scale-transport-unmeasured`: closure requires a live overlay run at
  a signer count producing a carrier near the 984260-byte ceiling, retaining
  separate payload, queueing, propagation and verification evidence.

The owner-supplied deployment link is 100 Mbps symmetric. A maximum carrier is
7874080 bits: 78.7 ms at line rate and 157.5 ms after the accepted 0.50 network
headroom. One transmission therefore consumes about 12.1% of the 1300 ms
persisted-finality criterion and 39.4% of the 400 ms target block interval,
before gossip fan-out. This is a launch-relevant measurement requirement, not
a conclusion that the link fails.

The separately named 4-validator tier is minimum BFT (`n = 3f + 1`, `f = 1`).
It can establish protocol path, message flow and carrier transport at the
minimum fault-tolerant configuration. It cannot characterize launch sizing or
network capacity: its roughly ten-kilobyte certificate does not exercise the
984260-byte ceiling, the two admission pools, the 400-carrier validator pool,
or the section 0.11/0.12 scale-cliff question.

Mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Delete an open gap but retain its required id | `n6-manifest-completeness` | `N6_MANIFEST_FAILURE: open measurement gaps reported the wrong release refusal: measurement-gap registry required ids and entries differ` |
| Mark both measurement gaps resolved with `resolved_by` evidence | `n6-manifest-completeness` | `N6_MANIFEST_FAILURE: open measurement gaps reported the wrong release refusal: release-grade measurement refuses commit ...: no N5 closure artifact was supplied for that exact commit` |

## N6.5 scale-sweep instrument

Registered diagnostic gate: `n6-scale-sweep-minimum-bft` (label
`n6-scale-sweep`). It boots the only tier this host can support honestly: four
PQ Genesis validators (`n = 3f + 1`, `f = 1`) plus a distinct non-validator
consumer. The result records the requested and actually booted validator
counts and separately records time to the first proposal, first notarization
certificate and first FinalCert from production consensus trace events.

Latency is not a hidden flag. `no-simulated-latency.json` and
`launch-default.json` are separate inputs retained in the manifest/result.
The local backend refuses a nonzero profile because it cannot apply network
shaping; the launch-default profile requires a remote-command deployment with
external shaping whose backend manifest names the applied profile. Only the
no-simulated-latency 4-validator point is executed here. The 21/32/64/100
release scales, the full section 8.1 cliff matrix, and the launch-default run
remain explicitly unexecuted and release-ineligible.

The runner accepts larger remote scale lists without changing its result
contract. Its fast contract gate drives two distinct requested values through
the actual boot-count argument and checks both reported counts. Fixing the
boot argument to the first scale makes the second point fail with
`N6_SCALE_SWEEP_FAILURE: requested scale 7 booted 4 validators`; this prevents
a list-shaped driver from silently measuring one cluster repeatedly.
The milestone analyzer also requires strict proposal < notarization < FinalCert
ordering. Three fields populated from one event fail with
`proposal, notarization and FinalCert milestones are not distinct`.

An explicit `--allow-local-multi-scale-diagnostic` switch exists only for
instrument validation on a capable development host. It is false by default,
is not used by the registered 4-validator gate, and sets
`local_colocation_diagnostic_override=true` in its result. Such a run remains
ineligible for release evidence and cannot satisfy a required release scale.

This tier proves only minimum-BFT protocol progress, message flow and carrier
transport. It makes no launch-sizing, carrier-ceiling, network-capacity or
consensus-correctness claim, and it does not resolve either open measurement
gap.
