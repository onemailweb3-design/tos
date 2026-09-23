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

Branch CI also configures, but does not build, the repository and runs the
complete `source-guard` label. The inventory checker requires the exact 22
guard ids before CTest runs; `--no-tests=error` remains as the independent
empty-selection check. Labels live beside each test registration. This now
includes `n6-cluster-runner`, `pq-finality-boundary-source`, and
`consensus-no-fallback`, which are configure-only checks that previously ran
only as part of the main-only full CTest workflow. Removing one label makes
the inventory fail naming the missing guard, rather than allowing the other
21 to hide its absence.

A separate branch workflow builds only the native artifacts required by the
Python fixtures, runs the complete Python suite, and boots
`test/integration/test_basic.py` with four PQ validators on every push and pull
request. This is intentionally independent of the main-only full native build:
the classical-descriptor refusal introduced on 2026-09-20 made every existing
chain fixture unable to form a validator group, and branch CI reported nothing
until a manual N6 run exposed it. The workflow comment and
`branch-chain-python-ci-source` guard pin the unrestricted branch triggers,
generated TL API, full pytest invocation, required native targets, and real
PQ-chain invocation so that coverage cannot silently return to main-only.

The first cold branch-chain run at `5d69c798c` spent 2,323 seconds in the
native fixture build and 2,553 seconds overall. The next run at `46b76fde7`
restored the 32 MiB object cache: step 7 fell to 755 seconds and the total to
about 950 seconds. Its post-build statistics reported 464/464 cacheable calls,
464 direct hits and zero misses. The remaining warm-build cost is therefore
the non-compiler portion of the 1,143-edge graph (generation, archives and
links), not a production-build cache-key defect. The cache key intentionally
includes the Git SHA and reuses prior data through its prefix restore, so each
push adds a new roughly 32 MiB immutable entry to the repository cache budget.

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
required-id list is cross-checked against the entries, and all currently open
questions are also pinned by the manifest code, so deleting an entry or only
one side of the registry fails closed.

The seeded open question records the failure observed at `efd22ce46` in
`validator/consensus/chain-state.cpp:123`: a candidate's state update was
applied to a base root it was not produced against.  It closes only with
run-derived evidence identifying whether production consensus or the fixture
selected the mismatched pair, plus a regression guard for that demonstrated
ordering.  Source inspection alone is not closure evidence.  While it remains
open, RELEASE mode refuses it by name.

The second open question records an execution-coverage gap uncovered while
moving the wallet regression to the PQ path. Sixteen E2E scripts contain 17
calls to `make_initial_validator()`. A direct two-validator reproduction shows
the manager refusing their classical descriptors, disabling validation and
reporting `Validating 0 groups`; the chain never reaches masterchain seqno 1.
No branch CI job boots a chain: `build-tos-linux-x86-64-shared.yml` declares
`on.push.branches: [main]`, while `tosctl-service.yml` declares
`jobs.real-chain-explorer.if: github.event_name == 'workflow_dispatch'`
(observed skipped on run `35748202781`). Thus branch CI did not expose this
state.
The affected inventory is:

- `test/integration/test_simplex2_release.py`;
- `scripts/localnet-jsonrpc.py` (and therefore its TOSCAN consumer);
- `scripts/agent-wallet-account-e2e.py`, `agent-query-api-e2e.py`,
  `agent-chain-index-e2e.py`, `agent-task-escrow-e2e.py`,
  `agent-economy-composed-e2e.py`;
- `scripts/proof-attestation-e2e.py`, `capability-registry-e2e.py`,
  `dispute-e2e.py`, `service-actor-e2e.py`, `wc0-token-index-e2e.py`;
- `scripts/validator-election-stage-a.py`, `dns-e2e.py`, and
  `nominator-pool-lifecycle-e2e.py`.

Recommended disposition: first classify each entry as retained or retired.
Then make every retained path consume one shared deterministic PQ
initial-validator helper and execute each advertised route against a real PQ
chain in branch CI. Retired scripts must be removed from release claims and
entry-point inventories. This unit registers that work; it does not perform 16
independent conversions before ownership and retained scope are decided.

A third open correctness question inventories the classical stake-production
surface instead of treating the two base Fift files as orphaned. The inventory
includes those two files, the `validator-elect-req>B` library word,
`test-smartcont.cpp`, two validator-proposal Fift tests, the nominator-pool and
validator-election Python flows, both pool operator scripts, and tosctl's
election daemon, interactive bid command, and config-wallet pool command.
These consumers make deleting the
base tools in isolation an invalid retirement.

Pooled staking remains in the launch set through `single-nominator-pool`. Its
contract already relays stake through the controller and parses the PQ
authorization shape; its stale operator script must be converted to consume
`engine.validator.createPqStakeAuthorization`. In contrast,
`liquid-staking/controller.func` still submits classical `new_stake` directly
and handles the elector reply itself. The liquid-staking directory is therefore
not launch-supported and must be absent from release claims and entry-point
inventories until that contract-level conversion is complete. The converted
single-nominator contract is the worked example for that future work. The
registry's closure condition also pins the local tosctl signature-length
refusal, both tosctl producer conversions, and the rule that common Fift tools
cannot be removed until every retained caller and `test-smartcont.cpp` move in
the same change.

## Open diagnostic observations

`N6-OPEN-DIAGNOSTIC-OBSERVATIONS.json` records operational findings that need
causal diagnosis but are not, by themselves, release correctness refusals. Its
required ids are also compiled into `n6-diagnostic-observations`, so deleting
both an entry and its JSON-side required id cannot silently erase it. A
resolved entry remains present and must name `resolved_by` evidence.

The initial open entry records repeated unanswered lite-server queries in the
co-located four-validator PQ functional run. The client deadline is 10 seconds
at `toslib/toslib/ExtClient.cpp:69`; observed retries include both
`get_masterchain_info` and `lookup_block`, on node-1 and node-2 across runs.
The entry deliberately makes no claim about which endpoint or code change is
responsible. Closure requires one query identity traced through client send,
server receipt, response send and client completion, followed by a regression
gate for the demonstrated cause. A longer timeout or a successful retry does
not close it.

The second entry records the first five-minute steady-state PQ Simplex
observation at the enforced 21-validator launch committee size. On one
co-located host it produced 733 blocks in 314 seconds, all 22 queried nodes
agreed full block ids through height 746, cadence p50 was 399.1 ms against the
400 ms target, p95 was 500.2 ms, and no lite query retried. Safety held, but
seven observation intervals lasted 1.3--2.3 seconds. Validator logs contained
`SkipVote` text, but the earlier claim that three of seven intervals were near
node2 skip bursts is withdrawn. That count mixed 951 basechain lines with 187
masterchain lines while the sustained observer measures masterchain cadence;
it correlated different chains.

A follow-up at `82f2e8134` produced 746 blocks, two roughly 1.4-second slow
intervals, unanimous full block ids through height 759, and 576 masterchain
`SkipVote` text lines. Its structured event stream contained no skip-class
event and the first analyser incorrectly returned `analysis_available=true`
with zero runs. Absence from a channel that has not demonstrated the event is
not evidence of zero. The analyser now reports this state as unavailable and
names the missing structured event types. The slow-interval/skip-run relation
remains unattributed and unmeasured; co-location remains a caveat rather than
a diagnosis.

This observation is relevant to the release criteria's tail-latency bounds,
even though the sustained-finality measurement gap was closed separately by
the inherited-Simplex evidence. It remains diagnostic: one co-located run is
not release-grade persisted-finality p99, and upstream inheritance does not
explain behavior of the new N5 carrier or admission machinery.

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
limits there. The hardware item is now a provisioning requirement rather than
an unspecified owner choice: 21 bare-metal hosts, one validator per host, each
with at least 8 physical cores, 16 GiB RAM, a 1 Gbps link and NVMe storage,
using the `performance` governor with turbo/boost disabled. The actual CPU
model is recorded when the hosts exist.

The released 6-core, 11.68 GiB KVM server with a 100 Mbps symmetric link is not
a release-measurement candidate. A guest cannot truthfully observe the host's
governor or turbo/boost state, so its timings cannot satisfy the attribution
contract regardless of its other resources. The owner therefore has three
explicit paths: provision the 21 bare-metal hosts demanded by the current
criteria; deliberately change the scale criterion with written,
machine-enforced extrapolation; or use VMs only for diagnostic evidence. Calling
VM measurements release evidence is not an available path. The live criteria
intentionally retain `OWNER_REVIEW_REQUIRED` and zero thresholds until real
hosts exist and all six profile fields are recorded together.

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
Merkle sequencing diagnosis, classical-E2E disposition, and parked N5 gaps
remain open.

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

## Release-measurement gap disposition

The required release scale is now `[21]`, matching the enforced launch ceiling
rather than an owner preference. The ceiling is fail-closed at all four
committee-forming boundaries: ConfigParam16 and ConfigParam28 updates in
`crypto/smartcont/config-code.fc`, node configuration admission through
`Config::validate_pq_launch_resource_config` in `crypto/block/mc-config.cpp`
and `validator/manager.cpp`, production Genesis in
`crypto/smartcont/gen-zerostate.fif`, and tostester Genesis in
`test/tostester/src/tostester/zerostate.py`. This narrowing also rests on the
inherited-consensus premise: `git ls-tree -r 628506c9e` shows 16 files already
under `validator/consensus/simplex/` at the fork point, and the reviewed
upstream production committee is approximately 400 validators. This premise
was checked against the tree because an earlier review assertion incorrectly
treated Simplex as project-local.

`N6-OPEN-MEASUREMENT-GAPS.json` is a fail-closed release registry parallel to
the correctness-question registry. Its required ids cannot be removed by
deleting a gap, and each resolved entry retains `resolved_by`, its fork-point
evidence, the three facts on which it depends, and gap-specific arithmetic.
All three are resolved by the documented inherited-consensus outcome rather
than by the co-located diagnostic runs:

- `release-scale-matrix-unmeasured`: resolved because inherited Simplex runs
  upstream at approximately 400 real validators, while every committee-forming
  path here rejects more than 21. The reachable scale is about one nineteenth
  of the inherited production deployment.
- `carrier-scale-transport-unmeasured`: resolved because 21 ML-DSA-44
  signatures occupy 50820 bytes, 1.99 times the 25600 signature bytes in a
  400-validator Ed25519 certificate carried by the same inherited transport.
  The 984260-byte 400-signer structural ceiling is unreachable at launch.
- `sustained-finality-distribution-unmeasured`: resolved because steady-state
  Simplex is the inherited upstream operating condition and reachable PQ
  verification is about 1419.6 microseconds per round, 0.12 times the roughly
  12000 microseconds for 400 upstream Ed25519 verifications. The cold-start
  sweep still does not itself produce a p99 distribution; it is simply not the
  evidence used for this closure.

Every closure explicitly depends on: TON's current production consensus being
Simplex, its production committee remaining approximately 400, and the TOS
launch cap remaining enforced at 21. The manifest validator checks those
recorded dependencies and the gap-specific arithmetic. If any premise changes,
the registry must be reopened rather than silently reusing this conclusion.

The historical 200-to-300 cliff is closed as section 0.12 Outcome B. Its cause
class is the old single-process harness: the table predates the later lifecycle
and backpressure work and N5, while the same inherited Simplex operates at
approximately 400 validators in production. The enforced 21 cap is below that
historical region at ConfigParam16, ConfigParam28, node admission and Genesis,
so the harness cliff is neither reachable launch configuration nor evidence of
a protocol cliff.

This inherited evidence has a strict boundary. It says nothing about the new
N5 pending-finality carrier/admission/cache machinery: the 409452160-byte
retention budget, pool split, per-sender rules, deadline and attempt tokens
remain project-local. It also does not answer the open
`merkle-base-state-mismatch` correctness question, which remains registered and
release-blocking.

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
| Close the release-scale gap with a result carrying `local_colocation_diagnostic_override=true` | `n6-manifest-completeness` | `N6_MANIFEST_FAILURE: co-located release-scale evidence reported the wrong refusal: release-scale-matrix-unmeasured cannot be resolved by local_colocation_diagnostic_override evidence` |
| Cite a result with the override false but diagnostic eligibility | `n6-manifest-completeness` | `N6_MANIFEST_FAILURE: diagnostic release-scale evidence reported the wrong refusal: release-scale-matrix-unmeasured evidence is not release_evidence_eligible` |
| Change an inherited closure's enforced-cap dependency from 21 to 22 | `n6-manifest-completeness` | `carrier-scale-transport-unmeasured does not pin the inherited Simplex dependencies` |
| Keep all three inherited closures intact | `n6-manifest-completeness` | The measurement-gap refusal disappears and the independent next refusal is `no N5 closure artifact was supplied for that exact commit` |

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
no-simulated-latency 4-validator point is executed here. The 21-validator
release point, the historical section 8.1 cliff matrix, and the launch-default run
remain explicitly unexecuted by this harness. Their absence is not hidden by
the inherited-evidence disposition above.

The runner accepts larger remote scale lists without changing its result
contract. The registered `n6-scale-sweep-cardinality` source guard drives two
distinct requested values through the actual boot-count argument and checks
both requested and reported counts. Fixing the boot argument to the first
scale makes the second point fail with
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
That statement remains enforced for the measured-result closure path: if a
result is cited to resolve `release-scale-matrix-unmeasured`, the manifest
validator rejects any result carrying the override before considering its
scale list. A result without the override must still declare release
eligibility and cover exactly the enforced scale 21. The live registry instead
uses the separately reviewed inherited-Simplex closure and cites no co-located
result.

Instrument-validation evidence was collected from a clean worktree at exact
commit `e7f1106c1`; it remains diagnostic, co-located and ineligible for release
evidence. It is recorded only to prove that the sweep argument controls the
booted topology:

| Requested validators | Actual processes | Unique ADNL identities | Unique ports | First proposal | First notarization | First FinalCert |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 6 (DHT + 4 validators + verifier) | 5 | 15 (`34002`-`34016`) | 5269.975 ms | 5299.334 ms | 5304.140 ms |
| 7 | 9 (DHT + 7 validators + verifier) | 8 | 24 (`35002`-`35025`) | 5283.550 ms | 5346.614 ms | 5352.426 ms |

The two runs had zero ADNL-identity intersection and zero port intersection.
Their milestone rows differ, and each row is strictly ordered. Fixing the
driver's boot argument to the first requested scale makes the fast gate fail
on the second point with `requested scale 7 booted 4 validators`.

This tier proves only minimum-BFT protocol progress, message flow and carrier
transport. It makes no launch-sizing, carrier-ceiling, network-capacity or
consensus-correctness claim, and it is not the evidence used to resolve any of
the three retained measurement-gap entries. In particular, its three
milestones describe one cold-start sequence and are not a sustained-operation
latency distribution.

## Sustained co-located consensus observation

`pq-n6-cluster.py --scenario sustained-consensus` keeps the real PQ Genesis
cluster alive for exactly one configured bound: `--sustain-blocks` or
`--sustain-seconds`. The interval threshold is the Genesis masterchain target
block rate multiplied by the explicitly recorded `--slow-interval-factor`
(default 3.0); a mismatch between the observer's target and Genesis is refused.

Height alone is not accepted as agreement. Height 0 is pinned to the unique
zerostate `BlockIdExt` supplied to every node by the common launch
configuration. For every produced masterchain height from 1 through the final
common height, the observer asks every node's own lite-server for the full
block id and fails immediately if root or file hashes differ. The result
retains the agreed id per height, every node's final height, the exact
observer-detection interval for every newly agreed height, min/p50/p95/max of
those observation intervals, and every observation interval individually
exceeding the stated threshold. These are polling observations, not block
generation timestamps; multiple already-produced heights can therefore yield
a very short observed interval.
Thus nodes at equal seqno on different chains cannot satisfy the mode, and a
node that stops following remains visible in `per_node_final_height`.

Each node's lite query has a 30-second transport retry budget. Only the exact
`toslib.toslibjson.ToslibError` shape with code 500 and a
`LITE_SERVER_NETWORK...` message is retried. Exhaustion fails as
`N6_SUSTAINED_TRANSPORT_FAILURE`, naming the silent node and operation;
non-transport exceptions propagate immediately. The retry is below the block
comparison, so a completed query that exposes different full block ids fails
immediately and is never retried. The gate covers one transient recovery,
persistent named transport exhaustion, a non-transport `ValueError` with one
call, and a disagreement with exactly one lookup per node.

The sustained result records `lite_transport_retries.total` and
`lite_transport_retries.per_node_operation` for `get_masterchain_info` and
`lookup_block`, including explicit zeroes for nodes with no retry. This makes a
passing but degraded observation distinguishable from a clean one. A
dependency-backed pytest constructs `toslib.toslibjson.ToslibError` from the
generated `tosapi.toslib_api.Error` type and pins both status code 500 and the
`LITE_SERVER_NETWORK` prefix; the source-only stand-in remains limited to
testing retry-loop sequencing.

The cluster result separately records `startup_lite_transport_retries` for the
initial all-node climb, so recovery before the sustained window is not hidden.
The observation-interval distribution repeats its own retry total and an
`includes_catch_up_after_transport_retry` flag. When that flag is true, short
intervals can be backlog replay after a silent lite-server recovers and must
not be read as block-production cadence. The flag counts only retries after
the interval window starts; retries while establishing the starting height or
checking historical block ids remain in the overall total but cannot
mislabel the later distribution. A production diagnostic run first
made this distinction observable: one node retried once after roughly ten
seconds, while the chain advanced 26 heights and the observer later replayed
the backlog at millisecond-scale observation intervals.

After the observation window, the harness waits for the production
`TraceCollector`'s five-second structured-log flush and reads every node's
`consensus.stats.events`. It retains per-node skip-vote counts rather than an
average, groups the union of session-local skipped slots into consecutive
runs, and records every slot and its scheduled leader. Candidate-received plus
block-accepted events map each masterchain height to the Simplex slot that
actually advanced it; every observation interval can therefore state whether
the intervening slots contain a skip run. The source-only gate includes a slow
interval with a run, a slow interval without one, and a run during a non-slow
interval, preventing either an always-true correlation or an explanation that
silently assigns every tail event to skipping.

If no skip-class event appears anywhere in the validator batches, the result
sets `analysis_available=false`, `run_count=null`, per-node counts to null and
every interval's coincidence value to null. It does not report a measured
zero. This is necessary because a run without skips and a telemetry path that
drops skips are otherwise observationally identical.

This is `COLOCATED_DIAGNOSTIC_ONLY` evidence with
`release_evidence_eligible=false`. Its observation intervals measure when all colocated
nodes expose the agreed block; they are not persisted-finality p99 and do not
resolve the open Merkle correctness question. The registered
`n6-cluster-runner` gate supplies both a positive same-block control and a
forked node at height 7. Removing the full-block-id comparison makes the gate
fail with `nodes on different masterchain blocks were reported as agreeing`.
It also pins per-node final heights, the interval distribution, and the
individual slow-interval record rather than accepting an average.

## Four-validator sustained functional regression

The existing `test/integration/test_basic.py` remains the single wallet
functional regression rather than being forked for N6. Its committee size and
sustained window are now explicit inputs, defaulting to four PQ validators and
ten additional masterchain blocks. The default invocation remains in the
native integration workflow and exercises wallet deployment/transfer, the
destination balance change, source-wallet seqno advancement, and validator
actor statistics and performance counters before entering the sustained
observer above.

The runner refuses committee sizes outside 4..21, verifies that the requested
size controls both the created node count and Genesis shard committee size,
and emits the same full-block-id agreement and per-node progress evidence for
the sustained window. A local default run booted four requested validators,
completed the wallet assertions, produced ten additional masterchain blocks,
and left all four nodes at the same final height with full block-id agreement
at every height checked. This is `COLOCATED_DIAGNOSTIC_ONLY` functional
coverage and is explicitly ineligible for release evidence; it neither closes
the open Merkle question nor substitutes for independent-host measurements.
