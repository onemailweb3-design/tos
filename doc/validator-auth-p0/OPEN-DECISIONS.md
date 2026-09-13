# Decisions for the two P1 boundaries

Status: resolved as **review-candidate protocol choices**, not frozen or activated.
This replaces the previous open alternatives with one implementable contract.

| Boundary | Chosen rule | Normative source | Executable evidence |
| --- | --- | --- | --- |
| Authenticated pending lifecycle | VATr records in VAI1; one per role/profile, ten per identity; explicit cancel, deterministic due-before-requests apply, immutable old sessions | LIFECYCLE.md; canonical-schema.json | lifecycle.py; test_lifecycle_api.py; lifecycle-api-golden.json; mutations.py |
| Complete signer/client encoding | One ordered binary schema; thin strict JSON transport; 13 typed methods, distinct four authorization types, context permits and journal receipts | API-CONTRACT.md; canonical-schema.json; transport.schema.json | schema-driven reference.py/api.py; golden/negative tests; mutation guards |

No RoleRef validity-field alternative, implicit retire-as-cancel, immediate-only
lifecycle, duplicate inner JSON layout or untyped authorization envelope remains.
Creating a review candidate does not require a protocol freeze and does not itself
approve production allocations. The v1 draft fingerprint changes with these edits.

First principles: election determines membership/weight; key lifecycle determines
which immutable credentials new sessions select; a session commits its own roster,
policy and keys; proof verification uses that committed era. Administrative requests
instead use current inclusion-time authority. Therefore scheduling belongs in
replayable authenticated identity state, not a local signer timer or per-signature
lookup. Signer receipts report irreversible local safety state and cannot replace
chain authorization. Client cursors organize retrieval and cannot replace proofs.

Remaining gates are implementation/approval gates, not alternative wire answers:
review and freeze of proposed allocations and artifact set; native state/BOC/range
proof integration; C++/Rust equivalence; hardware/external witness fencing and
rollback rehearsal; genesis/client/operator approvals; measured production C0 cost;
full testnet transition rehearsals. No PQ suite, network activation, deployment or
historical verifier change is authorized by this document.
