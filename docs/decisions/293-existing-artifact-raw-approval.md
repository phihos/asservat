# ADR-293 — Existing-artifact raw download approval

Date: 2026-11-03. Status: implementation in progress; no installed qualification.
Requirements: REQ-AUT-002–004, REQ-DLD-002, REQ-INV-002, REQ-SYS-003.

## Decision

Implement the specified `request_raw_access` operation for existing, independently
published raw artifacts. A policy collection grant grants no human disclosure
rights. Reuse the current independent human review, step-up, revocation, encrypted
operation audit, child/use ledger and native download authority ports. The first
composed operation is download_artifact; other declared raw operations remain
refused until their implementations are qualified.

One immutable rawQuery scope binds one case, up to 64 exact artifact IDs and
ciphertext-copy versions, each original capture/action/execution/target, verified
native length and original retained expiry, the requesting human and client,
reason, finite bytes/operations and an absolute deadline at most eight hours from
request. It does not invent a preview, collection grant or common target for
artifacts from different workloads. Current ordinary/raw eligibility and no deny
must hold for every selected target before catalog lookup; the reviewer must be
an independent current approver for every target. Replays preserve the original
selection and deadline. Current retention can only shorten actual use.

Store only the verified native byte count needed for review, never native names
or checksums. Return it from the existing complete verification pass and bind it
into the existing verification record and encrypted audit. There is no second
payload read or key unwrap. A historical NULL remains unknown; it is not zero,
ciphertext size or the configured output limit. Historical audit serialization
and old downloads remain unchanged. Exact-size standalone review of historical
unknown lengths requires a separately qualified metadata recovery path; this
remains an explicit delivery gap rather than a guessed allowance.

Every child names one exact selected artifact and the requesting client. Existing
atomic parent spend charges bytes and operations before disclosure, including
retransmission and uncertain delivery. New approvals do not change an older
grant's counters or broaden collection authority. Reuse a current covering grant
when it covers the exact file, operation, client and budget. Multiple targets do
not inherit authority from the first selected target. Raw sharing remains subject
to its separate reviewed share requirement.

## Complexity assessment

1. The observed gap is deterministic: every policy-produced raw artifact lacks a
   human ad hoc parent and is refused by the installed download path.
2. The maintainer required native downloads and independent raw approval; this
   does not reopen an accepted risk.
3. It serves the specified sensitive opt-in workflow, not default context reads.
4. Reuse the existing Asservat grant/review/transfer design; no novel service or
   external dependency is introduced.
5. Zero new credentials, collector privileges or network endpoints beyond the
   already specified authenticated operation.
6. Zero new lifecycle states; Pending/Approved/Denied/Expired/Revoked and existing
   finite pool exhaustion remain sufficient.
7. Zero configuration switches added for this mechanism.
8. No new external component dependency.
9. One nullable integer per verification row and one bounded scope per grant;
   at most 64 current target/artifact checks per request; zero extra payload reads,
   key requests, watches or background tasks for newly verified sizes.
10. Existing downloads remain available; rollback must refuse retained new grant
    or audited size records rather than discard their authority/provenance.
11. Reusing a policy acquisition grant or guessing output sizes would violate
    the actual requirement. Keeping raw downloads disabled is an incomplete state.

## Required evidence

Tests must cover exact client/version/target membership, multi-target review,
self-approval, raw/ordinary entitlement, original expiry, revocation, concurrent
budget exhaustion and idempotent uncertain spend. Verify native length comes from
successful semantic verification, survives publication unchanged, and never
appears after failed verification. Preserve old audit bytes, NULL semantics and
migration rollback refusal. Finish with installed policy collection followed by
separate human approval and hash-matched native download. None of those installed
claims follows from this decision record or component tests.


## Current component evidence

SQL130 native-length verification and legacy audit compatibility passed real
PostgreSQL/S3 cases (`verified-native-length-2`, Go4.379s, unchanged sources,
cleanup complete); empty upgrade/downgrade passed separately. The initial run
exposed a missing INSERT column grant; the production verifier and fixture now
have only the added `native_bytes` insertion permission, with forbidden-write
regressions. This does not implement standalone raw grants or legacy size recovery.
Canonical raw-query scope hashing stays in C-03 application code, alongside
existing grant digests; domain validation remains a pure typed-value check.
