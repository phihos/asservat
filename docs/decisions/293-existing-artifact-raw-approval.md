# ADR-293 — Existing-artifact raw download approval

Date: 2026-11-03. Status: native download implemented and installed-qualified on `af8d2b07`
(Native41673309250); other raw operations remain unimplemented.
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
regressions. The subsequent SQL131 implementation below composes standalone raw grants;
legacy size recovery remains pending.
Canonical raw-query scope hashing stays in C-03 application code, alongside
existing grant digests; domain validation remains a pure typed-value check.

## Bounded public review

The existing-artifact request keeps the canonical future raw-operation enum;
only `download_artifact` is executable now, with an explicit unsupported-operation
reply for other selections. Both selectors require at least one unique entry.
The existing fixed 10,000-operation ceiling is visible in review, with no new
user setting. Historical unknown native lengths remain unselectable.

`get_grant` alone uses a 256 KiB response allowance in both browser and MCP so
one review can retain all 64 exact artifacts without pagination or omitting
approval facts. All other operation limits remain unchanged. With existing
identity and DNS-name bounds, 64 maximal ASCII artifact rows measured 93,121
bytes; HTML-escaped opaque UIDs raised those rows to 154,561 bytes. A generated
browser-contract regression including long requester/reviewer identities,
reason and per-artifact values measured 233,239 bytes and passed the actual
browser client; a response above 256 KiB is refused. These are synthetic
serialization and client checks, not installed workflow qualification. No extra
API read, worker, watch, service, permission or configuration is introduced.


SQL131 component qualification (`existing-raw-grants-1`) passed raw-request
idempotency, exact selected membership, concurrent bounded spend, unchanged
original uses after replacement approval, real NULL parent targets, the 1 TiB
pool and rollback refusal (4.36s). Existing collection approval/child behavior
also passed (5.94s), as did empty SQL131 upgrade/downgrade (3.65s). The combined
command failed only the separate policy-companion fixture's stale assessment
identity; source hashes were unchanged and cleanup complete. Its corrected
fixture awaits a focused rerun. An actual TLS/Go SDK 64-artifact review passed
with 99,005 canonical bytes and a 218,810-byte duplicated MCP frame, preserving
every exact identity, size and label. The escaped browser stress case above
measures serialization capacity, not domain acceptance of every synthetic UID.


The focused composed rerun `existing-raw-grants-2` passed (Go10.921s, unchanged
sources, complete cleanup), including policy argument admission/preparation and
raw ledger replay/concurrent spend. Legacy covering-grant reuse now requires one
remaining operation per selected file and adequate distinct-artifact capacity.
If remaining artifact slots are insufficient, one bounded SQL aggregate counts
only the selected (at most64) already registered artifacts across reviewed
clients. Existing tables, indexes and SELECT permissions suffice.

Fresh Download preparation uses already verified native length to check full-file
coverage and returns a typed missing-approval result only after ordinary rights
and dependency checks succeed. The console opens the existing review prefilled
with that exact artifact and size; approval retries retain the original request.
Existing sessions and in-flight transfers retain their original accounting and
revalidation behavior. This adds no metadata/payload read or API request.

## Native transfer accounting

Every qualified raw-only format in the existing native registry reserves its
window bytes in the shared grant pool before content read: raw PCAP, syscall
arguments, pprof and Go trace. Metadata preparation retains its one-operation
charge. The installed argument regression exposed an earlier PCAP-only format
check in response transfer; transfer-level tests now exercise every current raw
format, two-window totals, denied/missing reservation ports and ordinary approved
formats. The registry lookup adds one local bounded lookup per response; no new
permission, SQL state, service, request, watch or configuration is introduced.
