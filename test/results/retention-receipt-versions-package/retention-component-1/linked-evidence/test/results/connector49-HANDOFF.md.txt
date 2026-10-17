# SQL49 connector fast component checkpoint

The immutable `files/` payload has 62 paths; `manifest.json` records each live base SHA-256 (null for new files) and tested payload hash. All seven manually modified live bases still match. Generated custodydb output is supplied for review/compile provenance; regenerate it after integration instead of overwriting concurrent generated changes. No live source was edited and no external service was started by this agent.

Manifest SHA-256: `815df470a9c365809fcf76aa933093e8494bde4d8479488aa5658a6580d3422d`.
Patch SHA-256: `6f9fb7eb1832721e9e0c5b102e685f9b4c9402fc9da4bd6cc23ab71b2aa63ef2`.

## Scope and changed contracts

Production components cover protected complete connector configuration, current Pod/process proof, bounded automatic process replacement, distinct client/server issuance and process-owned keys, actual current activated-leaf registry, six SQL duties, private peer-actor encrypted operation audit, fixed lifecycle views and independently acknowledged backing renewal. Legacy human audit encodings/public tool allowlists stay unchanged. All current source/role/recovery and original deadline checks remain mandatory. Behavioral identity excludes only Backing; complete source identity and backing revision remain current proof.

A stateless per-intent audit adapter handles the exact original already-admitted policy across backing renewal; it does not cache per revision or accept caller policy as SQL authority. Source candidate staging prepays its exact close/promotion, so exhausted ordinary capacity does not strand that candidate. Ordinary admission/signing/serving denies at exhaustion. Exact candidate IDs, original receipts and counters remain bound.

The typed retirement-only attester is distinct from ordinary issuance and rejects conversion to normal current authority. The provisional live-proof retirement coordinator was excluded because it does not solve historical retirement after process death/expiry.

## Required parent integration

1. Apply verified payload after ADR130 qualification, preserving shared changes. Seven modified non-generated bases are pinned in the manifest. No module/library additions.
2. Set the common SQL schema head from 48 to 49 and add exactly five tables to the pristine installation inventory: `connector_identity_root`, `connector_identity_profile`, `connector_identity_process`, `connector_credential_attempt`, `connector_backing_transition`. Regenerate sqlc. No RLS or hidden-history filtering is added to complete-history scans.
3. Merge ADR126/document/spec/catalog indexes as appropriate. Go layer architecture, full repository gates and canonical spec checks were not run on the integrated candidate by this agent.
4. Preserve SQL50 additive shared audit/helper changes over this actual final49 shape. Its old audit-api-v2 snapshot is a dependency baseline, not permission to replace later connector changes.
5. Qualify exact fast selector `TestContextAdmissionWithRealServices/connector-identity-fast` through the parent-owned custody harness. It is called by the narrow additive hook in `test/integration/capture_admission_test.go` after operation audit qualification. No special opt-in switch is required for fast mode. The harness's empty-selection guard must remain enabled.

## SQL roles and native fixture

The fixture creates seven distinct scoped logins: source, journal, acknowledgement, cleanup, verifier, finalizer and read. Protected source acceptance pins the first six actual role OIDs/names/database incarnation. Registry read has only exact leaf RPC. Source performs bounded stage/fence/promote/close; journal admits/stores process/credential/backing records and immutable audit journal data; acknowledgement only acknowledges exact admitted audit; cleanup/verifier/finalizer operate fixed private lifecycle views and purpose RPCs. View SELECT FOR UPDATE uses immutable-key UPDATE privilege, whose mutation is independently guarded. Detailed exact GRANT lists are in the new helper; no shared runtime-role fixture changed.

Fast fixture uses actual SQL/S3 encrypted pair writes, SQL admission/role/view checks, audit acknowledgement, leaf activation and backing continuation. Protected source/Pod/backend qualification and initial trust facts are explicitly synthetic; certificate signatures use a local test CA. It is neither native Kubernetes attestation nor actual OpenBao issuer/runtime/installation proof.

It tests leaf continuity and original process bytes after backing renewal; the next signing is the second permitted attempt in the initial period, not the timed thirty-minute renewal. It also tests final prepaid candidate close/promotion under exhausted transition backing, stale/changed source denial, private/human row isolation, wrong duty/base subquery/immutable key/INSERT RETURNING/SET ROLE/definer denials, and a bounded lock wait. These runtime tests are prepared but UNRUN. PostgreSQL parser acceptance is not PL/pgSQL runtime acceptance or measured private backing cost.

## Actual verification

`evidence/fast-final-checks.json` contains exact commands and terminal exit codes. Environment was GOMAXPROCS=2, -p2, explicit spacious TMPDIR. All 62 source hashes match before/after and the payload.

- Seven affected package race suites: exit0 (domain audit/fleet, application audit/fleet, mTLS, KMS, PostgreSQL).
- Focused Kubernetes `^TestConnector` race: exit0 (cached, exact source hash unchanged).
- Integration-source compile `-run '^$'`: exit0; no native fixture ran.
- Ten affected package vet: exit0.
- sqlc generation: exit0 before final tests.
- Shortened-source-deadline regression failed before (Finish used the old five-second interval after Store); fixed retained context/post-Store check passed in the final fleet race. Other retained before/after evidence covers backing identity and accepted replay.

## Explicit gaps and next task

There is no runtime enablement: no complete connector listener/bootstrap/role/provider installation composition, independent measured backend row/WAL/history qualification, or complete finite connector retirement. Distinct prepaid restrictive tickets, successor reservation before backing promotion, irreversible cohort/source/profile/root cleanup and exact original writer/possible-leaf/history verification remain to implement in a separately guarded follow-up. Current six-role views supply reused lifecycle components; the fast fixture does not execute final physical cleanup.

The 31-minute test `TestContextAdmissionWithRealServices/connector-identity-real-time-retirement` and `ASSERVAT_CONNECTOR_RETIREMENT_REALTIME=1` are agreed but NOT implemented/run in this payload. Do not integrate the parent's opt-in long harness as a passing feature. Its prepared v2 harness requires both exact Go subtest duration and monotonic process wall time >=1860 seconds; the eventual fixture must preserve actual minimum product periods and original dates. No backdating or compressed clocks.

Next: parent integrates ADR130 then49 and runs the fast real SQL/S3 matrix; this agent continues separate prepaid retirement tickets and native long-case source based on the frozen62 hashes. Ordinary removal of the final cluster must preserve a reusable logical root. Permanent minimized root tombstone is reserved for explicit installation teardown. The existing bounded context native exchange still has five-second conversation observations; no large-file readiness is implied.
