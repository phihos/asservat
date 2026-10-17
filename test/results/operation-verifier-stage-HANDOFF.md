# Frozen migration48 / ADR125 handoff

Payload: `package/`, 18 guarded source paths, based on integrated live47.
Patch: `migration48.patch` SHA-256 `e3f858e7f326daeb9810e15f246d29a4ead1405e236a7b5cd8b16c17d34003f7`.
Manifest: `manifest.json` SHA-256 `3cd51fb82b24c09c83bc76e5d72e7a0fb92a80dd06620226bcadd6e251571645`.
Qualification: `qualification.json` SHA-256 `b7da85def528d624a7e524ce147648d71652343e5ac821eec7e84f6083d076d2`.
All existing base hashes matched the live tree at final packaging. No live source
was edited and no external/native fixture was run by this agent. Source is frozen.

## Result and contract

Independent certificate verification spends one of two durable attempts before
GET/unwrap. The returned original deadline caps provider work and acknowledgement;
unknown claim replies authorize no I/O and remain spent. The acknowledgement role
alone can increment; producer/cleanup/finalizer cannot reset or acquire attempts.

New healthy admission requires explicit accepted `operation-audit-history/v3`,
including H=0. It reserves21 fixed plus3 per finite purge lease transitions, two
residual generations and qualified footprint/copies for all pool slots. Existing
nil/v1/v2 bindings stay readable, with a conservative constant default2 counter;
no original binding/date is rewritten or historical attempt reissued. Already
acknowledged history still retires through its existing terminal path. Normal
cleanup rejects unsupported unacknowledged history before original purge or
certificate creation; explicit overdue-original reconciliation remains separate.

Current accepted v3 resource coverage can monotonically cover recognized old
profiles. Common root/lane/install/store/backup identity/digest/horizon/max-leases/
overdue mode must match; qualified row/WAL footprint and copies cannot decrease.
This is not migration/source-derived acceptance and never upgrades old records.
No new table, key service, scheduler, public wire or runtime enablement is added.

## Evidence

- `sqlc-final`: exit 0, 0.157s.
- `final-race`: exit 0, 3.976s.
- `integration-final-compile`: exit 0, 12.469s.
- `final-vet`: exit 0, 3.284s.

`evidence/before.log` is the original meaningful exit1 regression:8 verifier
calls/8 acknowledgement failures/0 durable claims. The corrected allowance tests
include unknown claim, provider failure, original deadlines and cancellation.
`historical-before.log` separately failed before the early guard: normal cleanup
selected original purge and a doomed certificate claim on unsupported history.
`historical-after.log` passes under race, preserving acknowledged terminal cleanup.
Final checks include the current early guard and all final fixture changes.

Peer read-only SQL review found no new lock/accounting defect. Original recovery
and post-lock clock fences remain; no SQL48 effect accepts historical incarnation
as current recovery. sqlc checks SQL shapes, not full PL/pgSQL execution.

## Native source, unrun

The existing selected `TestContextAdmissionWithRealServices` owns all additions:
- `operation-audit-verifier-migration-preserves-history-and-spend`: a separate
  owned scratch database executes actual migrations1..47, inserts synthetic
  historical nil/v1/v2 records under active guards, then applies48. Tests spent
  backfill, each footprint/copy reduction, unknown layouts, insufficient backing,
  explicit covering v3 acceptance and pre48 acknowledged terminal cleanup. No
  trigger disablement or harness downgrade. Synthetic receipts are SQL
  compatibility evidence only.
- Existing healthy lifecycle cases use explicit v3 qualification and actual
  encrypted S3 certificates. They add two concurrent claims/denied third,
  committed-but-hidden claim reply, actual verifier failure, acknowledgement
  without claim, role/trigger boundaries and original recovery expiry after an
  observed blocking pool lock. No extra object/certificate allowance is created.
- Existing overdue cases now use explicitly accepted v3 fixture qualification;
  their original cleanup and proof dates are unchanged.

Recommend selecting the new migration subtest first, then the full custody suite
and required initial/recovery checks with parent source/hash/cleanup discipline.
The scratch case adds roughly14s of actual lifecycle waiting; this is not a
measured completed native duration. Aggregate600s already reserved by parent
remains separate from all unchanged individual authority/retention intervals.

## Integration

Apply manifest-verified sources, then regenerate all sqlc outputs. Generated
files in `sql-work/` are overlay dependencies, intentionally excluded. Shared
changes are custody.go schema47→48 and one appended fixture-role grant; no table
inventory change (preserve parent's corrected sorted inventory). Parent owns ADR
index, progress and full repository gates/native qualification.

Protected accepted policy/qualification/provider IAM, historical unknown-work
reconciliation and independently qualified restart/restore bridging remain
required. Ordinary intent/outcome lookup retries are a separate existing
bounded-interval path; this correction qualifies certificate verifier attempts.

## Files

- `docs/architecture/operation-audit-lifecycle.md`
- `docs/decisions/125-prepaid-operation-certificate-verification.md`
- `internal/adapters/postgres/custody.go`
- `internal/adapters/postgres/operation_audit.go`
- `internal/adapters/postgres/operation_lifecycle.go`
- `internal/application/audit/operation_lifecycle.go`
- `internal/application/audit/operation_lifecycle_test.go`
- `internal/application/audit/operation_verification_budget_test.go`
- `internal/domain/audit/operation_lifecycle.go`
- `internal/domain/audit/operation_verification_test.go`
- `internal/transport/presentation/operation_audit_healthy_test.go`
- `migrations/00048_operation_certificate_verification.sql`
- `migrations/queries/operation_audit_lifecycle.sql`
- `test/fixtures/sql/runtime-roles.sql`
- `test/integration/operation_audit_lifecycle_test.go`
- `test/integration/operation_audit_overdue_test.go`
- `test/integration/operation_verification_budget_test.go`
- `test/integration/operation_verification_migration_test.go`
