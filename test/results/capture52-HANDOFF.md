# ADR132 / SQL52 capture-intent lifecycle

Frozen source-only implementation based on the actually integrated and native-qualified SQL51. Public collection is still disabled. No SQL52 external fixture has run. Parent owns reviewed application, shared generation, native labs and runtime composition.

## Scope and contracts

- Atomic optional new admission protocol: `NewAuditedContextAdmissions` takes the private MAC and protected per-allocation backing; accepted capture, custody/control charge and capture-lane encrypted audit pair reserve in one transaction. Legacy captures never gain this protocol. Configured backing cannot be bypassed by the legacy constructor.
- Eight purpose-pinned SQL roles; three bounded tables (`capture_audit_root`, `capture_audit_allocation`, `capture_audit_binding`), immutable `context_capture.intent_operation_id`, qualified `capture-intent-history/v1`. Final table inventory91/head52. Private filtered views are not new charged rows.
- One irreversible acknowledged PUT claim per phase; two prepaid reconciliation reads per phase with four immutable cutoffs. Original RequestUntil/WriteUntil, role separation, positive actual joined completion and conservative unknown spend remain binding.
- The new private framing retains the actual human actor, at most8KiB minimized payload,16/24KiB encoded intent/outcome and64KiB ciphertext per object. No legacy bytes/limits change. Capture completion digest uses the explicit `asservat-capture-completion/v1`/NUL/phase/NUL/typed-no-HTML-JSON encoding; both value and decoded-pointer paths share it. SQL rejects zero completion/ciphertext digests.
- Reuses41/44/48 qualified deletion, independent verification, explicit overdue branch and delayed-H cooling. A rollback after operation→history transfer restores every original charge/dependency; concurrent finalizers release once; a different unknown same-account writer remains charged. Context/execution/idempotency metadata is not deleted/refunded.
- `CaptureOperationPublication` now requires `RootID` and `Completed CaptureOperationIntentReader`. `postgres.NewCaptureOperationIntents(ctx, readPool, root)` is the separate exact passive reader. It validates new-protocol ID, original minimized digest, timestamp/state and operation-intent receipt from retained acceptance, before any active writer/journal dependency. Fully complete reuse works after original audit WriteUntil and after qualified pair retirement, without KMS/GET/PUT/claims/ack effects. Malformed/failed reads never fall through. Historical provenance is not current collection or disclosure authority.
- First-profile capability/lookup/bridge is already integrated by the preceding14-path package. This package does not enable a route or invent regional transport. Console agent owns explicit fresh-current same-key continuation. Pending writes retain immutable cutoffs; complete acknowledgement reuse does not depend on audit write freshness.

## Verification actually completed

All commands use GOMAXPROCS=2, GOFLAGS=-p=2, TMPDIR=/home/phil/.cache/asservat-build/tmp; Go sees the sparse `overlay.json`, including the exact new embedded SQL52 file and actual live SQL51.

- Exact SQLc v1.31.1 generation51+52: exit0 (`logs/sqlc-passive51-52.log`).44 generated files compared byte-for-byte with the final candidate bindings.
- Full affected races over domain/audit, application/audit, objectstore/framed, objectstore and postgres:56458 exit0 (`logs/passive51-52-race.log`). Both migration-bundle tests plus existing connector and processing cases pass.
- Latest integration helper compilation:80394 exit0 (`logs/passive51-52-integration-compile.log`). This includes all final native regression sources, not an older helper snapshot.
- Six affected packages including integration pass vet:83468 exit0 (`logs/passive51-52-vet.log`).
- Actual Go embedded bundle test48384 exit0: head52 digest `eeac831739ef12bff1d88427ef4c0751b78684f81e7d527d57b1ced2fd7eb32b` (`logs/passive51-52-embedded-digest.log`).
- Unchanged Go architecture checker with file reads honoring the same sparse overlay: exit0,51packages269edges (`logs/passive51-52-go-architecture.log`). Ordinary checker first failed to open an overlay-only path; the wrapper changes only filesystem path substitution, not assertions.
- Captured failing-before then passing regressions: maximum valid complete writer digest, final shorter acknowledgement deadline, passive acknowledged read after original write cutoff/no fallback on malformed current read. Maximum synthetic TLS/Tink pair24,125ciphertext bytes; maximum opaque envelope intent36,646/outcome37,143bytes, each≤65,536. Production backend/WAL footprint remains separately qualified input.
- Preserve earlier full affected4888 exit1 from missing embedded51/52 composition: two bundle assertions failed and were not relaxed. Other before-fix and intermediate fixture Content-Length diagnostics remain under logs. A partial temporary static-view construction failed before a valid SQL-check candidate; it is not product SQL drift evidence. Final exact generated-byte comparison and real bundle checks pass.

No52 real PostgreSQL/S3, acquisition timing, public route, installed account source or recovery activation is claimed. Parent should run spec/architecture/full Go checks after integration; shared catalogs/progress/indexes are not edited here.

## Parent merge and native qualification

`package/manifest.json` binds every payload to its current live51 base. `package/changes/` is immutable. Shared source changes are additive and preserve connector51 retirement plus processing50 classification, including `processing-result/v1`. Parent should regenerate SQLc after application, expecting44bindings. Shared roles append8new roles without changing51. Version/inventory are exact52/91. No go.mod/go.sum changes.

`package/shared/capture-admission-hook.patch` is a separate guarded one-line hunk against the current SQL51 capture fixture; do not replace the whole fixture. It invokes `qualifyCaptureIntentLifecycle` after `qualifyOperationAuditLifecycle`.

Actual native selector after hook:

```
^TestContextAdmissionWithRealServices$/^capture-intent-private-pair$
```

Use parent's owned custody SQL/S3 harness. Fixture inputs for permission/recovery/retention/backing/HMAC profile remain synthetic, and S3-admin listing is fixture inventory observation only. The selected path proves actual role boundaries, original same-caller SQL→encrypted pair timing (not collector start), held audit-pool expiry with actual pg_blocking_pids, finite unknown reconciliation, exact two-object peak, direct empty digest denial, H=0/H>0 cleanup, rollback/concurrent retirement and same-account unknown spend. Passive replay waits for a true30s write cutoff while the original40s capture interval is still open; it also reads retained acknowledgement after pair cleanup.

Intentional waits are approximately108s total:30s passive-cutoff case,5s first-read expiry,30s H0 certificate schedule,43s H2/cooling. There are no extended authority deadlines. Selected custody harness currently allows300s; normal aggregate600s (scripts/test-custody.py test_timeout near144). Normal custody ContextAdmission uses the parent context, while native Kind mode has its separate3min bound. Parent may adjust only measured aggregate harness timeout if needed; no authority or individual fixture lease should be weakened.

## Immediate next work / limits

Run the selected real52 suite; retain terminal exit, exact source hashes and teardown. Then qualify the explicit current same-key continuation and admission→intent→actual acquisition timing with existing regional runner. Complete protected backing/source/role provisioning and installation routing before public enablement. Unknown writers, incarnation recovery reconciliation, U13 accepted control metadata retirement and HMAC/account migration remain required; healthy pair retirement does not solve these. No caller can repair a spent first-write claim or renew its original cutoffs.
