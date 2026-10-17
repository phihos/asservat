# ADR134 audited admission correction

Five paths, existing bases verified against current live source; two new regression files. No live edits, SQL migration, role/grant, public schema, output, UI or source-deadline relaxation. Preserve the parent's implementation-progress.md and context-capability.md updates; neither is replaced. The current integrated native diagnostics remain in the fixture.

PrepareCaptureOperation now truncates only its already-intersected live RequestUntil down to SQL microseconds. Immutable CreatedAt, WriteUntil, RetainUntil and original capture/lifecycle remain unchanged. Collapsed sub-microsecond intervals and invalid historical CreatedAt still reject. The native helper now funds 120 seconds of audit retention before admission, retaining its original 30-second capture/write interval. H=0, cleanup15 and proof1 make OriginalPurgeAt=RetainUntil-46 seconds: the old60 configuration purged at +14, the new120 at +74. The pure fixture regression invokes the same extracted backing constructor and tests 76-second denial/77-second acceptance at the strict original-write boundary.

The sole architecture document change explains downward precision, corrects SQL52's stale unrun paragraph using the actual eleven-pass report, and records this separate acquisition correction as pending native qualification. It does not claim the parent rerun passed.

## Evidence

All source checks used isolated Go overlays, GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp, with no native/external services.

- Before handle4064 exit1: both the nanosecond bound and actual fixture retention fail for the intended reasons. before.log; exact replayable before/ source and before-overlay.json retained. Initial7492 test setup omitted synthetic human Kind; its separate failed log is retained and is not the lifecycle evidence.
- After56801 exit0: go test -race -overlay overlay.json ./internal/application/audit ./test/integration -run 'TestCaptureOperationAdmission|TestNativeContinuationAuditBacking' -count=1. Audit1.014s, integration1.055s. This compiles the actual full integration package while running only the pure selected regression.
- Final80555 exit0: full application/audit race (1.137s), then go vet -overlay overlay.json ./internal/application/audit ./test/integration. Both log files included. No build remains active.

## Parent next action

Verify manifest bases/payloads and integrate five paths. No generated bindings are changed. Parent owns combined gates and exact native selector:

python scripts/test-context-storage.py --run '^TestContextAdmissionWithRealServices$/^native-api-runner$'

The earlier native failure is explained by these two independently reproduced precommit denials; only the actual rerun establishes complete acquisition continuation. Existing separate SQL52 native pass and ADR134 browser pass do not substitute. Keep original five-second caller bound, current authority, uncertain spend, sole key-preparation winner and passive historical replay unchanged. Public collection remains disabled.
