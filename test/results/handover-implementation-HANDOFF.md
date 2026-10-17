# ADR-129 initial activation handover checkpoint

Frozen 42-path sparse payload in `changes/`, original existing bytes in `base/`, exact guarded hashes in `manifest.json`; `changes.patch` is an alternate review representation. All 42 bases matched live at freeze, new paths were absent. Manifest SHA-256: `07a232373219d8bd4715e1ac018aabe9d6173fe848d08c77bf321c4b2a767358`. No live edits or external fixtures were performed by this agent. No migration, dependency, shared index, public workflow enablement or Helm runtime enablement is included.

## Implemented contract

The new explicit handover capability is selected before the original root and policy generation. Legacy omitted-field encodings/templates remain unchanged. Eleven declarative objects include the two permanent minimal history Role/Binding objects; the distinct final activation input set remains nine. Original root/plan/guard/Pod identities, current administrator checks, five-second effect bounds and original SQL/probe/provider intervals are retained.

The supervisor connects prepared inputs to canonical same-UID staging retirement, one-use original Pod gate removal, exact successful original Pod observation, independently read original SQL activation/audit disposition, and eight ordered cleanup acknowledgements. New positive original Secret CREATE provenance is produced only by the same owner's valid successful 201 response before its original deadline. Exact GET/409 or old receipts never synthesize it. Joined ownership can persist a previously retained positive response, not issue another CREATE.

Cleanup revokes existing-session SQL effects, independently confirms original provider token rejection, observes original probe rejection and Secret absence, removes exact target Secrets, makes setup RBAC inert while preserving the history pair, irreversibly clears the original private Secret, then marks/deletes the exact original terminal Pod. Each step uses fresh current checks without extending original authority. Externally supplied S3 credentials remain unmanaged.

The separately created installation history login has exact SELECT-only privileges and no memberships/ownership/application SECURITY DEFINER execution. Creator ADMIN membership is revoked. Passive loader replay consumes this history projection plus current bootstrap proof without maintenance/provider preflight or old issued credentials. Historical Activated is not current RecoveryReady.

The new profile's finite process budget is three minutes (legacy remains one minute); current leases remain five seconds. Whole-second Kubernetes terminal timestamps are compared at explicitly observational precision; microsecond authority deadlines are unchanged.

## Verification actually completed

All commands used `TMPDIR=/home/phil/.cache/asservat-build/tmp`, `GOMAXPROCS=2`, `-p 2`, and this stage's `overlay.json`.

- Four-package compile passed (`compile-first.log`). A later cleanup compile caught an unused shadowed context; the original deadline was preserved using the outer context, and corrected compile passed (`compile-cleanup.log` and `compile-cleanup-after.log` retain before/after).
- `go test -race ./internal/contracts ./internal/adapters/kubernetes ./internal/adapters/postgres ./internal/bootstrap -run 'TestInitial(Preparation|Preparer|Private|Credential|History|SQLHistory)'` passed; Kubernetes 110.652 seconds (`race-handover-first.log`).
- Final `go test -race ./internal/adapters/kubernetes ./internal/adapters/postgres ./internal/bootstrap -run 'TestInitial(Preparation(Handover|Secret|Terminal|Cleanup)|History|PrivateContinuationPreserves|Provider)'` passed; Kubernetes 20.885 seconds (`race-handover-final.log`).
- `go vet ./internal/contracts ./internal/domain/configuration ./internal/adapters/kubernetes ./internal/adapters/postgres ./internal/bootstrap` passed (`vet-final.log`, empty successful output).
- External spec venv ran `check-schemas.py` against canonical schemas plus staged replacements with Draft 2020-12, offline references and FormatChecker; passed (`schema-check-first.log`). Includes capability prerequisites, positive receipt binding, finite cleanup/date/secret/step negatives and legacy private/provider cases. This stage-only script is qualification support, not a product path.

Tests cover legacy/new profiles, own-response closure versus unknown HTTP/late responses, original operation/UID binding, local close, terminal timestamp precision and substitutions, early/wrong marker/restarts/failed phase, fixed cleanup order/deadlines/references, history credential purpose and privilege allowlist. These tests do not establish native admission/controller/PostgreSQL behavior by themselves.

## Integration and remaining qualification

Parent owns the separately staged actual-image/native fixture and five paths: `initial_preparer_handover_test.go`, `initial_handover_admission_test.go`, the shared `initial_preparer_test.go` helper, `scripts/test-context-storage.py`, and `Makefile`. None are in this payload. Refresh its dependency snapshot with all current changes before compilation. Parent's dedicated fresh-database native selection must qualify actual loader -> initial-install image -> SQL/encrypted audit -> all cleanup -> passive reopen. A separate explicitly synthetic admission fixture covers mutation/deletion negatives. Neither native result is claimed here. Parent should run integrated Go/schema/spec/architecture gates and update shared catalog/decision/progress indexes.

Unknown original Pod/Secret CREATEs, lost pre-effect claims, failed activation, expired unreconciled issuer retirement and restart/restore remain unavailable with original identities retained. They are required recovery follow-ups, not automatic reset or permission widening. Permanent roots/inert inventory are finite per installation. The chart remains configuration-only. No user collection/disclosure route is enabled by this checkpoint.

Next: integrate and qualify the actual handover path; fix any concrete native incompatibility while retaining before/after evidence. Then continue supported installer packaging and unresolved recovery composition rather than treating this component checkpoint as the complete platform.
