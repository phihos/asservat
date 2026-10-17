# Bounded confirmed conditional-conflict recovery

Frozen ten-path ADR129 follow-up. No live edits, new migration, dependency, credentials, retry settings or parent-owned native fixture changes. Manifest SHA256: `77e0bd6562dd9394ee394af89e0b0888bf7ecf1a596e67492d53d71f07b15767`. Every existing base was compared byte-for-byte with live at freeze; both new paths were absent. Parent can apply each changes/ payload only after matching manifest base hashes.

## Behavior and contract

Original Pod launch and same-UID staging retirement keep their original ID, UID/spec, resourceVersion and at-most-five-second interval. An actual HTTP409 raw v1 Status Failure/Conflict must identify exactly the original group/resource/name; duplicate/unknown JSON keys, AlreadyExists, malformed or client-synthesized outcomes, UID/causes/retry hints and late responses cannot provide no-effect proof. The original response owner privately retains only exact public binding and completion time, never the body. Only a successful bounded root CAS acknowledges that completion.

One second conditional UPDATE is permitted after a separately acknowledged unique retry-ID/new-resourceVersion CAS, still within the original parent interval and after rechecking exact original identity/spec. An already stored retry cannot dispatch again; a lost retry CAS reply or unknown second effect remains observation-only. Positive same-process negative completion can finish its own failed acknowledgement within original time; later GETs and other processes cannot manufacture it. At most two conditional effect requests per purpose, at most two private retained negative receipts. Ordinary no-conflict encoding is unchanged by omitempty fields.

The canonical root schema adds optional closed firstConflict/retry types and retry→firstConflict dependency. Runtime validation also checks exact original time ordering, unique IDs and changed nonempty revision. Native API shape was independently measured by the parent on actual status-only Pod/VAP changes in initial-handover-history-qualified.log; this patch does not claim that whole conditional retry execution has passed real Kubernetes.

## Verification (actual terminal results)

All commands used `TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2` and Go `-p 2`, against the recorded sparse overlay.

- `go test -overlay .../overlay.json ./internal/adapters/kubernetes -run '^TestInitialHandover'`: exit0,5.568s in unit-launch-first.log before final two retry-claim cases were appended.
- `go test -race -overlay .../overlay.json ./internal/adapters/kubernetes -run '^TestInitialHandover'`: exit0,43.214s in race-final.log. Covers raw parser plus7 staging and11 launch branches: known conflict, nonqualifying outcomes, original identity/spec substitution, deadlines, second conflict, negative acknowledgement loss before/after persistence, retry claim loss before/after persistence, concurrent resumptions, and second effect reply loss before/after its state change. No third UPDATE and unchanged original dates are asserted.
- `go vet -overlay .../overlay.json ./internal/contracts ./internal/adapters/kubernetes`: exit0, empty vet-final.log.
- `go test -overlay .../overlay.json ./test/integration -run '^$'`: exit0,0.012s, compile only, compile-final.log.
- `spec-venv/bin/python check-schema.py`: exit0,18 canonical positive/negative shape cases using offline reference registry and actual date-time FormatChecker, schema.log.
- Controlled failing-before comparison: overlay-before.json uses the original integrated launch/staging methods with the additive DTO/parser/test surface; `go test ... -run '^TestInitialHandoverStagingConditionalConflictDoesNotRenewAuthority$/^exact-conflict$'` exits1,0.337s: exact conflict was not recovered. Preserved in before-original-methods.log. This is a focused old-method regression, not a pristine-old-tree full gate.

The fixture is loopback TLS with explicitly synthetic protected roots and current observations, no SQL/provider authority or real Kubernetes admission. The baseline actual loader/image/cleanup/passive handover has passed separately; native injected conflict execution, current full repository gates and combined bootstrap observation fix remain parent qualification. No public runtime enablement.

## Integration and next work

No overlap with workflow's bootstrap observation race fix. Integrate ten hash-guarded payloads, combine that independent fix, run repository/schema/architecture checks and the parent-owned fresh-database actual handover qualification. If expanding native conflict injection, preserve the original five-second interval and distinguish measured HTTP Status shape from the full state-machine effect qualification. Broader uncertain launch/credential recovery and official runtime installation packaging remain required; this patch does not reset those states.
