# One original download request observation

Runtime baseline: `8302f761` (unchanged coordinator/runtime from `98f7e181`).
Green integrates ADR-220 private short-proof helpers from `ecf35eaf`.

The actual coordinator/native runtime/dispatcher use synthetic SQL, Job, audit
and authority ports. The first RED records three full constructions and a final
response expiry after successful Job recording/observation under 1.6 seconds of
synthetic cost per construction plus 400 milliseconds of audit work. That first
run also exposed a Ready fixture's unrelated request-digest mismatch; the corrected
RED retains all three intended failures (actual exit 1, 1.813 seconds wrapper).
No runtime source changed between those baseline runs.

After sharing the original checked authority, Pending and warm Ready each use
one construction with current SQL observations. Another request authorizes afresh.
Final SQL refusal, changed groups/scopes/policy, cancellation, original expiry and
unknown Job replies still refuse. Focused GREEN exits 0 (2.152 seconds wrapper,
0.006 seconds Go). The full evidence race suite exits 0 (8.140 seconds wrapper,
4.069 seconds Go); all 2,611 Go/module sources remain unchanged during each green
run. Two comment-only clarifications after that run describe the shared helper's
new coordinator use; no runtime behavior changed afterward. Independent review
finds no blocker.

`change.patch` and `regression.go.txt` retain the candidate delta/test. Logs, exact
commands, actual exits and source manifests are retained without filtering failures.
Combined design, real SQL and installed native qualification remain pending.
These component timings do not attribute native56's precise refusal or establish
native file delivery, Stop, expiry or managed deletion.
