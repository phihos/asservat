# Response-owned download permission cadence — component qualification

ADR-220 retains only ordinary entitlement for one original response, for at most
30 seconds from reconstruction start. Short identity/effect/native authority and
current SQL permission, retention, recovery, processing and spend fences remain.
This changes reconstruction cadence; it does not guarantee delayed revocation.

The actual RED baseline failed with repeated permission reads, revivable failed
owners and duplicate native authority construction. The exact passthrough source
and new regressions are retained under `source/red-source/`; `red-from-base.patch`
includes new files. The first GREEN failed only an inconsistent short-session
fixture: its original metadata key still referred to a long worker. That run and
its exact source remain under `source/green-source/`. The corrected fixture keeps
all original cutoff assertions and begins with one consistent short worker/key.

| Check | Actual exit | Command wall time | Package time |
| --- | ---: | ---: | --- |
| Passthrough RED | 1 | 4.672264 s | authorization 0.003 s; evidence 0.082 s |
| First GREEN | 1 | 2.353070 s | authorization 0.004 s; evidence 0.082 s |
| Focused final GREEN | 0 | 1.979412 s | authorization 0.004 s; evidence 0.084 s |
| Both complete affected packages, race | 0 | 14.911272 s | authorization 1.306 s; evidence 3.986 s |
| Integration package compile, no selected tests | 0 | 30.248751 s | compile only |

`result.json` links exact commands/environment, terminal tool sessions/chunks,
qualification limits and review. Each command's before/after manifest contains
2,610 Go/module source hashes with no change during execution. The eleven relevant
source snapshots match those manifests. Snapshot filenames end in `.go.txt` so
archiving them cannot introduce packages into `go test ./...`.

The cadence regression drives the real C-03 authorizer through 0, 5, 10, just
before 30, exactly 30 and 35 simulated seconds: four total permission reads after
two successful reconstructions, with current safety reads on every short check.
It also covers pre-I/O anchoring, exact scope/claim/audience changes, isolation,
aliased source slices, failed refresh/post-read construction, joined Close and
cancellation. The actual C-14 native response uses its exact short handoff while
retaining current attachment reads and original cutoff negatives. Its metadata
and attachment observations are explicitly synthetic; the negative chunk case
stops before a byte effect. Direct public current methods still reconstruct.

The added real SQL suspension test is compiled but **unrun**. Its existing owning
selection is `TestContextAdmissionWithRealServices/download-response-window-accounting`;
it adds `response-permission-cadence-keeps-sql-revocation` after the original
lifecycle checks. It must demonstrate that retained ordinary success cannot
bypass current SQL suspension while the short authority remains live. No SQL
implementation, role, pool or privilege changes are included.

No external fixture/resources were created. Installed streaming, sustained
availability, generic large artifacts and complete lifecycle remain unqualified.
This is not a native55 or native56 preparation-failure diagnosis. Combined
specification/architecture gates remain for the integration candidate.
