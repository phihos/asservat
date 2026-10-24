# Native52: regional capacity discovery did not reach the target

Baseline `b9e633205eb07a4b438b6847793e1a3096609cc8`, run `context-84bi0pmu`.
The harness exited **1** after 1425.418426 seconds (parent-owned terminal session47879). The selected installed journey failed at regional workload readiness before capture/download/Stop. This run does not qualify the new single-runner or metadata-role simplification, which was authored separately.

## Authoritative evidence

- `command-result.json` records the command, environment and actual terminal exit. `source-verification.json` independently matches all 2771 source hashes to the baseline, records unchanged sources and removed build scratch; verification exit is in `source-verification.exit`.
- `context-storage.log:175–180` records a regional `capacity-workload-candidates: claim/post (unavailable)` response at namespace index7, kind index0, followed by advancement to namespace8. The failed candidate read took 560ms; that duration does not establish its underlying cause.
- `retained-collection/regional-namespace-order.log` places `regional-apps` at index7 of the nine retained namespaces. `regional-target-namespace.log` and `regional-target-deployment.log` pin the target namespace and exact ready Deployment UID.
- `retained-collection/postmortem-readiness.log` shows no `capacity_workload` or `context_storage_binding` rows. The capacity source had accepted revision2 and a root-ready timestamp, while pool revision1 had been superseded.
- `retained-collection/postmortem-permission-scope.log` shows the exact target namespace/workload permission basis with a live workload-maintainer assignment, current basis/stream sequence2, and acknowledged activation audit. Those target assignment predicates existed before the failed discovery pass. The stream's later suspended/empty-freshness state was collected after fixture shutdown and cannot establish its state at the failed read.
- The four retained SQL snapshots show zero context captures, executions and custody records. This failure is earlier than request admission, API execution preparation, acquisition, publication or download.

## Diagnosis and limits

The source cursor in `internal/application/capacity/reconciliation_discovery.go` marks a workload page as loaded and empty on any failed LIST. Its next turn advances to the next kind. Consequently one transient Deployment LIST failure skips that kind for the entire enumeration pass; this concrete source behavior matches the index7 failure and subsequent index8 progress. The target Deployment's Pod is owned, so the Pod candidate list does not provide an equivalent second route to this workload. The next full regional pass began only near the five-minute readiness deadline.

The generic `compose/permission-scope (not-allocated)` log is first emitted for namespace index0, not the target. The reporter suppresses the same error outcome across workloads. It therefore does not prove that the target's accepted permission was missing; the targeted SQL evidence shows it was present. The selected evidence supports skipped discovery as the availability mechanism, but does not identify why the original `claim/post` request failed or prove that a retry would necessarily complete enrollment. No timeout, API rate, SQL budget, authority check or fixture wait has been increased.

A focused cursor regression should inject one failed first-page/continuation LIST and verify a later ordinary scheduled turn retries that same namespace/kind/page before moving on. Permanently failed pages need bounded advancement so a deleted namespace cannot starve later namespaces. Other clusters already retain round-robin scheduling; the existing serial-loop and per-cluster pacing must remain unchanged.

## Collection and cleanup

The existing retained-fixture collector completed exit0 (session62099/chunk625561); all recorded collection failures are empty in `retained-collection/collection.json`. Additional bounded, read-only SQL and exact Kubernetes metadata commands exited0 as recorded in `readiness-commands.json` and `final-targeted-command-results.json`. Private kubeconfigs were kept outside this archive, then removed.

The exact kept-manifest cleanup command exited0 (session21825/chunk4d535c); `cleanup.log` and `kept-cleanup-context-84bi0pmu.json` record success and no cleanup failures. Independent Docker read-back found all12 exact owned resources absent, Kind listed neither owned cluster, and private configuration removal was verified. `cleanup-verification-corrected.json` contains the successful result. The original `cleanup-verification.json` is deliberately retained: its false result was solely a case-sensitive parser failing to recognize Docker's lowercase `no such volume`; no remaining resource or failed cleanup action was found. The corrected report reclassifies the original authoritative responses and does not claim a second read-back.
