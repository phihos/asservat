# Candidate workload LIST refinement

Base: `ecf35eaf7ed7d84b3edd17e581346bd7dd98b584`.
Worktree: `/home/phil/Projekte/asservat-capacity-candidates-c62e02ac`.

Only the candidate workload branch loses the namespace GET before and after its
bounded typed LIST. Each successful or empty page therefore takes one API call
instead of three. This is a call count, not measured installed latency. The
original namespace reference, request digest, kind, cursor, page-size/schema
checks, caller cancellation and original response interval remain. Exact and
guarded workload observations retain their independent namespace UID/label
brackets and workload UID/owner/generation checks. No grants, cursors, retries,
protocols, rates, deadlines or persistent state change.

The real local TLS API fixture is synthetic. Candidate-success then exact-refusal
cases cover namespace unavailable/replaced/deleting/expired for both exact
purposes. Other tests preserve malformed/expired/empty pages, original request
and caller bounds, cancellation, and existing exact workload owner/UID/label/
generation refusals. No installed fixture or external service was run.

RED snapshots are byte-exact baseline production plus test-first regression.
The first RED selector included a nonexistent discovery-name alternative;
metadata and existing exact-workload tests did execute and genuinely failed.
Both GREEN selectors include the actual `TestCapacityDiscoveryIsBoundedCandidateEnumeration`.
Raw logs and per-command receipts retain actual exits, elapsed time, exact
commands/environment overrides and all 2,610 tracked Go/module source hashes.
`terminal-receipts.json` records observed terminal tool session/chunk evidence.
`source-ready.json`, `green-source/` and `tracked.patch` identify the final change.

Independent source review by `review_pr41` found no blockers. The reviewer ran
no tests. Full repository design/spec gates and installed qualification remain
parent-owned; this component evidence does not claim either has passed.
