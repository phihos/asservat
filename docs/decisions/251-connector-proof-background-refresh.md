# ADR-251 — Background refresh of the regional connector process proof

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-EXE-002, S-02. Resolves the remaining limitation of
[ADR-250](250-standby-residency-and-unstarted-acquisition.md); refines the proof reuse in
[regional context start](../architecture/regional-context-start.md#protected-connector-api-process).
Complements [ADR-212](212-api-preparation-remaining-interval.md).

## Problem

The region bounds every pre-work target answer and every work by its receiver check, which reads
`ConnectorAPIExecutionProtection`'s single cached process proof. A proof lasts at most five
seconds from its start; a full production takes about one to two seconds, so a new proof enters
the cache with three to four seconds left. The cache was strictly request-driven: the request that
found no valid proof produced one synchronously, and later requests rechecked and reused it until
its end. A request arriving in the proof's last second therefore got a short answer. After
ADR-250 this remained the only observed cause of `PrepareAPIExecution[target@<1s]/effect/headroom`
refusals and `resolution-expired` target queries (run 40461388398), retryable but avoidable.

ADR-250 tried replacing a cached proof that had less than 2.5 s left inside the request (8fa6b469).
That moved the full production into requests, and all four share runs overran their request
bound. It was reverted. The cache's contract ("no goroutine, timer or refresh survives this call";
"there is no background refresh") excluded producing a proof outside a request, so the remedy
needed this separate decision.

## Decision

1. **One background rebuild per connector.** The regional context process runs
   `RefreshProofs` for its connector API protection for the process's lifetime, joined on
   shutdown. When the freshest cached proof has less than **3 s** left (constant), the loop
   performs the ordinary complete `produceProof` with its own **5 s** bound, in its own goroutine,
   one at a time. No configuration.
2. **Only under demand.** A rebuild runs only if a request read (`ReadAPIProcess` /
   `ReadAPIProcessConnector`) used the cache since the previous rebuild began. An idle connector
   performs at most one rebuild after its last read; standby setup alone (`BeginAPIContextSetup`)
   creates no demand.
3. **Each proof keeps its own bounds.** A rebuilt proof is a separate proof with its own original
   start and end; it never changes, extends or re-anchors the proof it succeeds, which stays usable
   (with its current recheck) until its own end. A rebuilt proof enters the cache only if it ends
   later than the cached one, and a recheck of the older proof that completes afterwards narrows
   only its caller's copy. Requests read the freshest valid proof.
4. **Requests never wait on a rebuild while a valid proof exists.** The rebuild is not a request
   flight. A request without a valid cached proof joins a running current-generation rebuild
   instead of starting a second production; otherwise it produces as before.
5. **Unchanged authority.** Every reuse still performs its full current recheck. A rebuild error,
   an invalid or renewing result, or an invalidation during the rebuild leaves no proof usable,
   as a failed request production does; invalidation also cancels the rebuild. Setups bound to the
   cache generation are unaffected by a successful rebuild.

## Complexity gate

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Observed: `target@<1s` headroom refusals in installed share runs after ADR-250 (40461388398: 3 lines in one run). Harm: retryable `AcquisitionNotStarted`/`NotAvailable`, extra client round trips; no spent work. |
| 2 | Accepted risk? | No. ADR-250 recorded it as a remaining limitation needing a separate decision. |
| 3 | Typical deployments? | Yes: it depends only on request arrival relative to the five-second proof, not on load. |
| 4 | Precedent | Refresh-ahead caching (the kubelet rotates projected service-account tokens at 80 % of their lifetime; Caffeine's `refreshAfterWrite`): serve the current value, rebuild in the background before expiry. |
| 5 | Privileges/exposure | None added. Same credentials, same reads as a request production. |
| 6 | Added states | One: a background rebuild in progress (requests without a valid proof join it). No fallback. |
| 7 | Configuration | None; two constants (3 s threshold, 5 s rebuild bound). |
| 8 | External dependencies | None beyond the existing Kubernetes API reads. |
| 9 | Cost | Per connector while requests read: a rebuild about every 2 s (3–4 s left at entry, threshold 3 s; bounded below by rebuild time), at most 30 per minute. One rebuild is one full production: by code-path count about 40 Kubernetes API requests (2 TokenReviews, 1 SelfSubjectReview, the rest GETs of guards, sources, Deployment/ReplicaSet/Pod and inputs), no SQL, no hub request, about 15–20 API requests/s on the opening client (50 QPS, burst 100). Previously active periods produced on each read after expiry (about every 3–5 s), so the increase while active is below 2.5×. Idle: at most one rebuild after the last read. Memory: one extra proof. Scales with connectors (one loop each), not with workloads or nodes. |
| 10 | Upgrade/rollback | No persisted state or wire change; reverting the commit restores request-driven production. |
| 11 | Smaller fix? | Doing nothing keeps the retryable refusals. Refreshing inside requests was tried and failed (ADR-250). A longer proof would weaken the five-second freshness. |

## Consequences

Requests during active use find a proof with at least about one to two seconds left instead of
possibly less than one, without production on the request path. The connector performs more
Kubernetes reads while in use and at most one extra production after use. The proof's five-second
original freshness and every reuse's current recheck are unchanged.

## Qualification

Component tests (`internal/adapters/kubernetes/connector_api_proof_refresh_test.go`): rebuild
before expiry only under demand, single flight with requests rechecking the held proof without
waiting, a request without a valid proof joining the rebuild, no replacement of a fresher proof or
renewed bounds, invalidation on failure/change, and joined shutdown. Installed native results are
recorded in [implementation progress](../implementation-progress.md).
