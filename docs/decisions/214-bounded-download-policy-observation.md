# ADR-214 — Reuse bounded policy observations in download preparation

Date: 2026-10-20. Status: selected under the maintainer's explicit complexity-review
continuation; implementation and qualification in progress.
Requirements: REQ-DLD-002/003, TASK-03/11, S-02.

## Problem

One protected Kubernetes download-policy read makes 14 observer and three probe
requests. The download environment repeats it before and after SQL reads, and the
first worker-preparation phase evaluates that environment ten times. At the existing
20 QPS/burst-20 rate, its 280 observer requests alone require at least 13 seconds
inside a five-second request. The actual composed regression fails before Job creation.
See the [recorded baseline](../../test/results/resumed-c62e02ac-download-whole-phase-budget/README.md)
and [complexity review](../reviews/complexity-2026-10-20/README.md).

The maintainer did not require immediate interruption when permissions change and
explicitly authorized a relaxed bounded check interval. Repeated inspection of the
same protected installation policy at every helper call has no demonstrated benefit
that justifies this failure. The expensive policy observation is distinct from
current SQL permissions, recovery, processing restrictions and transaction spend.

## Decision

1. The installed download authorizer shares one policy observation for at most
   **60 seconds from the beginning of its original source read**. This is the
   selected starting interval for qualification. Cache hits never reset it.
   Each caller still evaluates its own principal/client, artifact class, purpose
   and exact installed path against that observation.
2. The raw Kubernetes source remains unchanged: its complete protection, two
   source reads and closing guard must succeed within the caller's original
   deadline and the existing five-second I/O limit. Only a successfully completed,
   currently valid source observation can enter the download observation store.
   The 60-second bound concerns reuse of the observed configuration; it does not
   extend the source read, its caller, a human session or any evidence lifetime.
3. Domain validation distinguishes this download observation from the raw
   five-second policy used by privacy operators and capacity administration.
   Administrative operations do not use the longer observation. The production
   wrapper is installed only in the download environment.
4. Keep one retained policy and one concurrent refresh per reader. Waiters honor
   their own cancellation/deadline; refresh runs in its initiating request, with
   no detached work, watch, periodic goroutine or new deployment/configuration.
   Return independent copies of all policy slices. Expiry, failed refresh and
   clock rollback never provide stale authority or renew the old observation.
   Refresh on demand when less than the existing five-second operation budget
   remains, so a new request does not inherit an avoidably tiny policy deadline.
   Only another successful source read supplies a new observation interval;
   an operation already bounded by an older observation keeps its deadline.
5. Keep current SQL permission, retention, recovery, processing, worker/generation
   and spend checks at their existing effect boundaries. Their shorter proof and
   request bounds remain independent. Cheap checks may detect and enforce changes
   earlier than 60 seconds. A complete `DownloadAuthority` is never shared across
   independent requests. The request-owned refinement below reuses it only within
   one already bounded operation.

This amends ADR-127's repeated protected-policy observation requirement for the
download path. It changes no persistent schema, wire format, grant scope, approval,
native file bytes or processing-operator permission. It does not justify a blanket
increase of all five-second timers.

## Identity-policy reuse within its existing interval

The stronger preparation regression composes the actual identity service, bearer
request and download authority. With download-policy reuse in place, it still
fails after 4.958 seconds: 40 identity checks attempt 119 Kubernetes requests on
the identity reader's separate, unchanged 20-QPS/burst-20 client. Job creation and
its Pending observation succeed; the final identity check exhausts the original
request interval. Claims/signatures and SQL/catalog/retention remain synthetic
in this regression, so this is still not installed-workflow qualification.

`IdentityPolicyClient` already returns an observation valid for 30 seconds. Reuse
that completed observation until its original `FreshUntil`, with one retained
snapshot and one synchronous refresh per pinned reader. Do not increase its
lifetime. Continue signature/token, session, subject/client and policy eligibility
validation on every identity resolution. Copy returned slices, preserve issuer
pinning and caller cancellation, and never serve an expired observation after
refresh failure. A policy change is discovered by the next refresh within the
existing 30-second bound; no watch or additional credential is introduced.
Use the same demand-driven five-second refresh headroom as the download policy.
Without it, a new request arriving at age 29.9 seconds would inherit roughly
100 milliseconds from the otherwise valid cached policy. No periodic task or
new timeout setting is needed to avoid that predictable availability gap.

This replaces repeated reads of unchanged identity settings, not repeated identity
validation. The installed browser, MCP and download services share that pinned
reader; their independent session, token and request deadlines still apply.

## Request-owned authority refinement (2026-10-22)

Configuration reuse removes the demonstrated Kubernetes rate-limit failure, but
the first worker-preparation path still reconstructs complete authority ten times.
The worker helper adds identity reads around an authorizer that already checks
identity and permissions before and after its catalog/privacy reads. Retaining
these nested checks is not a user requirement.

Obtain one complete authority observation when constructing the request-owned
worker operation. Later checks in that operation validate the retained value,
exact scope, cancellation, clock direction and its earliest original deadline
locally. The operation is still capped at five seconds and cannot renew itself.
Another request performs a new authorization. This is neither a process-wide
authority cache nor a sixty-second download permit.

Keep the SQL effect checks for permission revision/suspension, retention and
effective dates, processing restrictions, recovery epoch, worker generation and
spend. A durable change can therefore reject an effect before the observation
expires. External identity/group changes no longer require another remote lookup
at every helper boundary within the same operation; the next request observes
them. Token/session/evidence expiry known when authorizing still caps the original
operation, as does cancellation at any point.

This removes repeated work from dispatch and enrollment without another timer,
configuration option, durable record or credential. It amends the per-step
external-identity refresh described in
[the worker lifecycle contract](../architecture/worker-current-lifecycle.md).
The 2026-10-23 refinement extends that ownership to the complete finite prepare
request: coordinator entry, installed native runtime, and final Preparing/Ready
view consume the same original authority. The private native handoff validates
exact scope, current identity-policy revision, required scopes and all original
bounds without another full reconstruction. Ready replay and metadata reads also
consume the current request's checked authority. A standalone runtime call still
authorizes independently, and a new prepare/status request always authorizes anew.
Current SQL observations and final identity comparison remain. An unknown Job or
SQL reply cannot become acknowledged Pending. No constant is increased.

The composed regression genuinely observes three full constructions before the
change. With 1.6 seconds of synthetic cost per construction and 400 milliseconds
of audit work, Job creation/observation succeed but the final reconstruction
exhausts the original five seconds. After the change, Pending and exact warm Ready
replay each use one full construction; current SQL reads, changed final identity,
cancellation, expiry and unknown-Job refusal remain covered. This is component
evidence, not proof that native56 failed in that exact branch. The existing
transfer renewal is separately refined by ADR-220.

## Complexity check

| Question | Answer |
| --- | --- |
| 1. Observed harm? | The actual preparation regression fails after 4.951 seconds; installed native50 also fails before worker creation. |
| 2. Accepted risk? | Yes: bounded permission-change handling was explicitly authorized. Immediate/per-step revalidation was not a user requirement. |
| 3. Typical path? | Every first context download currently repeats the policy reads. |
| 4. Prior art? | Bounded reuse of configuration/identity observations is established; the review cites SPIRE's cached workload identities. This is not a claim of equivalent authorization semantics. |
| 5. Added privileges? | None; the existing exact source, guard, clients and installed paths remain. |
| 6. Failure states? | One retained observation and one transient refresh; no durable recovery state. Expired/unavailable data denies. |
| 7. New knob? | None. A fixed 60-second download-only observation bound. |
| 8. External coupling? | No new dependency; the same Kubernetes protection read and SQL effects. |
| 9. Aggregate cost? | Under steady demand, refresh download policy after about 55 seconds (14 observer/3 probe requests) and identity policy after about 25 seconds (three observer requests). The five-second headroom avoids shortening a new request to the final fraction of an observation. Failures and other readers still consume their existing request budgets; complete-path cost must be measured. |
| 10. Upgrade/rollback? | In-memory state only; restart drops it. Older code returns to more frequent reads. No migration or retained authority conversion. |
| 11. Smaller solution? | Raising QPS or only increasing the operation deadline preserves unnecessary work. Reuse the policy observation while retaining existing effect checks. |

## Qualification

Require the existing five-second first-Job regression to reach acknowledged
Preparing at the original rate, with one complete protected policy read. Exercise
concurrent callers, original observation expiry, source changes at the next refresh,
refresh failure, independent copies, cancellation and clock rollback. Preserve the
raw source/admin five-second tests. A loopback policy test does not qualify the full
installed identity, SQL, audit, worker and transfer composition.

Measure remaining complete-path work before running the installed fixture; qualify
native transfer, Stop, expiry and deletion separately from a successful preparation.
Require the stronger identity/authority regression to pass at the unchanged client
rates, with one identity-policy read (three observer requests) and continued token
validation at each actual authorization boundary. For request-owned reuse, prove
one full worker authorization, bounded local checks, fresh authorization on a new
operation, and unchanged cancellation/expiry and SQL revocation enforcement.
Preserve the failed combined run and the earlier repeated-check counts as evidence.
Actual commands and results belong in [implementation progress](../implementation-progress.md).

## Response-owned ordinary entitlement refinement (2026-10-23)

[ADR-220](220-response-owned-download-permissions.md) permits ordinary permission
reconstruction once per original response interval of at most 30 seconds, anchored
before I/O. It refines the earlier requirement to reconstruct that component for
every short lease. Current identity, catalog, retention, environment and SQL
fences remain, and every combined authority/delivery/native interval still lasts
at most five seconds. Known SQL changes may deny earlier. New responses and
preparation are fresh; no stored source timestamp or original deadline is renewed.
The actual native response consumes an exact already-checked short authority
through a private handoff. Qualification is recorded separately; this does not
claim sustained installed transfer or a native55 preparation fix.

## Approved query shares the observation (2026-10-23)

The installed approved query (`get_file_excerpt`) was composed over the raw
protected source. Its authority evaluated the placement environment twice, each
reading the policy twice: four complete protected reads (about 56 observer and
12 probe requests on the shared 20-QPS client) before query admission, inside
the same five-second request. Installed native63 refused that call about four
seconds in with no `context_query` row. The query now uses the download path's
single observation and its 60-second bound; each call still evaluates its own
client, purpose, path and regions, and recovery, processing, ordinary
`ReadApproved` and SQL effect checks are unchanged. Direct administration keeps
the raw five-second policy. Refusals now name their closed stage
(`query refused: excerpt/<stage> (<class>) left@<bucket>`), so the next installed
run confirms or refutes the policy cost as the refusing stage.
