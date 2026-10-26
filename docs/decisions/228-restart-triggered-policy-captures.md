# ADR-228 — Restart-triggered policy captures (first S-03 increment)

Date: 2026-10-25. Status: accepted; implemented; qualification results below.
Requirements: REQ-TRG-002/004/005, REQ-AUT-001/003 (ADR-059), REQ-EXE-001, S-03 (TASK-04).

## Problem

S-03 needs automatic bounded collection. The S-02 context pipeline (preview, admission, intent
audit, hub-run regional start, publication, download, deletion) exists, but nothing triggers it, and
every check in it assumed a human actor. The accepted ADR-059 components (automation envelopes,
policy sources, acceptance and its audit) existed without a source of policies, an activation path
or an executor that could run a capture.

## Decision

1. **One trigger kind.** A DebugPolicy with exactly one `kind: exit` detector (reasons OOMKilled,
   Error, CrashLoopBackOff; optional exit codes) referenced directly by `when`, the pod-status
   context recipe, `maxPods: 1`, `selection: triggeringPod`. The compiler rejects every other
   detector, expression, recipe or option with its field path (`spec.detectors[0].kind`, ...).
2. **Polling, no watch.** hub-api (which holds the standby router) polls every active policy every
   15 seconds with one new target query, `observe-workload-restarts`, on the existing outbound
   query frames 11/12 (ADR-179). The region answers with one bounded Pod LIST of the named workload
   (Pod UID, name, whole-pod restart total, latest termination reason and exit code, current
   CrashLoopBackOff). It reuses the workload-resolution reads and adds no privilege. A truncated or
   incomplete LIST, or an answer too large for one 32 KiB frame, fails: the poll is Unknown and
   fires nothing.
3. **Counter semantics.** The pure delta function keeps one watermark per (policy, Pod UID). The
   first observation of a Pod is only its baseline; a later higher counter with a matching latest
   termination is one occurrence keyed (policy, Pod UID, restart count). A missed poll coalesces
   its restarts into that one occurrence (counted as `coalesced`); replay and concurrent duplicate
   polls are no-ops; a vanished Pod's watermark goes. Kubernetes reports exit codes, not signals,
   so `signals` is rejected; intermediate restarts' reasons are not visible.
4. **Hub-held DebugPolicy.** Policies live in the hub control namespace like AccessBindings, with a
   new `spec.target.cluster`. Their source observation names the policy object's own location; the
   accepted authority names the target workload. The ADR-059 equality of submission and target
   location assumed co-located policies and is removed for this reason only.
5. **Activation.** An administrator adds `spec.automation` to a team AccessBinding (ADR-059); a
   maintainer applies the DebugPolicy; the authenticated human calls the new MCP/browser operation
   `activate_policy`. hub-api reads the source, compiles the subset, resolves the workload through
   the region, finds the sole automation-bearing binding, pins the human's sponsoring group
   assignments, takes the envelope's per-policy maxima as limits, preflights
   `ValidatePolicyAcceptance` and calls the existing `AcceptPolicy` transaction, then publishes the
   existing encrypted acceptance audit. Only an acknowledged acceptance is eligible. A retry under
   the same key returns the original receipt (nonce derived from actor, policy and key); an
   unchanged source revision can never be accepted again, so spend and expiry cannot be reset.
   `get_policy_status` returns a content-free explanation (state, expiry, spend, watched Pods,
   recent occurrences with their captures, suppression counts by reason).
6. **Executor.** Policy captures run the ordinary investigation unchanged — a preview of the
   triggering Pod by name and a request under the occurrence ID as idempotency key — with the
   policy principal (ADR-059) as actor. Every eligibility point (investigation, SQL admission after
   locks, request resolution, regional work read, execution preparation, hub-run start check)
   evaluates a policy executor through its current acknowledged acceptance and current team
   delegation (`EvaluatePolicy`) instead of personal scopes and groups. The default audience is
   computed exactly as for a human; neither the creator nor the executor is added. The intent
   audit, the signed regional work and the SQL capture-intent check accept exactly this principal
   besides a human. A start that becomes ambiguous is never repeated (ADR-223). A review that
   admitted nothing for a transient reason (a lost regional exchange, a replaced standby) is
   reviewed again at most three times, two seconds apart, repeating every check; authority,
   capacity, invalid input, a conflicting admission and a replaced Pod are final. The occurrence
   key keeps admission to at most one capture.
7. **Budgets (migration 00082, schema 82).** One transaction per policy and poll, under the
   policy-source row lock and the workload budget row locks: watermarks, occurrences (unique per
   restart), a generic-cell-rate budget per workload (one per five minutes, burst two, shared by
   every policy on the workload) and one per policy (its cooldown and hourly bound, which can only
   tighten the shared one), and `executions_spent` (checked against the accepted ceiling). A
   suppression is one row per policy and reason (`cooldown`, `budget`, `coalesced`, `capacity`,
   `authority`, `unavailable`) with a saturating count, never a row per match. A capacity shortfall
   at admission is a suppression, never a queue. Existing per-workload capture slots, storage
   allocations and the hub-wide capture reservations still apply per cluster. At most 16 active
   policies per workload cluster.

## Agent-authored restrictions revised (recorded as such)

- Policy source freshness 5 s → 30 s (`authorization.PolicySourceInterval`, SQL check): one policy
  capture's preview, admission and regional start run on one observation and take longer than five
  seconds end to end; the 15-second poll refreshes it.
- ADR-062 signed submissions are deferred for this path: hub-api authenticates the human itself and
  accepts in-process, so it builds the submission check in-process. A JWS is needed only when a
  separate GitOps or admission submitter exists.
- Dropped for this API-read counter trigger: fire-on-activation and the 10-second re-arm
  (REQ-TRG-002; a counter has no level to re-arm, and activation only baselines), the 30-second
  correlation append (REQ-TRG-004 MAY) and per-node budgets (no node agent runs).
- The ADR-059 separate source/accept/audit/read SQL credentials are one duty in the ordinary hub
  union (ADR-222 rationale): `policy-automation`.

Maintainer requirements kept: Kubernetes-only configuration, the team envelope, per-incident and
workload storm limits, finite expiry, encrypted audit, every authorization check of a human capture.

## Complexity gate (AGENTS.md)

1. Problem: no automatic collection exists (S-03 exit item), frequent in real operation.
2. Not previously accepted as a risk.
3. Typical deployments: crash loops and OOM kills are the most common incident.
4. Comparable tools (Kubernetes event exporters, Robusta) poll or watch Pod status; polling the
   restart counter is the established cheap signal.
5. No new privilege on collectors, workers or regions; hub-api gains `get` on DebugPolicies in its
   own namespace and the `policy-automation` SQL duty; hub-api's audit credential gains the
   `policy-acceptance/v1/<root>/` prefix.
6. Degraded states: one (Unknown poll fires nothing).
7. No configuration of its own machinery (budgets are fixed defaults).
8. External behaviour: Kubernetes restart counters (stable API).
9. Cost per active policy: one regional Pod LIST (plus one ReplicaSet GET per owning ReplicaSet)
   and two hub API GETs per 15 s; one SQL transaction; bounded rows (watermarks ≤ Pods,
   occurrences ≤ admitted, suppressions ≤ 6). At 16 policies per cluster that is about one query
   per second per cluster on the standby budget of eight queries per exchange.
10. Additive migration (floor stays 81); disabling is deleting or suspending the DebugPolicy.
11. A smaller fix (manual captures only) does not meet S-03.

## Differences from the plan, and why

- **Investigation reused, not refactored.** Instead of giving `ContextInvestigation` a second
  actor type, the policy executor is an ordinary request identity (`policyIdentity`) and the
  shared eligibility port dispatches on the principal. The preview names the triggering Pod by
  name (kind `Pod` resolves under its actual owner); the request must pin the occurrence's Pod UID
  and the accepted workload, so a same-named replacement is never captured.
- **No executor/occurrence columns on `context_capture`.** The executor is already the capture's
  scope executor and intent actor; `policy_occurrence.capture_id` (unique) links the capture.
- **Budget rows are generic cell rates** (one `tat` column) rather than `window_start`/`admitted`:
  this gives exactly "one per five minutes, burst two" with one row per workload and policy.
- **128 Pods per observation, not 256.** The answer, with Pod names, must fit one 32 KiB query
  answer frame; an answer that does not fit is a closed failure (Unknown) instead of a broken
  exchange.
- **Continuation after a no-effect start refusal.** The installed run showed the first start refused
  by the ADR-212 preparation headroom before any effect, as human requests are (native48). The
  trigger then uses the existing explicit accepted-only `Continue` up to three times, two seconds
  apart; durable execution state refuses it after any possible start, so ADR-223 still holds.
- **Policy bound without the recovery read window.** A policy identity and its eligibility are
  bounded by the source observation and expiry, like a human token, not by the five-second
  recovery read inside the acceptance read; every effect transaction still checks its own recovery
  proof. With the recovery window included, the start had too little time left after admission.
- **Status reason `unavailable`** (target gone, region unreachable) besides capacity/authority.
- **Browser UI not built.** Both operations are reachable through the browser's generic operation
  route and MCP; console screens are the next increment.

## Qualification

- Unit and race: compiler field paths, delta function (baseline, replay, missed poll, lower
  counter, UID replacement, reason/exit-code/CrashLoopBackOff filters), policy eligibility (team
  authority, audience without creator/executor, sponsor/executor deny, removed sponsor, expired
  envelope or binding, executions above envelope, undelegated action, stale delegation), exact
  executor principal, capture intent with the executor, activation with strict fakes (envelope
  limits, retry and unchanged-scope replay, refusals), regional restart LIST (owned Pods only,
  truncated/remaining/oversized/denied/deleting), real-TLS restart query (128 Pods; oversized
  answer is a closed failure and keeps the standby), hub-held source reader.
- Custody (real PostgreSQL, compiled hub-runtime grants): concurrent duplicate polls make one
  occurrence; shared workload window across two policies; window reopens after a time shift;
  independent workloads; one suppression row per reason, saturating count; executions ceiling
  and its CHECK; single link/refusal per occurrence; suspended, stale, replaced-workload, other
  scope and unaudited acceptances refused without spend.
- Installed (`ASSERVAT_JOURNEY_FOCUS=policy`, new `[continuation-policy]` CI suite): 823 s
  (go test 815 s). Activation 9 s after the envelope was applied; the killed container's capture
  ran under `policy:<uid>` (restart 1) and the Keycloak user downloaded it (354 bytes) 42 s
  after start; a 150-second three-replica storm (14 kills, 11 observed restarts) admitted one more
  occurrence (2 in total), counted the other 10 as suppressed, kept 3 watermark rows and 1
  suppression row, and no capture followed in the 30 quiet seconds. Restart focus regression:
  741 s, passed. Details in [implementation progress](../implementation-progress.md).
- PR #55 CI: the first CI policy run refused the first occurrence as `unavailable` (the regional
  exchange failed on the Pod read and the review was not repeated); fixed by the bounded review
  retry above. The storm is now 90 s (it saturates the workload window within the first minute).
  Local re-run: 759 s go test, passed (capture 44 s after start; storm 11 kills, 11 observed
  restarts, 2 occurrences, 10 suppressed, 1 suppression row, 3 watermark rows).

## Next increment

Log/resource/probe detectors (node-local, watch-based), policy grants for intrusive actions,
browser UI for activation and status, policy deactivation/replacement in the UI, and the
all-replica selection modes beyond `triggeringPod`.
