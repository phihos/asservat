# ADR-229 — Policy deactivation, console policy page, off-loop policy captures

Date: 2026-10-26. Status: accepted; implemented; qualification results below.
Requirements: REQ-AUT-001/003 (ADR-059), REQ-TRG-005, S-03 (TASK-04). Extends
[ADR-228](228-restart-triggered-policy-captures.md).

## Problem

ADR-228 could start a hub-held restart policy but stop it only through Kubernetes (suspending or
deleting the DebugPolicy, or removing `spec.automation`), which the team member who activated it
usually cannot do. Complexity-gate item 10 (disabling is straightforward and tested) therefore was
not met for the person who turns a policy on. The console had no policy screen, and the poll loop
ran each capture inline, so one capture (up to 45 s) delayed every other policy's poll.

## Decision

1. **`deactivate_policy`** (MCP and the browser generic operation route, CSRF and
   `Idempotency-Key` like `activate_policy`). The current human needs the team authority that
   sponsors activation: a current, undenied `workload-maintainer` group assignment of the policy's
   delegating AccessBinding (`authorization.PolicyStopEligibility`, `ScopeEligibility` on the
   policy's workload, so deny precedence and freshness apply), plus `evidence:capture`. No new
   role: a permission administrator already stops a policy through Kubernetes, which needs no
   operation here. The creator alone (departed from the team) cannot stop it; the executor cannot.
2. **Deactivation clears `policy_source.active_id`** under the policy-source row lock
   (`DeactivatePolicySource`, `active_id=$3` compare-and-set). Every binary since migration 00019
   already treats a missing active acceptance as "not accepted": `ListActivePolicies` stops
   listing it at the next cycle, a tick already in flight is refused under the same lock, and
   every capture eligibility point (`acceptedPolicyIn`) refuses the executor, so an in-flight
   capture is refused at its next check; one already started in the region completes and stays
   (a start is never undone). An older binary honours it too, so migration 00083 only
   adds the operation name to the two SQL operation-audit functions and the ADR-227 floor stays at
   81 (schema 83). Repeating it for the same acceptance is a replay; another current acceptance (a
   concurrent replacement) is a conflict.
3. **Nothing is refunded or deleted.** `executions_spent`, occurrences, suppression counts,
   watermarks, captures and evidence stay. Status of a deactivated policy reads its latest
   acceptance (`LatestPolicyAcceptance`) and reports `deactivated`.
4. **Reactivation is a fresh acceptance of a changed scope.** The existing
   `UNIQUE(root_id, policy_uid, scope_digest)` already makes an unchanged revision unacceptable a
   second time; `activate_policy` now reports this as `PolicyDeactivated` instead of `Conflict`,
   and a retried activation under the old key no longer reports the deactivated acceptance as
   active. To activate again, the maintainer changes the DebugPolicy (a new generation). This keeps
   ADR-228's rule that stopping and starting can never reset a policy's spend or expiry.
5. **Audit.** The call goes through the existing two-phase encrypted operation audit (intent
   before the operation, outcome with `effect: accepted` and the acceptance ID in the digested
   output). The deactivation is a restrictive change, so the SQL effect may precede the outcome
   record (ADR-055); a lost outcome leaves the policy stopped. No new audit format or prefix.
6. **Console `/policies`.** A page in the React console where the user names a hub-held policy,
   sees its content-free status (state, executions, expiry, watched Pods, occurrences with links
   to their captures, suppression counts by reason) and presses Activate or Deactivate. It uses
   the generic operation route, the session CSRF token and one idempotency key per pending
   command (kept on an uncertain transport failure, dropped on a definite result). Looked-up names
   live only in the tab; there is no policy listing operation (listing would need `list` RBAC on
   hub DebugPolicies and a new operation, deferred). The capture page links to it. The request
   function of `capture/http.ts` is shared (`postOperation`), not copied. No new dependency.
7. **Captures off the poll loop.** `PolicyTrigger.Run` starts the captures of one tick on one
   goroutine per policy and joins them before returning (deployment shutdown already waits for
   `Run`). A policy whose previous captures still run is not polled that cycle (`tick/busy`); its
   next poll coalesces the restarts in between (counted `coalesced`, the existing missed-poll
   rule). At most one goroutine per active policy (`ListActivePolicies` is bounded at 65).
   `Cycle`/`Tick` remain synchronous for direct callers.

## Complexity gate (AGENTS.md)

1. Problem: a team cannot stop the policy it started without Kubernetes write access — every
   activated policy needs a stop; frequent, harmful (unwanted captures until expiry, max 1 h in
   the installed envelope). Inline captures: hypothetical at one policy, real with several.
2. No; the maintainer asked for disabling to be straightforward (gate item 10).
3. Typical: every policy user.
4. Comparable tools (Robusta playbooks, Kubernetes CronJob `suspend`) offer a stop that keeps
   history; same here.
5. No new privilege, credential or network access; hub-api's existing `active_id` UPDATE grant.
6. Degraded states added: 0 (a stopped policy is the existing not-accepted state).
7. No configuration.
8. No external dependency beyond the existing ones.
9. Cost: one SQL transaction per deactivation; status adds one indexed read for a deactivated
   policy; the console adds no polling (status on demand). Capture goroutines: ≤ 1 per active
   policy (≤ 65).
10. Additive migration (two function bodies), floor 81 kept, older binaries honour a
    deactivation; disabling is now one operation, tested in unit, real PostgreSQL and installed
    runs.
11. Documenting "ask an administrator to suspend the DebugPolicy" does not meet the maintainer's
    straightforward-disable requirement for the activating team.

## Qualification

See [implementation progress](../implementation-progress.md) for the commands and results.

## Next increment

A policy listing operation (needs `list` on hub DebugPolicies), log/resource/probe detectors,
policy grants for intrusive actions, all-replica selection.
