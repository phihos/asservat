# Authority timing: one check per operation (plan, 2026-11-07)

Status: plan. Step 1 is implemented with live watch (PR #174); step 2 (downloads) is implemented; later steps pending.

## Problem

Request paths re-check authority under several independent five-second windows
(delivery policy via about four Kubernetes API reads per observation, recovery
state, identity snapshot, per-phase budgets) and take the `min()` of them. Checks
take about 1.7 s on a real cluster, so operations lapse mid-request. About 56
installed live-watch runs failed this way, each patched individually.

## Requirement vs agent choice

- Maintainer (AGENTS.md, 2026-10-20): relaxed, bounded recheck intervals are
  authorized; five seconds is not immutable. No authority or retention extension.
  REQ-AUT-004: each query rechecks authorization before output.
- Agent-added: the five-second observation windows (ADR-258 row 2, ADR-310), the
  double policy/recovery reads, and the "five-second freshness re-check" wording
  in specs/live-watch.md.

## Mechanism

1. One interval constant `identity.AuthorityRecheckInterval` (30 s, to be
   measured); the delivery policy keeps the accepted 60 s observation interval.
2. One `OperationAuthority` snapshot per operation, valid until the earlier of
   check time + interval and every original hard end (identity/session, grant,
   watch, lease, privacy, retention, source). Never extended.
3. Context deadlines come once from the operation request window; inner code keeps
   I/O timeouts only, not nested authority minimums.
4. One classifier: transient (adapter/I/O/unavailable) vs denied (explicit
   negative fact) vs ended. Replaces the per-site transient patches.

Invariants: revocation stops disclosure within the recheck interval (≤30 s, ≤60 s
for a delivery-policy change); denial ends a view; no deadline is extended; SQL
effect fences (recovery trust, audit request window, ledger CAS) stay.

## Complexity checklist

Frequent and harmful (every live read); risk already accepted by the maintainer;
all deployments; precedent ADR-220/258 (30 s downloads); no new privileges; net
fewer failure states; no tuning config; no new dependencies; far fewer API reads;
no schema change; the first step is the smallest fix.

## Rollout

1. Live reads use the downloads' cached policy observation instead of the raw
   Kubernetes reader (done in PR #174). Then remove the five-second phase caps in
   live and map adapter errors to unavailable; measure installed read time.
2. Downloads read policy, recovery and processing once per check (done). The
   download authority and environment caps use the recheck interval; the 5 s
   check/policy-read I/O timeout and the catalog record's own 5 s observation
   contract remain. A cached policy observation is reused while valid and
   outliving one check's I/O timeout, so no check straddles its expiry.
3. Introduce `OperationAuthority` and the classifier; delete the per-site patches.
4. Raise identity, eligibility and recovery windows to the recheck interval
   (capture start currently also lapses: PrepareAPIExecution/expired/eligibility).
   Done for the evidence-read recovery reader, the credential
   refresh-scheduling window and the API start check interval; eligibility
   already derives from identity and the 30 s permission stream. The default
   recovery reader keeps five seconds: SQL fences that persist recovery proofs
   (connector enrollment, migration 00049; `capacity_recovery_current`,
   00054/00065/00073) refuse longer ones, which stalled installation when the
   default was raised (2026-11-07). Raising it needs a migration first. Capture start stays bounded near five seconds by
   its start binding, not by these windows: SQL `context_execution.not_after
   <= not_before + 5 s` (migration 00035) and `execution.Binding.Valid`, the
   start phase caps (ADR-292 handoff, regional start, `Execute*`,
   `APIContextWork`), and five-second target, capability, process and
   hub/connector receiver observations. Widening them is a separate step
   (new migration plus peer-observation intervals).
5. ADR-311 and spec/AGENTS.md updates with each step.
