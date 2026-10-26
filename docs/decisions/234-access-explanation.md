# ADR-234 — Caller-only access explanation (S-06 increment 7)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-PER-002 (effective-access explanation, own target only), REQ-PER-006
(explainability), S-06 (TASK-07). Plan: the S-06 plan `docs/reviews/s06-plan-2026-10-26.md`,
increment 7 (feature F11). Number and migration 00087 were the next free ones on `origin/main` when
written; parallel S-06 increments may require renumbering before merge.

## Problem

Every refused investigation operation returns the same `NotAvailable` reply, deliberately: the
reply must not reveal whether a workload exists or who else may access it. A developer therefore
cannot tell whether they lack a binding, are named by a deny, use a client without the needed
scope, or hit stale permission data, and has to ask an administrator to read AccessBindings for
them.

## Decision

1. **One read-only operation, `explain_access(target_ref, operation)`**, on MCP and the shared
   browser operation route, audited on the normal lane like `get_policy_status`. `target_ref` is the
   `preview_capture` workload reference; `operation` is `capture`, `read` or `download`
   (`CollectContext`, `ReadApproved`, `DownloadApproved`). No client scope is required: a missing
   scope is one of the answers. The design-only console operation that also took a `principal`
   (administrator explanation of another principal) is renamed `explain_principal_access`; it stays
   unimplemented.
2. **The real evaluator, not a copy.** `AccessExplainer` (C-03, application) reads recovery, resolves
   the workload through the same `ContextTargets.ResolveWorkload` as the preview, reads the same
   permission projection (`postgres.Permissions`) and calls `authorization.Explain`, which runs
   `ScopeEligibility`'s evaluator (`evaluateDetail`). The evaluator itself is unchanged in its
   decisions; it now also records which of its own conditions refused (the matched deny assignment,
   the missing scope, a skipped stale matching allow). `Evaluate`/`ScopeEligibility` discard that
   record. A test asserts that `Allow` coincides with `ScopeEligibility(...).Eligible` for every
   explained scenario.
3. **Result.** `Allow`, `Deny` or `Indeterminate`; the unmet condition (`NoMatchingAllow`,
   `ExplicitDeny`, `ClientScopeMissing` plus the scope, `PermissionObservationStale` for a stale
   projection, deny snapshot or matching allow, `IdentityUnavailable`, `AudienceOverflow`,
   `ServiceUnavailable` for recovery or permission-store outages); the roles that permit the
   operation (from the evaluator's role table); the exact target UIDs; the caller's own contributing
   allow assignments or the deny that names them, each with assignment ID, role, subject kind, basis
   kind/UID and basis digest as revision (at most 32 rows, with the total); on `Allow` the decision's
   validity. A fixed reviewed message per condition; no Kubernetes or caller text is echoed.
4. **Nothing the caller could not already learn.** Details appear only when the projection lists at
   least one assignment that matches the caller (any role, fresh or stale). Such a caller already
   knows the workload through their own binding. Otherwise, and for every target that does not
   resolve (absent, unobservable, unsupported), the reply is the same `Deny`/`NoMatchingAllow` with
   no target and no assignments, byte-identical in the presentation test. Other principals'
   assignments never appear: the evaluator only collects assignments that match the caller. The
   explanation evaluates the target scope only; it reads no catalog, retained audience, share or
   evidence and therefore reveals no evidence existence. Stale rows only decide what to reveal; they
   never authorize anything.
5. **Console.** A "Why?" link (`WhyAccess`) next to the capture workspace's unavailable error and
   preview blockers calls `explain_access` for `capture` on the entered target, only when pressed.
6. **Migration 00087** redefines `operation_audit_lane` and `operation_audit_human_input_valid`
   with the new name (copied from 00086). Schema head 87; the ADR-227 compatibility floor stays at
   81 because older binaries never serve the operation.

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Every refused user today receives a reason-free `NotAvailable` by design; harm is support load, not data exposure. Frequency of support requests unmeasured. |
| 2 | Risk accepted | n/a (adds no risk acceptance); REQ-PER-002 already specifies own-access explanation. |
| 3 | Typical deployments | yes (every user who is refused). |
| 4 | Precedent | `kubectl auth can-i` (self only by default), GCP Policy Troubleshooter. |
| 5 | Privileges added | none: existing hub metadata SQL credential and target resolution; caller's own projection rows only. |
| 6 | Failure/degraded states | 0 new; `Indeterminate` is a result value. |
| 7 | Self-configuration | no. |
| 8 | External dependencies | no new ones (same regional target query as `preview_capture`). |
| 9 | Cost at scale | per call: 1 recovery read, 1 regional target query, 1 permission projection read, 2 audit writes; no watch, no background work; O(assignments on one target) ≤ 256 rows. |
| 10 | Upgrade/rollback | additive; older binaries ignore the name; removing the route disables it. |
| 11 | Smaller fix | Documenting the evaluator rules is not enough: users cannot see their own bindings or token scopes. A query over the existing evaluator is the smallest form. |

Benefit established, cost small: proceed.

## Not done

- Explaining another principal and the configuration/retention impact previews (F12/F13): separate
  increments. `kubectl apply --server-side --dry-run=server` complements, not replaces, them.
- Artifact-level explanation (retained audience, shares, approval grants): explaining an artifact
  would reveal its existence; `get_case` already distinguishes ordinary and shared access.
- Explanation links outside the capture workspace (case and download pages).

## Qualification

Unit tests over the real evaluator (`internal/domain/authorization/explain_test.go`), the
application service with fake ports (`internal/application/authorization/explain_test.go`) and the
audited presentation contract including byte-identical undisclosed replies
(`internal/transport/presentation/access_operations_test.go`), all with `-race`; console unit tests;
`make pre-push`. Migration 00087 is covered by the existing custody/SQL gates in CI (not run locally
for this change); no installed qualification.
