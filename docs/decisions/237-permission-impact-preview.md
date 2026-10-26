# ADR-237 — Permission impact preview (S-06 increment 10)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-PER-002 (bounded configuration impact preview using the real evaluator), S-06
(TASK-07). Plan: `docs/reviews/s06-plan-2026-10-26.md` increment 10 (feature F12), first-release
scope by the maintainer decision of 2026-10-26 (§2.4). Builds on ADR-234 (`explain_access`).
Number and migration 00090 were assigned with the parallel S-06 increments 5 (00088, ADR-235) and 6
(00089, ADR-236); see "Migration" below.

## Problem

An administrator changing AccessBindings can validate the objects with
`kubectl apply --server-side --dry-run=server`, but that checks schema and admission only. Nothing
shows whose collect, read or download access a change would grant or remove before it is applied,
so a mistaken deny or removed allow is noticed only when a team is refused, and a too-broad allow
only by reading every binding.

## Decision

1. **One read-only operation, `preview_access_change(changes)`**, on the shared browser operation
   route (`/api/v1/operations/preview_access_change`), audited on the normal lane like
   `explain_access`. Each of 1–16 changes is `create` (AccessBinding spec), `update` (existing UID +
   new spec) or `delete` (UID of an AccessBinding or PermissionSource). Specs are decoded with the
   same embedded AccessBinding schema and checks as observed bindings
   (`kube.AccessBindingSpecDecoder`), so the preview never accepts what observation would reject.
2. **Browser only.** REQ-PER-002 makes the preview part of the browser query contract and adds no
   admin tool to evidence MCP. The canonical contract entry carries `"transports": ["browser"]`; the
   MCP handler neither lists nor accepts it (`InvestigationTool.MCP`). The S-06 plan row said "1
   tool"; the spec sentence decides.
3. **Administrator authority is the current fleet operator** (ADR-193 protected fleet
   administration: configured issuer, client and subjects/groups, not suspended), checked before
   any proposal is decoded or projection read, and again on the final identity check. It is the
   only existing installation-wide administrator role expressed for browser identities; no new role
   or configuration is added. The Kubernetes-side permission administrators and delegated writers of
   ADR-189 are Kubernetes users/groups with no mapping to browser identities, so delegation-scoped
   preview is not offered (see Narrowing). A fleet operator administers the whole installation; the
   targets are limited to its enrolled clusters (the hub and the guarded cluster catalog read at
   process start). Cells in any other cluster are `Indeterminate`/`ClusterUnavailable`.
4. **Targets are workload scope cells of the current accepted projection, not a pod listing.** For
   every namespace that a proposed binding names or that holds an updated/deleted object, the cells
   are each workload UID named by a current basis or by the proposal, plus one cell that stands for
   every other workload of the namespace (`other_workloads`). Assignments are scoped to
   cluster/namespace/workload, so these cells cover every workload exactly; no regional Kubernetes
   read is needed. More than 1,000 cells, or more than 1,024 current bases, refuse the preview
   (`PreviewTooLarge`). One SQL transaction under the shared stream lock reads all cells with the
   same `permissionProjection` as the capture and read paths (`Permissions.PreviewProjections`).
5. **The real evaluator, not a copy.** For each cell the proposal removes the rows of updated or
   deleted objects and adds the candidates that the observation's own `ProposeBinding` derives for
   the cell (placeholder assignment IDs, the proposal's spec digest; never persisted). Each subject
   whose rows were added or removed is evaluated before and after with `authorization.Decide`,
   which runs `ScopeEligibility`'s evaluator and the same reason mapping as `Explain`. A subject is
   evaluated as a principal holding only that subject (a group as one member with no other groups)
   with every client scope, so the result describes configuration, not a client. Group members are
   never enumerated; no catalog, evidence or retained audience is read.
6. **Incomplete data is Indeterminate, never Allow.** A cell whose projection is stale or
   unreadable (`PermissionObservationStale`, `ServiceUnavailable`) or outside the enrolled clusters
   (`ClusterUnavailable`) is reported in `unavailable` with decision `Indeterminate` and is not
   evaluated; `complete` is then false. A stale projection inside an evaluated cell stays
   `Indeterminate` on both sides through the evaluator itself. Recovery outages and identity or
   fleet-settings failures refuse the preview.
7. **Result.** `complete`, `targets_evaluated`, `deltas_total` and up to 64 delta rows (cluster,
   namespace UID, workload UID or `other_workloads`, subject, operation, before, after, after's
   unmet condition), trimmed further to stay inside the shared 24 KiB operation reply; up to 16
   unavailable rows with their total; and `unmatched`, the updated/deleted UIDs that hold no current
   assignment. A fixed reviewed message; nothing caller- or Kubernetes-supplied is echoed beyond
   the identifiers the operator submitted or administers.
8. **Console.** `/access-preview` (`AccessPreviewWorkspace`): a JSON change list, Preview, the
   delta table and the Indeterminate targets, with the reminder that changes are applied with
   kubectl or GitOps (REQ-UI "configuration previews hand administrator writes back to
   Kubernetes/GitOps").

## Narrowing (recorded against REQ-PER-002)

- **Who:** installation-wide fleet operators only. Delegated (namespace-scoped) permission writers
  keep `kubectl --dry-run=server` until a browser-identity mapping for the ADR-189 delegation
  envelope exists.
- **What:** AccessBinding create/update/delete and PermissionSource delete. A created or edited
  PermissionSource derives subjects from live namespace metadata and qualified protection, which
  the preview does not observe; such changes are refused as `InvalidProposal`.
- **Assumes acceptance:** admission delegation, automation envelopes and acceptance audit are not
  simulated; the preview shows the effect once the objects are admitted and accepted.
- **Result bound:** 64 delta rows and a 24 KiB reply (the shared operation limit) instead of
  256 KiB, with totals. Per-delta contributing revisions and freshness expiry are not returned;
  the reply's metadata deadline bounds its validity.
- **Subjects:** only subjects named by added or removed assignments, each in isolation; a user's
  combined access through several groups is not computed (that needs group membership, which is
  never enumerated).

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Unobserved: no installation runs binding changes yet. Harm of absence is a wrong deny (teams blocked until noticed) or an overly broad allow (evidence exposure) applied blind. |
| 2 | Risk accepted | Yes: the maintainer decision of 2026-10-26 puts F12 in the first release. |
| 3 | Typical deployments | Every deployment whose operators change bindings; an uncommon, operator-only path. |
| 4 | Precedent | GCP IAM Policy Simulator, AWS IAM policy simulator, `kubectl auth can-i --as`; `kubectl --dry-run=server` validates but does not evaluate. |
| 5 | Privileges added | No credential or grant: the hub-api's existing `hub-metadata-read` credential (table SELECT on `permission_basis`/`permission_assignment`, already used by the projection reader) and the existing protected fleet settings reader. No Kubernetes, collector or evidence access. New exposure: fleet operators, the installation-wide administrators, can see how bindings affect the subjects their proposal names or removes (never group members or evidence). |
| 6 | Failure/degraded states | 1: `Indeterminate` per unavailable cell (stale/unreadable projection or non-enrolled cluster). Refusals (`PreviewTooLarge`, `InvalidProposal`, `AdministratorRequired`) are not states. |
| 7 | Self-configuration | No; constants (16 changes, 1,000 cells, 64 rows). |
| 8 | External dependencies | None new (PostgreSQL, the existing fleet ConfigMap). |
| 9 | Cost at scale | Per call: 2 identity resolutions, 1 protected fleet settings observation (as the fleet bootstrap route: two ConfigMap reads plus the admission-guard check, a few hub Kubernetes API reads), 1 recovery read, 1 SQL transaction (1 stream read, 1 basis list ≤1,025 rows, ~5 queries per cell; typical 1–10 cells, worst 1,000), evaluation of ≤ cells × subjects × 3 operations × 2. No watch, no background work, nothing persisted. Independent of workload/node count; linear in named workloads of the affected namespaces. |
| 10 | Upgrade/rollback | Additive: migration 00090 only extends the two operation-name functions; older binaries never serve the name; removing the route disables it; no state to migrate. |
| 11 | Smaller fix | Documentation or dry-run does not show cross-principal effects; `explain_access` evaluates only the caller. Reusing the evaluator, the projection reader and the fleet role is the smallest form. |

Benefit accepted by the maintainer, cost small: proceed.

## Migration

`migrations/00090_preview_access_change.sql` redefines `operation_audit_lane` and
`operation_audit_human_input_valid` (copied from 00087) with `preview_access_change` and, so that
whichever of 00089/00090 applies last keeps every name, the planned increment 6 names
`list_capture_history` and `get_capture_settings` (no binary serves those yet). Increment 5
(00088, PR #74) adds no operation name. Schema head 90; the ADR-227 floor stays 81. The schema
bundle requires contiguous files, so this branch installs only once 00088 and 00089 are merged;
merge it after them or renumber.

## Qualification

- Unit tests over the real evaluator: `internal/domain/configuration/access_preview_test.go`
  (added deny, removed allow, scope narrowing, unavailable/foreign cluster Indeterminate, stale
  projection never Allow, 17 changes / 1,001 targets refused, invalid proposals, 64-row bound),
  `internal/application/authorization/access_preview_test.go` (fleet operator allowed; other
  groups, another client and suspended administration refused before any read; limits; recovery),
  `internal/transport/presentation/access_preview_operations_test.go` (contract-valid reply,
  `AdministratorRequired`, wire refusals, reply budget, browser-only contract),
  `internal/adapters/kubernetes/access_binding_spec_test.go` (decoder),
  `internal/transport/mcp/access_preview_test.go` (composed for the browser route, absent from MCP
  `tools/list`, an MCP `tools/call` never reaches the use case; fails without the filter), console
  unit tests.
- Not measured: the time of a worst-case 1,000-cell preview. The request keeps the ordinary
  five-second window; a preview that cannot finish in it is refused, never partially answered.
- Real PostgreSQL: subtest `permission-impact-preview` of `TestPermissionAuthorityWithRealServices`
  (custody fixture) reads three cells under one stream lock, reports the unmatched UID and, with the
  real evaluator, shows that deleting a namespace-wide allow removes access from the proposal-named
  and other workloads but not from the workload a narrowed binding keeps.
- No installed qualification.
