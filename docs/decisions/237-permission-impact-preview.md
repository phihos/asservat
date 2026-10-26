# ADR-237 — Permission impact preview (S-06 increment 10)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-PER-002 (bounded configuration impact preview using the real evaluator), S-06
(TASK-07). Plan: `docs/reviews/s06-plan-2026-10-26.md` increment 10 (feature F12), first-release
scope by the maintainer decision of 2026-10-26 (§2.4: every spec feature ships). Builds on ADR-234
(`explain_access`). Migration 00090 was assigned with the parallel S-06 increments 5 (00088,
ADR-235) and 6 (00089, ADR-236); see "Migration".

## Problem

An administrator changing AccessBindings can validate the objects with
`kubectl apply --server-side --dry-run=server`, but that checks schema and admission only. Nothing
shows whose collect, read or download access a change would grant or remove before it is applied,
so a mistaken deny or removed allow is noticed only when a team is refused, and a too-broad allow
only by reading every binding.

## Decision

1. **One read-only operation, `preview_access_change(changes, cursor?)`**, on the shared browser
   operation route (`/api/v1/operations/preview_access_change`), audited on the normal lane like
   `explain_access`. Each of 1–16 changes is an AccessBinding or PermissionSource `create` (spec),
   `update` (existing UID and spec) or `delete` (UID). Specs are decoded with the same embedded
   schemas and checks as observed objects (`kube.AccessBindingSpecDecoder`), so the preview never
   accepts what observation would reject.
2. **Browser only.** REQ-PER-002 makes the preview part of the browser query contract and adds no
   admin tool to evidence MCP. The canonical contract entry carries `"transports": ["browser"]`; the
   MCP handler neither lists nor accepts it (`InvestigationTool.MCP`).
3. **Authority is "the administrator's delegation envelope"** (REQ-PER-002), checked before any
   proposal is decoded or permission data read, and again on the final identity check:
   - A current **fleet operator** (ADR-193 protected fleet administration: configured issuer,
     client and subjects/groups, not suspended) is the installation-wide administrator. The
     targets are limited to the enrolled clusters (the hub and the guarded cluster catalog read at
     process start); cells in any other cluster are `Indeterminate`/`ClusterUnavailable`.
   - A **delegation previewer** previews within a delegation envelope of the installed permission
     guard (ADR-189: exact cluster, namespace name/UID, optional workloads, roles, subject issuers).
     The guard's writers are Kubernetes users/groups, which have no mapping to browser identities,
     so each installer-configured delegation names its browser `previewers` (issuer + `User`
     subject or stable `Group` ID). The installer copies delegations with previewers into the
     owner deployment (`public.permissionDelegations`); previewers are not part of the guard and
     grant no Kubernetes write. As the native guard does, every proposed object must fit one of the
     caller's envelopes (cluster, namespace, workloads within the envelope, allowed roles and
     issuers, no automation envelope) and PermissionSource changes are administrator-only;
     otherwise the preview is refused (`DelegationExceeded`) before any projection read. That
     refusal concerns only the caller's own proposed scope and reveals nothing. Updated or deleted
     objects are matched only inside the caller's envelope namespaces (`PreviewRead.Allowed`), the
     envelope namespaces are always read, and an object counts as matched only when that is
     proven: every cell was read (none unavailable), at least one of its current assignments is
     visible, and all of them lie inside the envelope. Any other object (foreign, wider than the
     envelope, hidden by an unavailable cell, without a visible assignment) is neither removed nor
     evaluated: it is reported in `unmatched` exactly like a UID that does not exist (an update
     still adds its proposed rows, as for a nonexistent UID). A
     previewer therefore cannot probe for objects beyond their envelope (Gitar review of PR #77).
     Only cells inside the caller's envelopes are reported.
4. **Targets are workload scope cells of the current accepted projection, not a pod listing.** For
   every namespace that a proposed binding names or that holds an updated/deleted object, the cells
   are each workload UID named by a current basis or by the proposal, plus one cell that stands for
   every other workload of the namespace (`other_workloads`). Assignments are scoped to
   cluster/namespace/workload, so these cells cover every workload exactly; no regional Kubernetes
   read is needed. More than 1,000 cells, or more than 1,024 current bases, refuse the preview
   (`PreviewTooLarge`). One SQL transaction under the shared stream lock reads all cells with the
   same `permissionProjection` as the capture and read paths (`Permissions.PreviewProjections`) and
   records the stream revision.
5. **The real evaluator, not a copy.** For each cell the proposal removes the rows of updated or
   deleted objects and adds the candidates that the observation's own `ProposeBinding` derives for
   the cell (placeholder assignment IDs, the proposal's spec digest; never persisted). Each subject
   whose rows were added or removed is evaluated before and after with `authorization.Decide`,
   which runs `ScopeEligibility`'s evaluator and the same reason mapping and assignment reporting
   as `Explain`. A subject is evaluated as a principal holding only that subject (a group as one
   member with no other groups) with every client scope, so the result describes configuration,
   not a client. Group members are never enumerated (ADR-059: no directory reader); no catalog,
   evidence or retained audience is read.
6. **Incomplete data is Indeterminate, never Allow.** A cell whose projection is stale or
   unreadable (`PermissionObservationStale`, `ServiceUnavailable`) or outside the enrolled clusters
   (`ClusterUnavailable`) is reported in `unavailable` with decision `Indeterminate` and is not
   evaluated; `complete` is then false. A stale projection inside an evaluated cell stays
   `Indeterminate` on both sides through the evaluator itself. A PermissionSource create or update
   is reported in `not_evaluated` as `Indeterminate`/`InheritanceNotAccepted`: the installation's
   reconciler accepts explicit bindings only (`docs/architecture/permission-acceptance.md`:
   namespace-metadata and exec inheritance need their own qualified current-source paths, which do
   not exist yet), so the hub holds no accepted namespace-metadata observation and applying a
   source changes no access today; the message states that an edited source's current
   assignments, if any, stay in effect in the after state of every listed decision. A
   PermissionSource delete removes the source's current
   assignments like a binding delete. Recovery outages and identity or fleet-settings failures
   refuse the preview.
7. **Result, revisions and freshness.** `complete`, `targets_evaluated`, `fresh_until` (the
   earliest freshness expiry of the evaluated projections), `deltas_total`, `unavailable_total`;
   rows of `unavailable` targets and of decision changes (cluster, namespace UID, workload UID or
   `other_workloads`, subject, operation, before/after decision and unmet condition, and for each
   side the deciding assignments: effect, role, subject kind, basis kind/UID, revision = basis
   digest, `proposed` for rows derived from the proposal; on an `Allow` after, its validity);
   `not_evaluated`; and `unmatched` (updated/deleted UIDs without current assignments). A fixed
   reviewed message; nothing caller- or Kubernetes-supplied is echoed beyond the identifiers the
   caller submitted or administers.
8. **256 KiB result in pages.** The listed rows of one result (Indeterminate targets first, then
   decision changes) are bounded to 256 KiB serialized, as REQ-PER-002 requires; `listed_rows` and
   the totals say how much was listed. The result is delivered in pages that each fit the shared
   24 KiB operation reply (MCP's double copy is the reason for that shared limit; raising it would
   widen every audited operation). `next_cursor` (`offset:key`) continues the same request; the key
   binds the caller, the exact proposal and the permission stream revision, so a page from a
   changed projection or proposal is refused (`PreviewChanged`) rather than mixed. Each page
   recomputes the preview within the ordinary five-second request; nothing is stored between
   pages.
9. **Console.** `/access-preview` (`AccessPreviewWorkspace`): a JSON change list, Preview, the delta
   table with the deciding revisions, Indeterminate targets and sources, "Show more" for further
   pages, and the reminder that changes are applied with kubectl or GitOps (REQ-UI "configuration
   previews hand administrator writes back to Kubernetes/GitOps").

## Remaining limits (recorded against REQ-PER-002)

- **Inherited permissions:** PermissionSource create/update is `Indeterminate`, not evaluated
  against namespace metadata, because the product does not accept inheritance yet (above). When the
  namespace-metadata source reconciler lands, the preview must evaluate sources against its
  accepted metadata observation, with stale or missing metadata `Indeterminate`.
- **Admission and automation are not simulated beyond the delegation envelope:** REQ-PER-002 asks
  for decision deltas, not an admission verdict; `kubectl --dry-run=server` remains the admission
  check. The result describes the effect once the objects are admitted and accepted.
- **Subjects:** only subjects named by added or removed assignments, each in isolation; a user's
  combined access through several groups is not computed, because that needs group membership,
  which is never enumerated (ADR-059).
- **Deciding assignments:** at most 8 per side of a delta.

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Unobserved: no installation runs binding changes yet. Harm of absence is a wrong deny (teams blocked until noticed) or an overly broad allow (evidence exposure) applied blind. |
| 2 | Risk accepted | Yes: the maintainer decision of 2026-10-26 puts F12, with its spec behaviour, in the first release. |
| 3 | Typical deployments | Every deployment whose operators or delegated writers change bindings; an uncommon, administrator-only path. |
| 4 | Precedent | GCP IAM Policy Simulator, AWS IAM policy simulator, `kubectl auth can-i --as`; `kubectl --dry-run=server` validates but does not evaluate. |
| 5 | Privileges added | No credential or grant: the hub-api's existing `hub-metadata-read` credential (table SELECT on `permission_basis`/`permission_assignment`) and the existing protected fleet settings reader. New exposure: fleet operators and configured delegation previewers see how bindings within their administration affect the subjects their proposal names or removes (never group members or evidence). |
| 6 | Failure/degraded states | 1: `Indeterminate` per unavailable cell or unaccepted source change. Refusals (`PreviewTooLarge`, `InvalidProposal`, `AdministratorRequired`, `DelegationExceeded`, `PreviewChanged`) are not states. |
| 7 | Self-configuration | No tuning: constants (16 changes, 1,000 cells, 256 KiB result, 24 KiB pages). The delegation `previewers` are authority configuration that REQ-PER-002 needs to name who holds a delegation envelope in the browser. |
| 8 | External dependencies | None new (PostgreSQL, the existing fleet ConfigMap, installer input). |
| 9 | Cost at scale | Per page: 2 identity resolutions, 1 protected fleet settings observation (as the fleet bootstrap route), 1 recovery read, 1 SQL transaction (1 stream read, 1 basis list ≤1,025 rows, ~5 queries per cell), evaluation of cells × changed subjects × 3 operations × 2. Measured worst case: 1,000 cells in 1.27 s read and 1.31 s read+evaluate (real PostgreSQL, `-race`, see Qualification), so no batching was needed. A 256 KiB result takes about 12–15 pages, each recomputed. No watch, background work or stored state. |
| 10 | Upgrade/rollback | Additive: migration 00090 only extends the two operation-name functions; older binaries never serve the name; removing the route disables it; `previewers` and `permissionDelegations` are optional fields. |
| 11 | Smaller fix | Documentation or dry-run does not show cross-principal effects; `explain_access` evaluates only the caller. Reusing the evaluator, the projection reader, the fleet role and the installed delegation envelopes is the smallest form. |

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

- Unit tests over the real evaluator: `internal/domain/configuration/access_preview_test.go` and
  `access_preview_scope_test.go` (added deny, removed allow, scope narrowing, unavailable/foreign
  cluster Indeterminate, stale projection never Allow, 17 changes / 1,001 targets refused, invalid
  proposals, deciding revisions with `proposed`, freshness expiry, PermissionSource create
  Indeterminate, delegated envelope: admitted change, cells outside the envelope omitted, refusals
  for namespace-wide/foreign-namespace/automation/foreign-role/foreign-issuer/source changes, and
  identical replies (`reflect.DeepEqual`) for deleting or updating a binding wider than the
  envelope, or one hidden by an unavailable out-of-envelope cell, and for a nonexistent UID),
  `internal/application/authorization/access_preview_test.go` and
  `access_preview_delegation_test.go` (fleet operator; delegation previewer inside/outside the
  envelope with no read on refusal; non-previewer refused; delegation without fleet
  administration; limits; recovery), `internal/transport/presentation/access_preview_operations_test.go`
  (contract-valid reply with revisions, source Indeterminate, `AdministratorRequired`, wire
  refusals, 600 deltas paged within 24 KiB per page and 200–256 KiB listed in total, foreign
  cursor `PreviewChanged`, browser-only contract), `internal/adapters/kubernetes/access_binding_spec_test.go`,
  `internal/transport/mcp/access_preview_test.go` (absent from MCP `tools/list`, an MCP
  `tools/call` never reaches the use case), console unit tests.
- Real PostgreSQL (custody fixture, `scripts/test-custody.py --run
  '^TestPermissionAuthorityWithRealServices$'`): `permission-impact-preview` (three cells under one
  stream lock, unmatched UID, an envelope-limited read reporting a foreign-namespace object as
  unmatched without reading its namespace, delete of a namespace-wide allow) and
  `permission-impact-preview-1000-targets` (17 accepted bindings naming 992 workloads plus 7
  proposal-named workloads and the other-workloads cell: 1,000 cells read in 1.269 s,
  read+evaluate 1.314 s, under `-race`).
- No installed qualification.
