# ADR-240 — Retention impact preview (S-06 increment 11)

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-PRV-002 (policy updates first produce a bounded impact preview: affected classes,
counts, earliest deletions, storage-lock conflicts and incomplete clusters), SC-PRV-009, S-06
(TASK-07). Plan: `docs/reviews/s06-plan-2026-10-26.md` increment 11 (feature F13), first-release
scope by the maintainer decision of 2026-10-26 (§2.4). Builds on ADR-055 (effective cutoffs are
monotonic overlays), the migration-17 catch-up (`docs/architecture/retention-catchup.md`) and the
browser-only pattern of ADR-237. Migration 00093 was assigned alongside the parallel S-06 migrations
00090 (ADR-237), 00091 (ADR-238) and 00092 (ADR-239); see "Migration".

## Problem

A retention administrator changes EvidenceRetentionPolicy objects through Kubernetes. Applying a
shortening is the authorization to enforce it on retained evidence (REQ-PRV-002), and the catch-up
then moves effective deadlines earlier, possibly closing access at once. Nothing showed beforehand
how many stored artifacts a change would affect or how soon they would become unreadable or due
for deletion, and `kubectl --dry-run=server` checks only schema and admission.

## Decision

1. **One read-only operation, `preview_retention_change(changes)`**, on the shared browser
   operation route (`/api/v1/operations/preview_retention_change`), audited on the normal lane.
   Each of 1–16 changes is an EvidenceRetentionPolicy `create` (spec), `update` (existing UID and
   spec) or `delete` (UID) in the hub control namespace, or with `source_cluster_id` in that
   cluster's local source. Specs are decoded by `kube.RetentionPolicySpecDecoder` with the same
   embedded schema and mapping as observed policies (an empty hub scope is the baseline; a local
   empty scope never is).
2. **Browser only.** REQ-PRV-002 places the preview with policy administration, and evidence MCP
   offers no administrator tools (specs/permissions.md, specs/apis.md). The contract carries
   `"transports": ["browser"]`; the MCP handler neither lists nor accepts it (the ADR-237
   `InvestigationTool.MCP` mechanism, applied identically here so both branches merge cleanly).
3. **Authority: current fleet operators.** Retention administrators are Kubernetes writers of the
   protected control namespaces and have no mapping to browser identities. Retention policies are
   installation-wide administrator configuration, so the preview is offered to the
   installation-wide administrator of the protected fleet administration (ADR-193:
   configured issuer, client and subjects/groups, not suspended), reusing
   `fleet.Administration.Operator`. The check precedes decoding and every catalog read and is
   repeated on the final identity check. Delegated retention administration has no browser
   identity mapping yet; it is not offered.
4. **The catch-up's functions, not a copy.** The service reads (a) every retention source with its
   ordinary readiness (`acceptedRetentionSource`: accepted, fresh, audited, caught up, not
   recovery-blocked) and its latest accepted snapshot, in one short transaction under the usual
   root/source share locks, and (b) at most 10,000 retained context registrations whose effective
   deletion deadline has not passed, in a second lock-free transaction of keyset pages of 1,000
   over the catch-up's `retention_context_scan` index, selecting only the columns the existing
   `retainedContext`/`admittedRecord` readers use, plus each shortened artifact's current lifecycle
   decision for its accumulated policy origins. It applies the changes to the changed source's
   latest accepted snapshot (an update keeps the UID with generation + 1; a create gets a fresh
   placeholder UID) and runs `HistoricalSourcePolicies` and `ApplyRetainedObligation` per artifact,
   hub first, carrying merged origins forward exactly as successive checkpoints would. The result
   is what reconciliation records once the change is accepted. Both functions only shorten, so a
   longer maximum never moves a bound date and a delete shortens nothing.
5. **Unknown and incomplete are reported, never assumed.** An artifact for which a newly
   encountered namespace/workload label selector would need historical labels (the catch-up
   stops such a page) is `Unknown`; so is a retained row that does not decode, grouped as
   `unknown`/`other`. A cluster is incomplete (`SourceUnavailable`) when its local source, or the
   hub source, is not ready, or a proposed local policy targets a cluster without an accepted local
   source (the proposal is still applied to that cluster's artifacts). An update or delete of a
   UID the source does not hold is reported in `not_evaluated` (`UnknownObject`), as is a change for
   a cluster with more than one local source (`SourceAmbiguous`). A scan beyond 10,000 sets
   `scan_limited`; counts and dates are then lower bounds. `complete` is false in each case.
   Recovery outages and identity or fleet-settings failures refuse the preview.
6. **Result.** Totals (`artifacts_scanned`, `affected_total`, `read_closed_total` — access would
   end at once, `deletion_due_total` — deletion would be due at once, `unknown_total`), the
   earliest new access end and deletion dates, and up to 32 groups per cluster, privacy class and
   evidence type (earliest new deletion first) with `groups_total`; up to 32 incomplete clusters
   with `incomplete_total`; `not_evaluated`; `baseline_changed` when the proposed hub would no
   longer hold exactly one baseline (new collection would be suspended). No artifact, case,
   workload or principal identifier is returned. The largest reply measured 16.5 KiB, inside the
   shared 24 KiB operation reply, so no paging is needed.
7. **Console.** `/retention-preview` (`RetentionPreviewWorkspace`): a JSON change list, Preview,
   the totals, earliest dates, the group table, incomplete clusters and unevaluated changes, and
   the reminder that policies are applied with kubectl or GitOps.

## Remaining limits (recorded against REQ-PRV-002)

- **Storage-lock conflicts** are not reported: the product has no holds or immutable-storage locks
  yet (REQ-PRV-005). When holds land, the preview must report artifacts whose shortening a hold
  would defer.
- **Only retained context artifacts** are evaluated, the only producer mapped into retained input
  today (`docs/architecture/retention-lifecycle.md`). Case and audit metadata maxima are not
  previewed.
- **Accepted topology is not read:** sources are the SQL retention sources; a local source that
  the installer topology requires but that was never begun is treated like a missing local source.
- **Delegated retention administrators** cannot use the browser preview (no identity mapping).

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Unobserved: no installation runs retention changes yet. Harm of absence: a shortening applied blind can close access to evidence a team is still using, immediately and irreversibly. |
| 2 | Risk accepted | Yes: the maintainer decision of 2026-10-26 puts F13, with its spec behaviour, in the first release. |
| 3 | Typical deployments | Every deployment whose administrators change retention; an uncommon, administrator-only path. |
| 4 | Precedent | Rarely provided (plan §2.1); S3 lifecycle and Kubernetes offer dry-run validation only. The closest internal precedent is ADR-237. |
| 5 | Privileges added | None: the hub-api's existing `hub-metadata-read` credential already selects every table read (`retention_source`, `retention_checkpoint`, `retention_catchup`, `retention_decision`, `context_capture`, `custody_attempt`) and holds the share-lock columns; the custody test role mirrors exactly that subset. New exposure: fleet operators see aggregate retention counts and dates per cluster and class, no evidence or identifiers. |
| 6 | Failure/degraded states | 1: `Unknown` per artifact without qualified selector history. Incomplete clusters and limited scans are reported facts of the result, not service states; refusals (`PreviewTooLarge`, `InvalidProposal`, `AdministratorRequired`) are not states. |
| 7 | Self-configuration | No: constants (16 changes, 10,000 artifacts, pages of 1,000, 32 listed groups and clusters). |
| 8 | External dependencies | None new (PostgreSQL, the existing fleet ConfigMap). |
| 9 | Cost at scale | Per preview: 2 identity resolutions, 1 fleet settings observation, 1 recovery read, 1 short sources transaction (per source: readiness and latest snapshot decode), 1 scan transaction of at most 11 statements. Measured on real PostgreSQL (see Qualification): 28 µs per artifact read and 3 µs evaluated without `-race` (436 µs and 12 µs under `-race`), about 0.3 s for the 10,000 bound (extrapolated, not measured at 10,000); about 3 MB per page of 1,000 rows. No watch, background work, lock held during the scan, or stored state. |
| 10 | Upgrade/rollback | Additive: migration 00093 only extends the two operation-name functions; older binaries never serve the name; removing the route disables it. |
| 11 | Smaller fix | Showing each artifact's effective deadline does not answer "what would this change do"; dry-run checks admission only. Reusing the catch-up functions, the existing reader credential and the fleet role is the smallest form. |

Benefit accepted by the maintainer, cost small: proceed.

## Migration

`migrations/00093_preview_retention_change.sql` redefines `operation_audit_lane` and
`operation_audit_human_input_valid`, copied from the latest definition (00092, ADR-239), with
`preview_retention_change` added. The list therefore keeps `list_capture_history`,
`get_capture_settings` (00089, ADR-236), `preview_access_change` (00090, ADR-237),
`transfer_share` (00091, ADR-238) and `stop_future_sharing` (00092, ADR-239). Schema head 93; the
ADR-227 floor stays 81. The branch is rebased onto the ADR-239 branch and installs once 00092 is
merged.

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-06-increment-11-retention-impact-preview-adr-240-2026-10-27).
