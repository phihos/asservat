# ADR-236 — Recent captures and Collect again (S-06 increment 6)

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-HIS-001–004 ([capture history](../../specs/capture-history.md)), first part;
S-06 (TASK-07/08). Plan: `docs/reviews/s06-plan-2026-10-26.md`, increment 6 (F7/F8).
Maintainer decision 2026-10-26: every specified feature ships in the first release. This
increment is the F7/F8 base; encrypted parameter snapshots, keyed settings digests, the history
eviction ceilings and persisted `repeatedFromCaptureID` lineage are increment 12, with the first
parameterized recipe.

## Problem

A developer who collected a pod-status snapshot during an incident has to re-enter cluster,
namespace, workload and retention to collect again, and cannot see what was collected for the
workload recently. `context_capture` already stores every accepted request with its immutable
scope, but its target identity is inside opaque JSON, so there is no bounded query and no
listing tool.

## Decision

1. **Typed target identity at acceptance (migration 00089, schema 89, floor 81).** Four nullable
   columns on `context_capture`: `history_cluster_id`, `history_namespace_uid`,
   `history_workload_uid`, `history_origin` (`manual` = human executor, `policy` = policy
   executor). A `BEFORE INSERT` trigger fills them from the accepted expectation and scope and
   ignores caller-supplied values; any later change is rejected. One partial index
   `(root, cluster, namespace UID, workload UID, origin, created_at DESC, id DESC)`. No backfill:
   rows accepted before the migration keep `NULL` and are not history. Because the trigger fills
   them, an older binary's inserts during a rolling upgrade are history too, so the ADR-227
   compatibility floor stays 81. The retained capture-intent view is re-created to keep exposing
   every capture column.
2. **Identity, not names.** `list_capture_history(target_ref, origin, cursor, limit)` first
   resolves the named workload to its current namespace and workload UIDs (the existing target
   resolver, as `list_diagnostics` does) and then queries by UID. A namespace or workload
   recreated under the same name has new UIDs and starts an empty history. A workload that does
   not currently resolve has no listable history (uniform `NotAvailable`).
3. **Visibility.** The caller needs current ordinary `ReadApproved` eligibility on the workload
   (otherwise the whole list is refused). Each row is then visible to its original requester
   (issuer, subject, kind; any client) or to a caller whose current contributing assignment is
   part of that capture's retained audience (`CaptureHistoryEligibility`). A newly granted or
   re-created assignment is not in an older capture's audience. A share grants no workload
   assignment, so a share-only recipient sees no history. Denies win as everywhere.
4. **Bounded and evidence-free.** History covers seven days after acceptance (the
   specification's initial case-metadata default, a constant `HistoryLifetime`); older rows are
   neither listed nor repeatable. Pages are newest first, `limit` ≤ 100 (default 20, origin
   default `manual`), and one page examines at most 200 rows; `next_cursor` is an opaque keyset
   position bound to the selector and origin. It needs no caller binding or MAC because every
   page re-authorizes every row. Each entry's phase is derived exactly as `get_capture` derives
   it, in one SQL snapshot (two batched reads per page). No evidence, catalog content, live
   workload capacity or storage binding is read.
5. **`get_capture_settings(capture_id)`** returns the canonical `captureSettings` record of a
   visible entry: the accepted authored target, the recipe spec, the dependency pins and the
   requested retention, with `settings_digest` over the canonical settings and the original
   execution digest. No reason, recipients, grants, credentials or old pod. Data class `extract`.
6. **Collect again = the normal preview.** `preview_capture(history_capture_id)` (mutually
   exclusive with `target_ref`, `preset_ref` and `requested_retention_seconds`) reads the settings
   under the same visibility, then runs the ordinary preview of the original named workload with
   the original requested retention. Every current check of a new preview runs: identity,
   recovery, target resolution and Pod selection, collection eligibility (`evidence:capture`,
   workload-maintainer), capability, retention policy and clamping, storage binding, processing
   coverage and the impact assessment. Nothing old is reused as authority. If the name now
   resolves to another namespace or workload UID, the preview fails with `TargetReplaced`, which
   is reported only after current collection eligibility on the new workload succeeded (no
   existence oracle). The reply carries `repeated_from_capture_id`; `request_capture(preview_id,
   idempotency_key)` remains the only submission and creates a new capture identity with normal
   budgets. A policy occurrence repeats as one manual capture. The original capture's sharing is
   never restored; the caller may add a new capture-time `sharing` instruction (ADR-235) to the
   history branch, checked exactly as on a new preview.
7. **Console.** After "Find diagnostics" the target page shows **Recent captures** (accepted time,
   phase, evidence state, link) with **Collect again**, which opens the normal review stating
   that the settings come from that capture.
8. **Operation names.** Migration 00089 redefines `operation_audit_lane` and
   `operation_audit_human_input_valid` with every name of migration 00086 plus `explain_access`
   (ADR-234, migration 00087) plus `list_capture_history` and `get_capture_settings`, so merge
   order drops no name. Both are normal-lane reads with `context-input/v1`.

The canonical `list_capture_history` contract additionally accepts `target_ref`, the same
selector `preview_capture` takes; the runtime subset implements only that selector.

### Deferred to increment 12 (not designed out)

Encrypted parameter snapshots and protected parameter records, keyed selector/settings digests,
the 1,000/100,000 history ceilings and eviction, `HistoryUnavailable`/`SettingsTooLarge`, discovery
origin, and persisted `repeatedFromCaptureID` lineage on `request_capture`/`get_capture`. For
pod-status the repeatable settings are exactly target, preset and requested retention, which
contain no user-supplied content beyond the workload name, so the accepted scope is the snapshot.
Lineage needs a nullable column on the preview blueprint and the accepted capture; nothing in this
design prevents adding it.

## Complexity gate (AGENTS.md)

1. **Frequency/harm:** every repeat of an incident capture today re-enters four fields and a
   retention; documented friction (plan F7/F8). Not test-induced; no security harm.
2. **Risk accepted:** yes: capture history and repeat are accepted first-release scope (ADR-031
   keep; maintainer decision 2026-10-26).
3. **Typical:** yes, every installation that collects manually.
4. **Precedent:** CI/job run history with "re-run" (GitHub Actions, Argo Workflows) lists runs
   per pipeline and re-runs with current permissions; general product knowledge.
5. **Privileges added:** none. 0 new SQL grants (the hub metadata credential already reads
   `context_capture`), 0 Kubernetes rights, 0 credentials, no collector or worker change. The
   repeat preview uses the existing preview path and its rights.
6. **Failure/degraded states added:** 1 (`TargetReplaced`). History unavailability is the
   existing uniform `NotAvailable`.
7. **Self-configuration:** none (seven days, 100, 200 are constants).
8. **Outside Asservat's control:** none new; the target resolver is the one `list_diagnostics`
   uses.
9. **Aggregate cost:** per list: 1 target resolution (as `list_diagnostics`), 1 indexed keyset
   query of ≤ 200 rows, 2 batched reads for ≤ 100 visible rows, 1 permission projection read.
   Per settings read: 2 indexed reads. Per insert: one trigger evaluation and one index entry
   (≤ 200 bytes). 0 watches, 0 background work; cost does not grow with cluster or node count.
10. **Upgrade/rollback/disable:** additive migration; an older binary ignores the columns (its
    inserts still fill them). Rolling back the image removes the tools; the columns stay inert.
    Tested: custody suite migrates to schema 89 and exercises the trigger, immutability and
    visibility.
11. **Smaller fix:** documenting "repeat by re-entering" leaves the accepted requirement unmet;
    listing without typed columns would scan opaque JSON per workload without an index. This is
    the plan's simplified form (no snapshots, digests or eviction for a settings set that is just
    target + preset + retention).

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-06-increment-6-recent-captures-and-collect-again-adr-236-2026-10-26).
