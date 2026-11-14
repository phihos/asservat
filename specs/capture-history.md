# Capture history and repeating requests

Users MUST be able to revisit captures for a workload or selector and repeat their settings without re-entering them. History is a view over accepted capture rows in [hub persistence](persistence.md); it adds no CRD, collector or execution API.

## REQ-HIS-001 — Find previous captures for a selector

**Recent captures** on the target page and **Repeat capture** on each authorized capture show request time, origin (manual, policy, discovery), permitted requester, action kinds, outcome, evidence and settings availability and a link. Pending, failed, cancelled and partial captures are included; a request refused before acceptance is not history. A row exists from acceptance, before evidence. The default filter is manual captures, newest first, so trigger storms do not bury them; policy and discovery filters are explicit. Suppressed triggers appear in policy status, not in history.

History groups captures by a **selector key**: cluster, namespace and the authored workload kind/name or the canonical pod-label expression (sorted `matchLabels`). Rollouts and a workload recreated under the same name keep the key ([REQ-TGT-001](targets.md)); UIDs are per-capture provenance. Different label expressions are different selectors even if they match the same pods. Each capture also stores a **settings digest** of its normalized collection settings (excluding IDs, times, grants, reason and sharing), so identical settings can be grouped. Both are SHA-256 over RFC 8785 JSON. Grouping is presentation, never authorization (REQ-HIS-003).

### SC-HIS-001

Given two captures with different packet filters for one Deployment, when its pods roll or it is recreated under its name, then both remain listed under it. Reordered `matchLabels` give the same history; a different selector matching the same pods does not. A user without rights to a record's audience does not see it.

## REQ-HIS-002 — Repeat as a fresh, reviewable request

**Repeat capture** restores a draft from the accepted capture's parameter snapshot, not from today's recipe of the same name: authored target, collection settings, expanded recipe, pinned dependency versions and requested retention, plus original effective values where they were clamped. The user reviews differences against today (pod count, capabilities, privacy, retention, limits, approval) and selects **Collect again**; editing opens the normal editor. Pinned versions that are missing or disabled block the repeat; an upgrade is a visible edit. A draft collects nothing.

The repeat is a new capture with its own ID, requester, execution digest and idempotency key, and an optional `repeatedFromCaptureID` that grants no access to the original. It is checked against current rights, ceilings, capacity and approvals: an old grant never covers it, an intrusive repeat needs its own approval, and it is charged to the normal rate and storage limits. It resolves current pods of the named workload and current members of process selectors and peer queries. An exact Pod or `selectedPID` that is gone asks **Choose a current target/process**; a policy occurrence that used `triggeringPod` needs an explicit pod choice. Ongoing actions repeat as a finite manual session without prehistory (REQ-LIF-005); enabling monitoring is a separate policy action.

Grants, permits, deadlines, credentials, idempotency keys, sharing and the reason are not restored; secret references are re-resolved under current scope. Retries of the same submission reuse its idempotency key; another **Collect again** is a new capture. Repeating a Failed or Indeterminate capture is a deliberate new collection, never an automatic retry. The [assessment](capture-assessment.md) is recomputed; an old verdict is not reused.

### SC-HIS-002

Given a capture of two workers with packet context, when a maintainer repeats it, then settings are restored, current pods and processes are resolved and differences are shown. A double click creates one capture. The old ad hoc grant is not reused. A gone process asks for a choice; repeating a policy occurrence does not enable monitoring.

## REQ-HIS-003 — Who sees history and for how long

A record is visible to its requester while they keep scoped rights, and to maintainers whose current rights cover the record's audience. A new owner of a workload does not see a former owner's records. An evidence share grants no history or settings. Listing, details, lineage and repeat previews follow the same rule; repeat also needs collection rights. Unauthorized records get the uniform unavailable response.

Each accepted capture writes its parameter snapshot (authored spec plus expanded recipe and composition) as a PostgreSQL row in the acceptance transaction ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D8). It holds no credentials, reason or captured output, and has no size cap beyond the Kubernetes object size. Summaries and snapshots live for the case-metadata lifetime (default 90 days, within the administrator maximum); values derived from evidence (discovery) keep the evidence's earlier deadline. Rows have no count cap: they expire, lists use keyset pagination, and storms are bounded by rate limits (ADR-335 D8). Expired settings show **Parameters expired/unavailable** and are never rebuilt from audit or backups. Viewing or repeating never extends any lifetime.

### SC-HIS-003

Given expired evidence but a settings snapshot within its lifetime, when the owner opens history, then they can preview a repeat. After the snapshot expires, history says repeat is unavailable. A new owner or share recipient cannot read old settings, and a discovery-derived filter does not outlive its source.

## REQ-HIS-004 — Browser and MCP

`list_capture_history` takes exactly one of `target_handle`, `target_ref` or a cluster plus `target` selector, an optional origin filter (default manual), cursor and limit (default 20). Authorized namespaces and audiences are resolved once per request (ADR-311) and applied as a SQL filter. Pages are keyset on accepted time then capture ID; no hidden totals.

`get_capture_settings(capture_id)` returns the settings projection: target, expanded recipe, dependency pins, requested retention, settings digest, original execution digest and expiry. An oversized snapshot returns `SettingsTooLarge` with a browser link; repeat by reference still works. The browser reads the full snapshot in one response.

`preview_capture(history_capture_id, reason?, sharing?)` returns the normal preview and `plan_digest` for a repeat; it excludes target, diagnostic, preset and retention inputs. Edits use a normal preview with `repeated_from_capture_id`. `request_capture` with `expected_plan_digest` and an idempotency key is the only submission. Both read tools need `evidence:read`; previews and submissions also need collection rights and `evidence:capture`. `get_capture` keeps working after the history row expires.

For a [capture-profile](capture-profiles.md) composition, the snapshot also stores components, typed edits, resolved definition digests and the action map, and a repeat uses those versions, not today's defaults. For a [recording save](recording-saves.md), the settings are the policy, action IDs, lookback and reason, and a repeat opens a new save preview on current sources or reports `NoCurrentSource`.

### SC-HIS-004

Given an agent sees a capture in history, when it calls `preview_capture` with `history_capture_id` and submits the preview, then one new capture uses the retained settings under current authorization. Combining `history_capture_id` with another target is rejected. Share-only access, revoked access, expired settings and missing dependencies cannot be bypassed.
