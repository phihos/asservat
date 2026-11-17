# Retention

C-01 owns the policy source, C-15 owns effective evidence deadlines and their
application to existing artifacts, C-21 supplies the Kubernetes and SQL
adapters and C-24 the policy and deadline types. This implements
REQ-PRV-001–004 and the retention parts of REQ-DLD-004 under
[ADR-055](../decisions/055-retained-evidence-cutoffs.md) and
[ADR-330](../decisions/330-event-driven-system-design.md) D1 and D12.

## Policy source

`EvidenceRetentionPolicy` is a namespaced CRD in the hub control namespace,
which is administrator-only
([ADR-328](../decisions/328-administrator-only-namespaces.md)), so Kubernetes
RBAC decides who writes policies. The CRD schema and CEL rules validate shape
only. Status is informational and never authority.

The hub worker's retention follower lists the policies, stores the complete
set in `retention_policy` and then watches from the list's
`resourceVersion`. After every `ADDED`, `MODIFIED` or `DELETED` event it stores
the complete set again; bookmarks only advance the cursor. A watch that the
API server ends is resumed from the last `resourceVersion`; an error or `410
Gone` lists again after a backoff (1 s up to 30 s, like client-go's
reflector). The follower runs under the hub-worker scheduling Lease; its SQL
writes are idempotent per policy UID, generation and spec digest, so a
replaced worker repeats nothing.

Storing the set is one transaction: it locks `retention_policy`, upserts every
new or changed policy, applies it to stored deadlines (below) and writes one
`retention_policy_event` audit row per applied or removed policy. Unchanged
policies write nothing. The set must hold exactly one empty-scope baseline;
without it new collection stops and existing deadlines stay bound.

Local policies in a cluster's connector namespace (pushed by the connector)
are not implemented yet; only the hub control namespace is read.

## Matching

Collection matches the stored set against the target: every policy whose
cluster scope covers the target's cluster applies, and the shortest maximum
wins (`privacy.MatchPolicies`, `privacy.Resolve`). Rules select by privacy
class and evidence type; every collector records evidence as potential user
data. Label selectors use matchLabels semantics against the namespace labels
and the workload labels (Deployment or StatefulSet, or the bare Pod) that
target resolution reads. A saved recording window uses the labels its source
recorded at arming (`SourceSnapshotTarget.Labels`). A target without observed
labels refuses new collection under a covering labeled policy.

## Stored deadlines

Each artifact row keeps its original registration dates and stores the
effective read cutoff (`effective_expires_at`) and deletion deadline
(`effective_delete_by`). Insert initializes them from the registration. A SQL
trigger rejects rewritten registration dates and any later effective date.
An early-erasure decision additionally advances `retention_sequence` with its
exact `retention_decision` row; a policy shortening does not.

## Applying a policy

`retention_policy_effect(effect)` computes, for one policy, the shortened
deadlines of every retained artifact it matches: evidence through
`context_capture` by cluster and native type, capture-history parameters as
case metadata. The effect parameter is computed in Go from the policy
(`privacy.Effect`): the cluster scope, the label selectors, the evidence
maximum per native type, the case-metadata maximum and the deletion budget. Applying it is one
statement:

```sql
UPDATE custody_attempt a SET effective_expires_at = e.expires_at, effective_delete_by = e.delete_by
FROM retention_policy_effect($effect) e
WHERE a.id = e.attempt_id AND (e.expires_at < a.effective_expires_at OR e.delete_by < a.effective_delete_by);
```

`delete_by = LEAST(old, anchor + maximum)` and `expires_at = LEAST(old,
anchor + maximum - budget)`, never before the anchor. A longer maximum, a new
default or a deleted policy changes no row. Admission records the target's
labels on `context_capture.target_labels` (all labels: a later policy may
select any key); a capture-history parameter uses its capture's row. A
labeled policy matches them by jsonb containment. A row without recorded
labels takes the policy across its cluster scope, since a privacy maximum may
only err towards earlier deletion.

An `AFTER INSERT` trigger on `context_capture` and
`capture_history_parameter` applies every stored policy to the new artifact
under a share lock on `retention_policy`. A policy committed while a capture
is admitted therefore either reaches that trigger or sees the admitted row.

## Effects

Capture admission resolves the stored policy set and stores the result on the
new row. Every later effect (publication, catalog visibility, query,
download, deletion claim) compares database time with the row's stored
effective dates inside its own transaction. No retention proof, topology or
source-readiness check exists.

A started download continues under its original authorization
([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md));
each delivery lease is fenced by the row's effective dates.

Deletion becomes claimable at the effective read cutoff and is due at the
effective deletion deadline. A shortening never releases storage by itself;
the charge is released when deletion completes.

## Impact preview

`preview_retention_change` ([ADR-240](../decisions/240-retention-impact-preview.md))
applies the proposal to the stored set and aggregates the effects of the
created and updated policies with one SQL call (`retention_preview`) over
stored deadlines. It writes nothing.
