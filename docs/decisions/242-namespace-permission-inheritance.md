# ADR-242 — Namespace metadata permission inheritance

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-PER-003 (namespace metadata inheritance), REQ-PER-006 (freshness, composition),
REQ-PER-008 (assignment identity and retained evidence), REQ-PER-002 (impact preview, completing
the ADR-237 limit). Accepted maintainer requirement: "automated permission management with
configurable inheritance including pod exec rights, Kubernetes-only permission configuration";
maintainer decision of 2026-10-26: every spec feature ships in the first release, the complexity
gate governs how. No migration: the existing `permission_basis` columns (`kind`,
`observation_version`) and the authority audit record carry everything.

## Problem

The hub reconciled explicit AccessBindings only (`permission-acceptance.md`). PermissionSource
objects were observed but never accepted, so a namespace created by the trusted provisioning
workflow gave its owner team nothing until someone also wrote an AccessBinding for it, and the
ADR-237 preview had to report every source create/update as `Indeterminate`/`InheritanceNotAccepted`.

## Decision

1. **One supported source form now.** A `namespaceMetadata` PermissionSource with
   `metadataMapping.mode: valueMap` and `protection.mode: administratorManaged` is accepted for
   the hub cluster (the cluster the hub-worker runs in, `NamespaceClusterID`). For every namespace
   that matches `namespaceSelector`, is not in `excludedNamespaces` and is not terminating, the
   value of the configured label or annotation selects the source's fixed issuer-scoped groups
   from the explicit value map; the source fixes role and issuer. Missing, unknown, malformed,
   oversized (> 256 bytes) or comma-listed values grant nothing. The PermissionSource admission
   guard already restricts every source write to permission administrators, so a written
   `administratorManaged` source is the administrator's attestation; its `reviewRef` (the
   attestation reference) is part of the spec digest recorded with every inherited assignment.
   Other forms grant nothing and are reported as such (`SourceUnsupported`): `groupID` mapping
   (needs directory validation; ADR-059 forbids a default directory reader), `admissionEnforced`
   (needs a qualified guard reader for the referenced policy), `workloadMetadata`,
   `kubernetesExec`, `kubernetesAccessReview`, and sources for clusters this hub does not observe.
2. **Assignments are ordinary accepted bases.** Each granted namespace is one
   `PermissionBasis{Kind: PermissionSource, scope: whole namespace, effect Allow, one role, groups}`
   with `ObservationVersion` = the namespace's resourceVersion, merged into the same SQL batch as
   the explicit bindings (`BindingJournal.Prepare`). They get SQL-generated assignment IDs, audit
   gating of new allows, the same projection, evaluator, retained-audience provenance and explain
   output as bindings. Denies stay explicit-binding-only and override inherited allows.
3. **Continuity (REQ-PER-008).** A namespace LIST starts a `NamespaceJournal`; every watch
   transition is applied and, when it changes the derived grants or observation, accepted before
   the next one is read (A → B → A therefore retires the first assignment). Such bases are
   `Continuous`. When a transition cannot be accepted at once (the binding list is not current),
   continuity is dropped instead: the next acceptance compares exact namespace resourceVersions
   and retires whatever changed. A new LIST (restart, expired history) never claims continuity, so
   an assignment survives a relist only when its namespace resourceVersion is unchanged — a routine
   restart keeps assignments, a gap with a write re-mints them. For the source object itself,
   authority is its spec, and every spec transition advances `metadata.generation`: equal
   generation and spec digest prove no transition, +1 proves exactly one, a larger jump retires.
   A status or metadata write that changes only the source's resourceVersion keeps assignments
   (this refines the REQ-PER-008 resourceVersion rule for PermissionSource objects; namespaces
   keep the strict rule because metadata has no generation). A re-grant after removal always gets
   a new assignment ID; retired IDs are never reused.
4. **Freshness and unavailable sources (REQ-PER-006).** The observation is current as of the last
   LIST or cleanly ended two-second watch session (bookmarks never renew it). A source whose
   namespace metadata is unknown — no journal yet, LIST/watch failing, keys being re-observed, or
   observation older than its `maxDecisionAgeSeconds` — is listed in the batch's
   `UnavailableSources`: its accepted assignments are kept (not retired, so a transient outage does
   not cut off retained evidence) but their basis is not renewed, and every projection, capacity
   scope and preview skips a PermissionSource allow whose basis lags the stream sequence. If the
   source list itself cannot be read, `SourcesUnavailable` keeps all of them that way. Explicit
   bindings and the complete deny set are unaffected; deny freshness still comes only from the
   complete binding LIST. The capture-time sharing triggers (ADR-235/239) check only that a pinned
   management assignment is not retired, so a kept assignment of a briefly unavailable source still
   counts there; the capture itself was admitted against the current projection, which skips it.
   While the reconciler runs, a source stops granting within one second of
   its `maxDecisionAgeSeconds`; if the reconciler stops, the whole stream expires after its
   30-second interval (ADR-200).
5. **Bounds.** At most 32 observed keys, 4,096 namespaces carrying an observed key (more makes the
   observation unavailable), a LIST of at most 80 pages × 200 namespaces and 64 MiB, `maxNamespaces`
   per source (exceeded: `TooManyNamespaces`, grants nothing), and the existing batch limits
   (1,024 bases, 4,096 assignments); a source that would exceed the remaining batch budget grants
   nothing. Sources are evaluated in UID order.
6. **Minimized observation, recorded and previewed.** The observation keeps, for namespaces that
   carry an observed key, name, UID and the SHA-256 of each observed value — never the value or any
   other metadata. Its form without resourceVersions is part of the batch and of the immutable
   authority audit record (`AuthorityRecord.Namespaces`), and the source digest of each assignment
   links to its spec. The ADR-237 preview now evaluates PermissionSource create/update against the
   observation of the stream's current acceptance (read with the stream under the shared lock; the
   record of the current sequence is current because identical refreshes keep the sequence): the
   proposed source's grants add proposed rows to every workload cell of each granted namespace and
   an update removes the source's current rows. The observation records only the keys of existing
   namespaceMetadata sources (enabled or not), so a source with new keys is `Indeterminate`/
   `MetadataNotObserved` — apply it with `enabled: false` first, then preview enabling it; a
   missing or non-current observation is `Indeterminate`/`MetadataUnavailable`. The contract's
   `not_evaluated[].reason` changes from the constant `InheritanceNotAccepted` to these two values.
7. **RBAC.** The hub-worker ClusterRole's namespace rule grows from `get` to `get, list, watch`
   (the chart's continuation ClusterRole gains `watch` on namespaces so it may grant it). The
   namespace observer uses its own client and rate limiter, so a large LIST never spends the binding
   reconciler's request budget.

## Not in this change: exec and access-review inheritance (REQ-PER-004)

`kubernetesExec` and `kubernetesAccessReview` are per-principal, per-pod live decisions: the local
connector submits a SubjectAccessReview for the authenticated principal under a trusted per-cluster
identity mapping, the capturing principal becomes the recorded audience, and reads repeat the review
for the recorded resource. That is a decision-time mechanism in the request path (identity mapping
records, SAR authority for the connector, per-principal persisted assignments, read-time
re-review, deleted-pod semantics), not a reconciler over watched objects, and none of it is reused
by this change. Such sources are accepted as configuration but grant nothing (`SourceUnsupported`)
until that increment lands. Likewise `workloadMetadata`, `groupID` mapping and `admissionEnforced`
protection, and namespace sources for clusters other than the hub cluster (which need the regional
observation channel), remain open.

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Unobserved: no installation runs yet. Without it every provisioned namespace needs a hand-written AccessBinding per team (the documented friction); the harm of absence is missing access, not exposure. |
| 2 | Risk accepted | Yes: namespace/exec inheritance is an accepted maintainer requirement; first-release scope by the 2026-10-26 decision. |
| 3 | Typical deployments | Yes: namespace-per-team provisioning is the default onboarding recipe (docs/research/permission-automation.md). |
| 4 | Precedent | Kubernetes controllers derive per-namespace authority from namespace metadata with a LIST+WATCH informer (Capsule tenants, Kyverno generate rules for RoleBindings, OpenShift's `openshift.io/requester` project annotation, the Hierarchical Namespace Controller). |
| 5 | Privileges added | 1 RBAC change on the hub cluster: hub-worker namespaces `get` → `get, list, watch` (cluster-wide namespace metadata read; it already had cluster-wide `get`); installer continuation +`watch namespaces`. No credential, secret, write, remote-cluster or network path; collectors and workers unchanged. Namespace values leave the reader only as digests. |
| 6 | Failure/degraded states | 1: a source can be *unavailable* (kept, grants nothing). Disabled, unsupported and too-wide sources grant nothing, as an absent source does. |
| 7 | Self-configuration | None: existing PermissionSource fields (`maxDecisionAgeSeconds`, `maxNamespaces`, selector, mapping); bounds are constants. |
| 8 | External dependencies | Kubernetes LIST/watch semantics (resourceVersion, 410 Gone, finite sessions), already relied on for AccessBindings. |
| 9 | Cost at scale | Per hub cluster: 1 namespace LIST at start and after expired history (typically 1 page; bound 80 × 200), 1 watch session per ~2 s (≈ 0.5 req/s, own limiter), 0 per evidence request (assignments are precomputed). Memory: ≤ 4,096 tracked namespaces × ~300 B ≈ 1.2 MiB worst case (tens of KB typical). SQL/audit: one acceptance and one audit record per namespace write that changes an observed key or a granted namespace's version (the existing 1 s refresh is unchanged); the record grows by ~150 B per observed namespace. Remote clusters: 0 (not observed). Preview: +1 authority-record read only when a source change is proposed. |
| 10 | Upgrade/rollback | Additive, no migration. Rollback to an older binary retires inherited assignments on its first acceptance (it lists no source bases); a kept unavailable row makes the older projection refuse that namespace until then. Disabling: `enabled: false` or deleting the source retires its assignments (tested). |
| 11 | Smaller fix | Documentation (provisioners write AccessBindings) does not meet the accepted requirement. A LIST-only poll would re-mint assignment IDs on every namespace write, cutting teams off from their retained evidence; a decision-time namespace GET needs persistent assignment IDs anyway. The informer journal over the existing acceptance store is the smallest form; exec inheritance is deferred rather than built speculatively alongside. |

Benefit accepted, costs small and bounded: proceed.

## Qualification

- Unit tests: `internal/application/configuration/inheritance_test.go` (value-map grants and every
  grant-nothing case: unknown, comma list, case change, oversized, missing, label spoof, selector,
  exclusion, terminating, disabled, deleting, groupID, admissionEnforced, exec, workload, other
  cluster, unobserved key, too many namespaces, unavailable observation; journal transitions and
  poisoning; reconciler A → B → A acceptance order and continuity flags; dropped continuity when a
  transition cannot be accepted; stale observation, unreadable source list, disabled source and
  failing LIST keep nothing current; batch budget), `internal/domain/configuration/permissions_test.go`
  (observation minimization), `access_preview_scope_test.go` (source create grants namespace-wide
  with the proposed revision, update replaces/keeps, unknown metadata Indeterminate),
  `internal/adapters/kubernetes/permission_namespaces_test.go` (complete paginated LIST reduced to
  digests, inconsistent pages refused, ordered watch, bookmark, expired history, clean end),
  presentation reply with `MetadataNotObserved`.
- Real PostgreSQL (custody fixture, `TestPermissionAuthorityWithRealServices/inherited-assignments-continuity-unavailability-and-preview`):
  identity kept across an unchanged relist and a source resourceVersion-only write, kept but not
  granted while unavailable (single source and whole list), re-minted after a namespace write in a
  gap, kept under a continuous watch, explicit deny wins, removal retires, re-grant and a two-
  generation jump mint new IDs, the audit record holds the digest-only observation, and the preview
  evaluates a proposed source (grant deltas) and reports one with unobserved keys `MetadataNotObserved`.
- Real Kubernetes + PostgreSQL + encrypted S3 (`make permission-integration`,
  `TestPermissionAdmissionWithRealKubernetes/live-guard-proof-and-binding-revocation/namespace-inheritance-with-real-namespaces-SQL-and-audit`):
  results in docs/implementation-progress.md.
- No installed qualification.
