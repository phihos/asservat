# ADR-247 — Guarded, group-ID, remote-cluster and workload permission sources

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-PER-003 (namespace metadata inheritance: `admissionEnforced`, `groupID`, every
cluster), REQ-PER-005 (workload ownership), REQ-PER-006 (freshness), REQ-PER-008 (assignment
identity). Accepted maintainer requirement: "automated permission management with configurable
inheritance"; maintainer decision of 2026-10-26: every spec feature ships in the first release,
the complexity gate governs how. Follows [ADR-242](242-namespace-permission-inheritance.md)
(hub-cluster `administratorManaged` value-map sources) and
[ADR-245](245-decision-time-permission-sources.md). No migration: the forms travel in the existing
audited permission batch and authority audit record (JSON), and workload bases use the existing
basis workload scope.

## Problem

ADR-242 accepted only one form of metadata source. `admissionEnforced` protection, `groupID`
mapping, namespaces of joined (non-hub) clusters and the `workloadMetadata` type were accepted by
the schema but granted nothing, so an organization whose ownership labels are protected by
admission rather than by provisioner discipline, whose namespaces carry group IDs, whose
workloads live in other clusters, or whose teams share namespaces had to mirror ownership into
AccessBindings by hand.

## Decision

1. **`admissionEnforced` reuses the capacity namespace selector guard.** The guard each cluster
   already has for capacity (ADR-190/197: a ValidatingAdmissionPolicy over namespace CREATE/UPDATE
   protecting the installer-selected label keys, an unprivileged probe in an empty probe
   namespace, a live dry-run proof) is the only guard profile: `guardRef: namespace-guard`. The
   hub-worker's capacity cluster readers — the owner's local observation for the hub cluster, each
   regional connector for its cluster — are shared with the permission reconciler; before each
   one-second refresh it obtains a proof when the last one has less than two seconds left. A
   source grants only while the proof is current and its label keys cover every selector and
   mapping key. That guard protects labels only; a source mapping an annotation key is
   `SourceUnsupported` under it (extending the capacity guard to annotations would change the
   capacity qualification digest and the regional join record for a case no requirement names).
   A lost proof, removed binding or changed policy makes the source `GuardUnavailable`: kept,
   granting nothing (tested with the real guard).
2. **`groupID` validates against the configured directory, not a directory reader.** The protected
   identity settings' administrator-configured `eligibleGroups` of the source's issuer (ADR-059
   allows exactly this) are the directory: a value maps to the stable group ID it names only when
   that ID is listed. The hub-worker reads the pinned identity settings ConfigMap
   (`PermissionDeployment.identity`, RBAC `get` on that one object); no group members are read.
   Without current settings the source is `DirectoryUnavailable` (kept, granting nothing).
3. **Joined clusters' namespaces through the cluster-observation channel, with connector-side
   watch continuity.** A new closed observation purpose `permission-namespace-metadata` asks a
   cluster's connector for its namespace journal of a key set. The connector keeps one LIST plus
   finite watch sessions per key set (`NamespaceJournalService`, idle after two minutes without a
   reader, restarted on any invalid transition) and counts, per namespace, the transitions of its
   observed values. A page reports `(journal ID, sequence)`, the journal's own freshness (start of
   its latest LIST or clean watch session) and, per namespace, version `<journal>:<changes>`; a
   cursor of another journal state is a change, so a reader restarts a complete read. The hub
   rereads each cluster's journal every 10 seconds (concurrently, 3-second budget, before the
   trust window opens), compares versions exactly and never claims continuity across reads. An
   unrelated namespace write leaves the version, so the assignment survives; an ownership round
   trip A → B → A changes it even when both writes fall between two reads, so the assignment is
   re-minted. A journal restart is a new journal ID: every version changes and assignments re-mint
   (fail safe). The minimized observations are recorded per cluster in the batch and authority
   audit (`RemoteNamespaces`) and serve the impact preview. Connector RBAC gains `watch` on
   namespaces.
4. **`workloadMetadata` over single workloads under a workload metadata guard.** A new
   ValidatingAdmissionPolicy (`<prefix>-workload-guard`, installed by the hub continuation and the
   regional cluster installer only when the operator's capacity profile names `workloadKeys`)
   denies, for every Deployment and StatefulSet CREATE/UPDATE by a writer other than its
   administrators, creating a workload that carries a protected label/annotation key and changing
   such a key's presence or value; DELETE only removes grants, replacement is a CREATE. Its proof
   reuses the capacity probe account: the pinned policy/binding are unchanged and a dry-run keyed
   Deployment creation in the empty probe namespace is denied by exactly this guard. The probe
   gains `create deployments` in its own namespace only, whose ResourceQuota admits no Pod,
   Deployment or StatefulSet, so the right serves nothing but the dry-run (tested: a real unkeyed
   creation is refused by the quota). A source needs `guardRef: workload-guard`, a non-empty
   `workloadSelector` (server-side label selector, at most 16 equality terms) and no
   `namespaceSelector` (scope is the selector plus `excludedNamespaces`; a namespace selector
   would need both guards for one decision — reported `SourceUnsupported`). Each connector keeps a
   metadata-only LIST+watch journal per selection over both kinds (`WorkloadJournalService`, at
   most four selections, idle after two minutes) with the same value-change versions, resolving
   namespace UIDs from a namespace LIST at most every 30 seconds; purposes
   `permission-workload-metadata` and `permission-workload-guard` serve the journal and the proof.
   The hub-worker reads them like remote namespace journals — for the hub cluster through the
   owner's local observation — and accepts one allow basis per granted workload, scoped to that
   workload's UID in its namespace UID (basis key includes the workload UID). Pods are never
   matched by labels: request-time target resolution derives the workload through the validated
   controller chain and the projection matches the workload UID (SC-PER-005).
5. **Unavailable is never broader.** Every new evidence — guard proof, directory, remote or
   workload journal — that is missing or older than its bound makes the source unavailable
   (assignments kept, nothing granted) and never falls back to another mapping or role. The
   preview evaluates proposed guarded, group-ID and workload sources as `Indeterminate`
   (`MetadataUnavailable`): it reads no proof or directory.

## Complexity gate (AGENTS.md), per form

| # | Question | admissionEnforced | groupID | Joined-cluster namespaces | workloadMetadata |
|---|---|---|---|---|---|
| 1 | Frequency/harm | Unobserved (no installation). Absent, an organization that protects ownership labels by admission must also attest administrator management or mirror bindings. | Unobserved. Absent, one value-map entry per group. | Unobserved. Absent, every joined cluster needs mirrored bindings: the multi-cluster deployments the product targets. | Unobserved. Absent, shared namespaces need workload-scoped AccessBindings (GitOps can generate them). |
| 2 | Risk accepted | Spec form; first-release scope (2026-10-26). | Spec form. | Spec (sources are per cluster); central multi-cluster management is an accepted decision. | Spec REQ-PER-005. |
| 3 | Typical deployments | Clusters with Kyverno/VAP label protection; opt-in per source. | Common where namespaces carry an owner group ID. | Yes: every multi-cluster installation using sources. | Uncommon path: shared multi-team namespaces. |
| 4 | Precedent | Capsule/Kyverno protect owner labels by admission; reuses the existing ADR-190 guard and proof. | ADR-059 eligibleGroups; group-claim-to-role mapping as in Argo CD RBAC. | Agent-side watches relaying reduced state to a hub, the pattern of multi-cluster agents such as Open Cluster Management's work agent; the hub never watches member API servers directly. | Same label-ownership pattern on workloads (Capsule tenant labels, Backstage owner labels under admission). |
| 5 | Privileges added | Hub-worker reads existing guard proofs via the existing channel; none new. | Hub-worker `get` on one pinned ConfigMap. | Connector `watch namespaces` (metadata digests only leave the cluster). | Connector/owner `watch deployments,statefulsets` (metadata only); probe `create deployments` in its quota-zero probe namespace; one cluster-wide VAP on workload writes (failurePolicy Fail, CEL in the API server); `get` on that VAP. |
| 6 | Failure states | 1 (`GuardUnavailable`, same handling as `MetadataUnavailable`). | 1 (`DirectoryUnavailable`, same handling). | 0 new reasons; journal restarts re-mint (fail safe). | 0 new reasons beyond the two above. |
| 7 | Self-configuration | None. | None. | None (refresh 10 s, idle 2 min, bounds are constants). | `workloadKeys` in the capacity profile: semantic (which keys are protected), not tuning. |
| 8 | External dependencies | ValidatingAdmissionPolicy (GA 1.30), already required. | None new. | None new (existing mTLS observation channel). | Same VAP API; ResourceQuota object counts. |
| 9 | Cost at scale | Per cluster with a guarded source: one proof (about a dozen API calls) every ~3 s while such a source exists — the capacity guard's existing cadence. | One ConfigMap read per ~5 min per issuer. | Per joined cluster with sources: one connector watch (bounded 4,096 namespaces with keys, ~1 MiB journal) and one hub read every 10 s (≤ 64 namespaces per page, ≤ 64 pages); 0 API calls per read on the connector. | Per selection: two metadata watches on the connector (≤ 4,096 workloads), one namespace LIST per 30 s, one hub read per 10 s; per cluster one guard proof every ~3 s. Admission: one CEL evaluation per Deployment/StatefulSet write in the cluster. |
| 10 | Upgrade/rollback/disable | Additive; disable by `administratorManaged`, disabling or deleting the source; an older reconciler grants nothing from the source and retires its assignments at its next acceptance (fail closed). | Same. | Additive purpose; an older connector refuses it (source unavailable). RBAC templates change: existing regional installs re-run the cluster installer (marker template digest). | Additive; guard only with `workloadKeys`; rollback leaves the VAP in place (it only restricts keyed workload writes; the operator can delete it); an older reconciler grants nothing from workload sources and retires their assignments. |
| 11 | Smaller fix | Document `administratorManaged` only: does not satisfy the spec's guarded mode. | Value maps only: spec names groupID. | Hub-polled LISTs: unrelated writes would re-mint (every resourceVersion change) or A → B → A would be missed; connector-side versions are the smallest correct form. | Workload-scoped AccessBindings via GitOps cover the need today; the spec still requires the source type, so it ships behind the opt-in guard. |

Benefit is spec-required for all four forms; costs are opt-in per source (and per installation
for the workload guard). `workloadMetadata` has the weakest benefit and the largest cost of the
four (a cluster-wide admission policy on workload writes, workload watches); it is implemented
because REQ-PER-005 requires it, but it is off unless the operator configures `workloadKeys` and
an administrator creates a source. Proceed.

## Open points

- Annotation keys under `admissionEnforced` namespace sources: unsupported (the capacity guard
  protects labels only).
- `namespaceSelector` on `workloadMetadata` sources: unsupported.
- At most 8 joined clusters and 32 workload selections are read per reconciler (constants).
- A connector restart or journal reset re-mints the assignments of that cluster's sources.
- No installed (Helm) qualification of the new purposes, RBAC or workload guard; the component
  tests below are with real Kubernetes, PostgreSQL and S3, not an installed journey.

## Qualification

- Unit tests over the grant evaluators, journals, journal services, reconciler paths, observation
  purposes, wire digests and RBAC.
- Real Kubernetes + PostgreSQL + encrypted audit (`make permission-integration`):
  `TestPermissionAdmissionWithRealKubernetes/live-guard-proof-and-binding-revocation/guarded-and-group-id-inheritance-with-real-guard-and-identity-settings`
  (namespace guard, groupID, workload guard and workload journal in one reconciler run).
- Remote-cluster purposes: unit/adapter tests only; no multi-cluster native run.
  Commands and results: [implementation progress](../implementation-progress.md).
