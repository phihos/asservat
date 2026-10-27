# ADR-245 — Decision-time permission sources (pod exec and access review)

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-PER-004 (exec-based and generic Kubernetes inheritance), REQ-PER-006 (freshness,
composition), REQ-PER-008 (assignment identity, retained evidence, SAR audience), REQ-PER-002
(impact preview). Accepted maintainer requirement: "automated permission management with
configurable inheritance including pod exec rights, Kubernetes-only permission configuration";
maintainer decision of 2026-10-26: every spec feature ships in the first release, the complexity
gate governs how. Follows [ADR-242](242-namespace-permission-inheritance.md), which accepted
namespace-metadata sources and left `kubernetesExec`/`kubernetesAccessReview` granting nothing.
Migration 00096 (schema 96; until S-04 increment 2 merges its 00095, the branch carries that migration byte-identical so the contiguous bundle check holds).

## Problem

Teams whose Kubernetes RBAC is the maintained source of truth ("whoever may `kubectl exec` into
the pod maintains it") had to mirror that RBAC into hand-written AccessBindings. The two
decision-time source types were accepted by the schema but granted nothing (`SourceUnsupported`).
Unlike namespace metadata they cannot be reconciled from watched objects: the answer is per
principal and per Pod, comes from the target cluster's whole authorizer chain, and the spec forbids
enumerating who might pass (REQ-PER-008) or inferring it from RBAC objects or
SelfSubjectRulesReview (REQ-PER-004).

## Decision

1. **Accepted sources, no subjects.** The hub-worker's permission reconciler now also accepts
   `kubernetesExec` (check `create pods/exec` on the exact Pod, role `workload-maintainer`) and
   `kubernetesAccessReview` (`create debugcaptures` in the namespace, or `get`/`patch`/`update` on
   the exact Deployment/StatefulSet; role `evidence-reader` or `workload-maintainer`) sources of
   every cluster, at most 4 per cluster (UID order; further ones grant nothing). Only
   `admissionParity.mode: noAdditionalRestrictions` is supported: no qualified exec-restriction
   adapter exists, so a `qualifiedAdapter` source stays `SourceUnsupported`, as REQ-PER-004
   requires. The accepted form (`configuration.ReviewSource`) travels in the existing audited
   permission batch (`PermissionBatch.ReviewSources`, part of the projection digest and the
   authority audit record) into `permission_review_source`. A source version with one spec
   transition and the same *authority digest* (type, cluster, role, check, identity mapping,
   parity) keeps its per-principal assignments: selector, exclusions and lifetime are applied
   afresh by every review. Any other change, a generation jump, removal or disabling retires them
   (`ReviewRetirements` in the audit record); an unreadable source list keeps them without
   renewal, so none grants. A trust change retires them with every other assignment.
2. **Identity mapping is connector-local configuration.** `identityMappingRef` names a record in
   the target cluster's regional connector inputs (Helm `cluster.identityMappings` →
   `installer-cluster --identity-mappings` → `RegionalAPIContext.identityMappings`, regional
   executor only, like the ADR-231 Alertmanager URL): `{name, issuer, usernamePrefix,
   groupsPrefix?, uid?}`. The connector maps the hub's *verified* Asservat principal: Kubernetes
   user = `usernamePrefix` + the stable OIDC subject, groups = `groupsPrefix` + each *current*
   stable group ID of the request (none without `groupsPrefix`) plus `system:authenticated`, uid =
   the subject when `uid` is set. Display names, e-mail and stored groups are never used; an
   unknown mapping or another issuer answers `MappingUnsupported` (grants nothing). Clients never
   name a Kubernetes user or group. Extra attributes are not mapped: an authorizer that needs them
   is outside this mapping and must not be attested.
3. **Request-time review through the existing regional query channel.** hub-api asks the target
   cluster's connector over the ADR-179 standby query frames (new method `review-access`), as it
   already does for target resolution and the S-03 detectors. The connector GETs the namespace
   (exact UID, the source's selector and exclusions, not terminating), GETs the reviewed Pod or
   workload (a different UID under the recorded name is `TargetChanged`; a deleted object is
   reviewed by its recorded name, which the RBAC authorizer decides by name), and submits one
   `authorization.k8s.io/v1` SubjectAccessReview whose subject is the mapped user, never the
   connector. Only `allowed: true`, `denied != true` and no `evaluationError` allow; only the
   closed outcome (`Allowed`, `Denied`, `OutsideSource`, `TargetChanged`, `MappingUnsupported`)
   leaves the cluster. Only human principals are reviewed: a policy executor or workload principal
   gets nothing from these sources (human-only exec inheritance supplies no automation
   delegation, REQ-PER-007).
4. **Persistent per-principal assignment, short decisions.** An allowed review mints, once per
   (source, principal), a SQL-generated assignment ID (`permission_review_assignment`, retired IDs
   never reused) and records per Pod the reviewed resource attributes and a decision lifetime of
   the source's `maxDecisionAgeSeconds` (≤ 60 s, taken from before the question was asked)
   (`permission_review_decision`). A refusal — RBAC removed, outside the source, changed target,
   SAR unavailable or the connector unreachable — ends that Pod's decision at once and mints
   nothing. The permission projection of an exact Pod adds each fresh decision of a current,
   acknowledged source as a `Reviewed` User allow (role of the source, basis = the source UID and
   the assignment's original spec digest), so every existing consumer — preview, SQL admission
   facets after their locks, execution start, catalog, projection read, download, explain — sees
   it with no new port; at most 32 fresh decisions per Pod (allow-only, so a bound drops the
   oldest rather than failing). Explicit denies still win; deny freshness is unchanged.
5. **Audience and reads (REQ-PER-008).** A capture's default audience contains a reviewed allow
   only when it is the capturing human's own: other principals who hold a fresh review of the same
   Pod are never enumerated, and a policy capture never takes one. Every read path (get_case,
   approved projection read, download start, get_capture, explain_access) first repeats the
   caller's *recorded* reviews of that Pod before its permission read — a fresh SAR per read and
   recorded attribute set — so access ends at the next read after RBAC removal and returns,
   with the same assignment ID, when RBAC is restored while the source is unchanged. The read
   evaluates only the original retained audience: SAR never authorizes unrelated historical
   artifacts for a principal who gained exec rights later (that principal has no recorded audience
   there). A same-name replacement Pod is `TargetChanged`. Capture and explain review the freshly
   resolved Pod. No evidence is read before eligibility: the reviews read only the caller's own
   permission rows (for get_capture, the capture's Pod UID).
6. **Capacity.** A workload that only decision-time sources cover gets a capacity enrollment scope
   (ADR-197/200) from a recorded allowed `workload-maintainer` review of one of its Pods by a
   current, acknowledged source (`read_capacity_permission_scopes` and `capacity_lock_observation`
   are rewritten in place by 00096). The scope is an enrollment prerequisite, never a grant; review
   scopes fill only the room left by binding scopes (1,024 in all).
7. **Preview.** A proposed supported `kubernetesExec`/`kubernetesAccessReview` create or update is
   `Indeterminate` with the new `not_evaluated[].reason` `DecisionTimeSource`: it grants per
   principal and Pod at request time. explain_access reports the caller's own reviewed assignment.
8. **SAR-derived roles stop at maintainership.** The source schema already limits roles to
   `evidence-reader`/`workload-maintainer`; sharing and owner-team management require
   `evidence-owner`, so SAR-derived maintainership supplies neither (specs/authorization.md).

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Unobserved: no installation runs yet. Without it every team whose Kubernetes RBAC already says who maintains a workload needs mirrored AccessBindings; harm of absence is missing access, not exposure. |
| 2 | Risk accepted | Yes: "configurable inheritance including pod exec rights" is an accepted maintainer requirement; first-release scope by the 2026-10-26 decision. |
| 3 | Typical deployments | Yes where teams get `kubectl exec` through OIDC groups (the common RBAC onboarding); off by default (no source, no mapping). |
| 4 | Precedent | Request-time SubjectAccessReview with short caches is the standard Kubernetes delegation pattern: `k8s.io/apiserver` delegated authorization (aggregated API servers, 10 s allow/deny cache by default), kube-rbac-proxy (SAR per request), Kubernetes Dashboard/Headlamp ("can I" reviews). |
| 5 | Privileges added | Connector: `create subjectaccessreviews` (cluster-scoped, only when identity mappings are configured; reveals authorizer decisions, changes nothing). Hub: SQL duty `access-review` (insert assignments/decisions, update/delete decisions); hub-worker `permission-accept` gains review-source writes and assignment retirement; every duty that reads assignments gains SELECT on the 3 tables. No credential, secret, collector or worker change; no new network path (existing hub→region query channel). |
| 6 | Failure/degraded states | 1 new: a review that cannot be answered (SAR forbidden/unavailable, connector unreachable, oversized frame) is recorded as a refusal and grants nothing — the same state as "denied". |
| 7 | Self-configuration | None: existing source fields; bounds are constants. Identity mappings are semantic (must match the cluster's authenticator), not tuning. |
| 8 | External dependencies | Kubernetes SAR API (`authorization.k8s.io/v1`, GA), the cluster's authorizer chain and its OIDC authenticator configuration (the operator attests both via `admissionParity.reviewRef` and the mapping). |
| 9 | Cost at scale | Per capture preview, capture request and explain: 1 SAR per accepted source of the target's cluster (≤ 4, typically 1) + 1 region query round trip + 1 SQL transaction each. Per read operation: 1 indexed SQL lookup of the caller's recorded reviews of that Pod (≤ 5 rows); 0 SARs when none, else 1 per recorded (source, Pod). Measured in Kind: first review 21 ms, mean 107.0 ms over 20 (2 GETs + 1 SAR + 1 SQL transaction). No watch, no background task, no hub memory. SQL: 1 assignment per (source, principal) ≤ 4,096 per source; 1 decision row per (assignment, Pod) ≤ 1,024 per assignment (~300 B); +1 indexed query (≤ 32 rows) per projection read. Capacity scope read: +1 grouped query over decision rows. |
| 10 | Upgrade/rollback/disable | Additive migration 00096 (floor stays 81). An older binary never reads the review tables and its acceptance never writes them: review grants vanish on rollback (fail closed); after re-upgrade the stale source rows lag the stream until accepted again. Disabling: `enabled: false`, deleting the source (retires, tested) or removing the mapping (`MappingUnsupported`). |
| 11 | Smaller fix | Documentation (mirror RBAC into AccessBindings) does not meet the accepted requirement. Precomputing exec rights from RoleBindings is the partial RBAC evaluator the research rejected (aggregation, webhooks, SelfSubjectRulesReview incompleteness). Polling SARs for every user × Pod needs enumerating users, which REQ-PER-008 forbids. An in-memory merge would not reach the SQL admission facets that re-evaluate after locks, nor give a stable audience ID. Request-time reviews recorded as short SQL decisions under a persistent per-principal assignment are the smallest form; mappings ride the existing regional inputs instead of a new CRD. |

Caching bound: a decision lives at most `maxDecisionAgeSeconds` (1–60 s) from before its question;
every read path re-reviews before reading permissions; a refusal ends the decision immediately.
Within one capture flow the SQL facets and the execution start may rely on the decision made at
the request (they run within seconds); after its lifetime they fail closed.

Benefit accepted (maintainer requirement), cost bounded and opt-in: proceed.

## Agent-authored restrictions revised (recorded as such)

- REQ-PER-006 asks to audit "source UID/revision, principal mapping, target UIDs, decision time/expiry
  and reason". Source revisions and retirements are in the encrypted authority audit; a capture's
  intent audit records the reviewed assignment (source UID, original spec digest, assignment ID)
  and the target UIDs; the reading principal is in the operation audit. The individual decision
  (time, lifetime) is SQL state only, not an immutable encrypted record per review: one encrypted
  object write per read would dominate the read path's cost. Recorded as an open point, not a
  silent omission.

## Open points

- `qualifiedAdapter` admission parity: no adapter exists; such sources grant nothing.
- Deleting a decision-time source in the ADR-237 preview shows no change (its per-principal
  assignments are not configuration cells); its retirement is reported only by acceptance.
- `resolve_capture_request` (lost-reply recovery) does not re-review; after the decision lifetime
  a SAR-only requester resolves through get_capture or a new request.
- No installed (Helm) qualification of the connector RBAC and inputs; the Helm render and the
  real-RBAC component test cover them.

## Qualification

- Unit tests over the evaluator, review application service, reconciler, domain forms and the
  connector adapter (16 SAR modes against a fake API server).
- Real PostgreSQL (custody): `TestPermissionAuthorityWithRealServices/decision-time-reviews-mint-expire-deny-and-retire`;
  capacity (fleet custody): `TestCapacityProducerWithRealPostgres/reviewed-workload-gains-a-capacity-scope`.
- Real Kubernetes RBAC + PostgreSQL + encrypted audit (`make permission-integration`):
  `TestPermissionAdmissionWithRealKubernetes/live-guard-proof-and-binding-revocation/decision-time-reviews-with-real-subject-access-reviews-SQL-and-audit`.
- No installed qualification. Commands and results: [implementation progress](../implementation-progress.md).
