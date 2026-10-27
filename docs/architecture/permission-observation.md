# Kubernetes permission observation boundary

Scope: C-01 configuration ports, C-20 wire DTOs, C-21 Kubernetes adapters and C-24 values; partial REQ-PER-001/002/003/006/008, REQ-DB-001 and TASK-07 in S-01/S-02. The [component record](../research/permission-foundation.md) separates tested behavior from authority that still needs implementation.

`configuration.PermissionReader` reads explicit bindings and automatic-source definitions from a pinned hub control namespace. `configuration.NamespaceReader` reads selected metadata from a namespace in one explicitly configured cluster. The concrete `kubernetes.PermissionClient` implements both. These are **observations**, not accepted SQL configuration or an implementation of `authorization.ProjectionReader`. There is no public endpoint, new configuration store or enabled collector.

## Read and provenance contract

Bootstrap selects a verified HTTPS API endpoint, credentials, installation cluster UUID, control namespace name/UID and clock. Client-go supplies Kubernetes transport/authentication; the adapter adds a five-second whole-call deadline, bounded JSON responses, no ambient proxy, no credential redirects and no internal retry of failed reads. Credentials must be scoped for the runtime role; the constructor does not establish RBAC/admission trust.

The reader obtains the control namespace before and after listing and rejects UID replacement or termination. It lists every AccessBinding in that namespace, without label/field filters or `resourceVersion=0`. Each page must have the same opaque collection resourceVersion; duplicate names/UIDs, cyclic continuation, changed versions, invalid objects, overflow, missing pages or HTTP errors discard the binding observation. An empty completed list is distinct from an unavailable list. A terminating allow is inactive; a terminating deny remains a candidate until it expires or actually disappears.

PermissionSource definitions are allow-only and are observed separately. A source-list failure sets `SourcesComplete=false`, discards that entire source list and preserves an independently complete binding list if its deadline remains valid. A malformed source spec is listed in `InvalidSources` using bounded resource identity, without error content; other valid source observations remain available. Unknown deny state never receives that treatment. The two lists are not an atomic cross-resource transaction, nor proof that no changes occurred after observation.

Each source retains cluster/control namespace/resource UID, name, opaque object resourceVersion, generation, deletion state and SHA-256 of the RFC 8785 canonical **spec**. Status, field managers, owner-looking annotations and a claimed review reference do not confer authority. Free-text binding reasons are validated and included in the spec digest but omitted from the returned binding value. Unknown spec fields fail the canonical schema check. The embedded schema graph is local and checked against the specification; no network schema loading occurs.

| Initial component bound | Value |
| --- | --- |
| Page / total list response bytes | 2 MiB / 8 MiB across the two list operations |
| Page items / objects per resource kind | 64 / 1,024 |
| Pages per resource kind | 32, including empty intermediate pages |
| Spec bytes / syntax work | 64 KiB / 16,384 JSON tokens, depth 32 |
| Page syntax work | 131,072 JSON tokens, depth 32 |
| JSON number token | At most 20 bytes, signed 64-bit integer |
| Observation lifetime | Five seconds from before the first API read |
| Namespace metadata query | At most 32 explicit keys; values at most 256 bytes |
| Namespace metadata lifetime | 30 seconds from before the API read; source maximum may shorten it |
| Namespace LIST (ADR-242) | 200 per page, 80 pages, 64 MiB; at most 4,096 namespaces carrying an observed key |
| Namespace watch session | 2 seconds; a clean end renews observation freshness, bookmarks do not |

These are fail-closed implementation limits, not a demonstrated deployment scale or measured overhead. There is no silent truncation. A future controller must coalesce reads and maintain bounded watched projections rather than issue a whole installation list for every developer request.

## Mapping without manufacturing authority

Namespace reads pin namespace name/UID and cluster connection, retain resourceVersion and termination state, and return only explicitly selected label/annotation keys. They do not expose unrelated metadata. The adapter validates actual Kubernetes names/keys in addition to JSON Schema constraints. Subjects use bounded stable IDs and HTTPS issuer identifiers compatible with the initial identity adapter.

Pure `ProposeBinding` explains binding scope matches and produces finite **candidates without assignment IDs**; C-01 `NamespaceGrants` evaluates a source against a minimized namespace observation (ADR-242). Explicit bindings match cluster, namespace name/UID and any configured workload kind/name/UID. Namespace mapping respects exact selector values, exclusions, termination, original freshness and the configured source maximum. Value maps preserve multiple owner teams and never parse comma-separated group IDs. `administratorManaged` and `admissionEnforced` (current namespace guard proof covering every key), value-map and `groupID` (configured `eligibleGroups`) sources grant; `WorkloadGrantsWith` evaluates `workloadMetadata` sources against a connector workload journal under a current workload guard proof, one workload per basis ([ADR-247](../decisions/247-guarded-and-workload-permission-sources.md)). Exec/access-review sources are decision-time: `ReviewSourceFor` accepts them as subject-free configuration and the target cluster's connector reviews each principal per Pod ([ADR-245](../decisions/245-decision-time-permission-sources.md)).

The source declaration's `protection` block is not an admission or administrator attestation receipt. Source `maxNamespaces` is retained for the future accepted-source inventory and is not proven by a single namespace read. No namespace population limit, directory membership, writer trust, controller chain or whole-pod exec restriction is inferred by this component.

## Required next boundary

Before a candidate becomes a current assignment, C-01/C-03 must verify current accepted source configuration, protected writer delegation, applicable review/guard readiness, namespace bootstrap provenance, configured population bounds and target identity. Then persist assignment transitions and their source continuity in SQL, with immutable encrypted audit records. No in-memory or deterministic-digest assignment-ID substitute is allowed.

A complete fresh relist establishes current values; it does **not** prove that ownership did not change A → B → A while observation was interrupted. A future reconciler must replay a continuous trusted history or invalidate uncertain assignments before reuse. Reusing an old ID just because the current label, spec digest or object UID matches would expose historical evidence incorrectly. Status-only/unrelated changes should preserve demonstrably equivalent assignments through explicit reconciliation; do not make normal Kubernetes churn require repeated manual grants.

The ordinary evaluator now requires a separate complete deny-observation interval of at most five seconds, even when there are no deny rows. Each deny row also retains its original five-second bound. Decision expiry intersects that interval with identity, positive-source and artifact deadlines; evidence lookup and the final evaluation cannot renew it. This corrects the initial implementation's overly permissive use of the positive 60-second bound for deny state. Since the ADR-200 revision (2026-10-23, migration 00074) both bounds are 30 seconds (`authorization.PermissionObservationInterval`) under the maintainer's relaxed recheck authorization; accepted deny changes and suspension still apply at once.

The [acceptance component](permission-acceptance.md) now supplies SQL projections, persistent audience identities, encrypted authority audit, structural CRDs and native admission boundaries. Protected bootstrap, continuous watch/relist recovery, real provider qualification, accepted execution and catalog publication remain prerequisites to production authorization. The test CRDs deliberately preserve unknown spec fields to challenge the reader; they are not product installation manifests.
