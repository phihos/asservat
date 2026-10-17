# Hub routing across acquisition clusters

[ADR-089](../decisions/089-multicluster-worker-routing.md) removes the single-worker-profile assumption from the [owner runtime](owner-startup.md) and [forwarder](owner-forwarding.md). Existing I-13 request/response, C-14 lookup ports and domain values remain unchanged.

## Lookup and authority

`postgres.NewWorkerRouting` takes a scoped SQL pool, installation ID and permission root. It exposes only `WorkerEnrollmentBindings` and `WorkerOwnerLookup`. It selects the latest admitted worker for the exact session and requires the requested worker ID. Its stored profile determines the acquisition cluster and current configuration source. Audited configuration/recovery must remain current; unaudited/unclaimed, terminated, retired, replaced or foreign workers fail. After potentially blocking configuration checks, reread the latest worker and parent session and intersect original SQL start, caller, parent, worker and configuration/recovery deadlines. The caller cannot choose a profile, issuer, cluster or endpoint.

The existing `DownloadWorkers` reader uses the same path with an additional exact constructor-profile match. Dispatch/enrollment/claim writers retain separate profile-scoped facets and credentials. The shared router stores exact operation registrations; each registration retains its original profile-specific claim store. Receiving needs the router and exact Pod/process identity, not a global effect store.

The scoped SQL role reads only schema version, worker/locator/session, fleet recovery and worker configuration/revision tables. Identity-column privileges permit required row locks; existing triggers prevent identity mutation. Do not pass migration/admin credentials or broaden this role to acceptance, signing or evidence access. Fixture privileges and negative tests are not an implemented installer role provisioner.

## Issuer selection

`mtls.NewWorkerTrustCatalog` accepts one installation and at most 256 existing closed `asservat-worker-control/v1` documents. Each is at most 64 KiB; its exact ConfigMap data digest is the key. Installation supplies the same bytes used to produce the cluster's immutable control ConfigMap. The catalog stores parsed copies, keeps separate roots per digest and checks CA lifetimes on each lookup. It performs no network fetch and uses no system trust.

`Replace` validates the full new snapshot before atomic publication. Duplicate digests, malformed documents, foreign installations or excess documents fail without partial replacement. An empty snapshot removes all trust. Multiple versions for a cluster can coexist during rollout, but only the exact currently accepted SQL profile can select one. The returned issuer pool is independently owned and cannot mutate the catalog. The loader must report rejected refreshes and synchronize material without asking application developers to configure internal certificates.

Before dialing and again before sending the Pod token, the forwarder verifies the selected profile's document exists with current roots. After receiving the worker certificate it uses only those roots, then repeats current owner/locator/worker checks and catalog verification before returning. A profile change mid-call, root removal or a certificate from another catalog cluster fails. Original live-delivery deadlines and cleanup remain unchanged. Catalog membership supplies public verification material, never enrollment or evidence authority.

## Composition and remaining work

The owner runtime accepts an installation-bound catalog instead of one profile/root pair; it can start with no worker clusters and deny unknown requests. Protected configuration acceptance still comes from the existing audited SQL readers. No public API, schema migration or extra dependency is introduced. Installation/connector synchronization of control documents, protected credential loading, native in-Pod cross-cluster routing and full download/UI/MCP composition remain unfinished. Actual test results and limitations are recorded in [implementation progress](../implementation-progress.md).
