# ADR-089 — Multi-cluster worker routing and exact issuer selection

Date: 2026-10-11. Status: selected for implementation under continuing maintainer authorization. Requirements: REQ-FED-001, REQ-DEP-003, REQ-DLD-003, REQ-CAP-003; part of TASK-02 and S-01/S-02.

## Problem

ADR-088's owner runtime accepted one worker profile and one issuer root set. That would pin a central hub to one acquisition cluster even though the product requires central multi-cluster management. Combining all cluster roots would let one enrolled issuer authenticate another cluster's worker. Constructing profile-specific effect stores from a request would also give the routing layer unnecessary authority.

## Decision

Add the C-21 `postgres.WorkerRouting` read facet, independently pinned to one installation and permission root. Resolve the latest bound, audited, claimed worker from durable dispatch using session/worker IDs, derive its exact stored profile, and require current audited configuration plus recovery. Recheck worker generation, termination and parent session after blocking configuration work. Preserve the original SQL observation, worker, parent-session and caller deadlines. Existing profile-scoped effect adapters reuse the same helper with an exact expected-profile check; their authority is unchanged. Locators remain metadata and cannot recreate live ownership.

Add a C-21 `mtls.WorkerTrustCatalog` of existing immutable worker-control documents, indexed by their canonical ConfigMap digest. Only installation composition supplies/replaces these public documents. They contain no bearer credential or private key, and presence in this catalog does not accept a profile or authorize any effect. Every lookup requires the current stored profile's installation, cluster and exact control digest. Validate separate server/issuer CA sets using the existing strict parser; return only that profile's current issuer roots. Never merge cluster roots or dial the document endpoint during lookup.

A snapshot contains at most 256 distinct documents, each under the existing 64 KiB bound. This is a bounded runtime catalog capacity, not a public cluster selector. Reject excess input and duplicates rather than silently dropping entries. Installation may stage old/new control versions for rollout. Validate a complete replacement before atomic publication; failed input leaves the previous snapshot, while an explicitly empty snapshot removes all trust. Readers use immutable snapshots and independently owned pools. Current audited SQL profile checks still deny old revisions even when their document remains in the catalog. Missing material denies the affected request rather than substituting another cluster or ambient trust.

The forwarder resolves trust before network/token transmission, repeats it before transmission and after receipt/current-state rechecks, and verifies returned worker DER only against the exact selected issuer. Original live-delivery cancellation, current owner admission, no-replay transport and finite intervals remain mandatory. Removing a catalog entry prevents the next check; it is not retroactive erasure or instantaneous recall of an already delivered certificate. Existing finite deliveries retain their original at-most-five-second final observation bound.

`OwnerRuntimeConfig` now accepts that installation-bound catalog and shared read facets instead of one worker profile/root set. Zero enrolled worker profiles is valid startup configuration; unknown workers remain unavailable. Existing local routing already supports multiple exact registrations, each retaining its own profile-specific store. The receiver can resolve these registrations without a dummy global mutation store. The current SQL fixture verifies that receiver use without a global store.

## Scope and alternatives

No SQL migration, public wire, evidence permission, tenant abstraction, external dependency or workload kubeconfig is added. The SQL read role needs SELECT plus identity-column UPDATE privileges solely for PostgreSQL shared row locks; immutable-identity triggers reject changes. It cannot dispatch, sign, claim/release ownership, acknowledge audit or accept/refresh configuration.

The catalog reuses the same worker-control bytes produced by installation; administrators must not maintain a second hand-written root list. Protected loader/source synchronization is still required. A failed update must be visible operationally and never be represented as successful acceptance. The programmatic replacement method is not exposed to worker/developer requests. Automatic delivery of enrolled cluster control documents through the protected installation/connector path, loader integration and native multi-cluster routing remain pending. The catalog alone does not close those gates.

## Validation

Use distinct real CAs and the actual mutual-TLS relay to test two worker clusters through one forwarder, cross-cluster issuer rejection, changed/removed trust before and after transmission, exact profile digest, independent pools and bounded replacement. SQL tests must show one read facet resolving two admitted profiles, foreign-root/installation/worker denial, unchanged per-profile effects, caller deadline preservation, isolated fencing, mutation denial and cancellation during a proven configuration-lock wait. Repeat the owned custody and native context suites with frozen sources and inspect actual terminal cleanup/hash reports. Synthetic authority, SQL-only dispatch and unit address remapping are not native multi-cluster deployment qualification.
