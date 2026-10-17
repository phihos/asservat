# ADR-185 — Public sources and the cluster catalog

Date: 2026-10-15. Status: accepted; steps 1–4 implemented with unit tests
(catalog source, hub-api composition, fixed names, probes and RBAC, public
sources step). The public sources step passed natively
([continuation run 18](../../test/results/adr183-continuation-native-18/result.json));
cluster addition and two-cluster qualification are pending.
Requirements: REQ-DEP-001/003/005, S-02; TASK-11.
Builds on [ADR-180](180-hub-api-public-composition.md),
[ADR-183](183-installer-runtime-continuation.md) and
[ADR-184](184-promoted-owner-first-launch.md).

## Context

The promoted hub-api reads six configuration sources that today exist only
as test fixtures:

| Source | Key | Guard | Mutable |
| --- | --- | --- | --- |
| Browser settings | `browser.json` | namespace workload guard only | yes |
| Identity settings | `identity.json` | namespace workload guard only | yes |
| Context capability, per cluster | `context-capability.json` | own guard | no |
| API context work trust, per cluster | `api-context-work-trust.json` | own guard | no |
| Download worker configuration | `worker-profile.json` | own guard | yes |
| Download environment | `download-environment.json` | own guard | yes |

Each guard needs:
- a ValidatingAdmissionPolicy and binding over the exact source name;
- a dry-run probe slot in the owner workload guard's configuration probes.

That list is capped at eight, and the installed layout already uses three.
The owner Role and ClusterRole are original journal objects with pinned
digests, and they grant no access to these sources.

`OwnerPublicDeployment.Clusters` fixes the regional cluster set in the
owner's immutable input. Regional clusters enroll after installation:
connector enrollment needs the running hub. Under ADR-184 the first launch
is final.

## Decision

1. **A cluster catalog instead of fixed clusters.**
   - `Clusters` leaves the immutable owner input. The input instead pins one
     guarded, administrator-written cluster catalog source by name, UID and
     guard.
   - Each catalog entry names a regional cluster:
     - its connector peer;
     - its executor identities;
     - its capability and work-trust sources with their guard pins.
   - hub-api reads the catalog at process start. Each entry is accepted only
     after its connector peer matches the current SQL connector activation
     (ADR-052) and its sources pass their own guards. Catalog membership is
     not authority.
   - Adding a cluster means writing the catalog and replacing the hub-api
     Pod. The ReplicaSet, template and revision pins stay unchanged. Live
     reload is later work.
2. **Fixed slot names.** Per-cluster sources use installation-derived slot
   names (`asservat-<id>-cluster-<n>-capability`, `-work-trust`). The owner
   Role can then name them before any cluster exists. The first installed
   profile has one regional slot. This matches the probe cap:

   | Probes | Count |
   | --- | --- |
   | Existing | 3 |
   | Worker configuration and download environment | 2 |
   | One cluster's capability and work trust | 2 |
   | **Total** | **7 of 8** |

   More regional clusters need a larger probe list, decided with that work.
3. **Owner RBAC at resource creation.** The owner Role gains:
   - `get` on the six source names and the catalog;
   - `get` on their policies and bindings.

   Names are fixed, so the rules are part of the original template digest.
4. **A public sources phase in the continuation.** After the worker launch
   and before the owner projection, the continuation creates or reopens a
   journal of guarded sources with exact receipts, like the 19 runtime
   resources:
   - **Browser and identity settings**, generated from chart values: issuer,
     client IDs, origin, groups, limits. Installer-derived revision, root ID
     and session epoch.
   - **Worker configuration and download environment**, generated from the
     download worker infrastructure objects and their revisions.
   - **The empty cluster catalog**, with its guard.

   Capability and work-trust sources are created per cluster when the
   cluster is added, with the work-signing public key and the release
   collector identity.
5. **Order inside the window.** Keys, meaning the signing key read back,
   precede the work-trust sources. Sources precede the owner projection,
   whose input pins the browser, identity, worker configuration, download
   environment and catalog references.

## Implementation notes

- **Owner-account probes.** The five guarded public sources are owner-account
  configuration probes in the provider-installed workload guard (eight of
  eight). The bridge proves only the other probes; the hub-api proves these
  at read time, because the sources do not exist yet when the bridge runs.
- **Owner RBAC.** The provider-installed owner gains:
  - `get` and `update` on the five sources (the dry-run probe needs the
    access review to pass and the guard to deny);
  - `get` on the browser and identity settings;
  - `get` on the five guards.

  Each guard is named after its source with `-guard`.
- **Empty catalog.** The router accepts zero clusters and then refuses
  every start.

## Consequences

The hub-api public composition changes from a startup-fixed cluster list to
catalog entries resolved at start. A cluster addition needs one Pod
replacement until live reload exists. The probe cap limits the first
installed profile to one regional cluster.

## Implementation

1. Contracts: the cluster catalog, slot names, and the owner input
   references replacing `Clusters`.
2. hub-api: resolve clusters from the catalog at start, with per-entry SQL
   and guard checks.
3. Owner Role rules for the fixed source names.
4. Public sources journal and continuation phase; chart values for browser
   and identity settings.
5. Cluster addition: per-cluster sources and catalog entry, then Pod
   replacement.
6. Native qualification with a second cluster.
