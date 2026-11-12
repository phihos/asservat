# ADR-326 — Individually selectable small services

Status: implementation candidate; installed qualification pending.

## Decision and scope

The maintainer cannot try the external-services context trial without an
external database and object store. On 2026-11-11 the maintainer additionally
requested bundled Keycloak, with every built-in service independently
configurable. This extends ADR-063's packaging options; it does not cancel its
local-identity/static-key capabilities or change evidence guarantees.

Use independent `services.postgres`, `services.objectStore` and
`services.identity` provider choices in the official chart. Bundle one
PostgreSQL server, pgBackRest with a separate retained encrypted repository,
SeaweedFS and Keycloak. Selecting an external provider must omit the associated
bundled workload. Keycloak can use the bundled PostgreSQL server or a separately
selected PostgreSQL database. The accepted isolated static-key alternative still
requires complete purpose/PKI composition. Optional bundled OpenBao has not been
selected and does not replace that requirement.
No database operator, message broker or provider controller is added.

One finite pre-install/pre-upgrade preparation hook persists generated private
state outside Helm release data before provider workloads initialize. It runs
only in the existing explicitly trusted bootstrap namespace. Kubernetes RBAC
cannot restrict Secret CREATE by name; its namespaced create grant and named
read grants are limited to this finite installer account. It has no
cluster-scoped runtime privileges. The existing installation/guard protocol
still establishes application runtime authority separately.

Persist Keycloak identity before initial PostgreSQL state. Retained databases,
provider workloads or volumes with missing original private state require
recovery, never silent credential or identity regeneration. Existing valid state
replays without new private material. Unknown CREATE permits one exact lookup;
no new attempt replaces it. PVCs and private state have no release owner that
would erase them on uninstall. Provider selection changes requiring data or
credential migration are refused until explicitly supported.

Bundled PostgreSQL supplies a fixed public CA source to bootstrap input. Resolve
the actual PEM before the existing full compiler and immutable desired-state
identity; no trust bytes are omitted from canonical identity. Initial SQL
client pools remain2; the server budget is117, or122 with Keycloak's fixed5
connections. PostgreSQL credentials remain a distinct selected Secret source
from provider material. Helm and the native runner must generate the same Pod.

## Complexity assessment

1. Observed blocker: the maintainer has zero external PostgreSQL/S3/OpenBao.
2. Self-contained installation is already an accepted first-release capability.
3. It directly serves typical small installations; external choices remain.
4. Reuse upstream PostgreSQL/pgBackRest, SeaweedFS and Keycloak protocols and
   existing Asservat adapters, rather than fork transactional/evidence storage.
5. Added privileges are one finite namespaced preparation account, provider
   database credentials and retained provider TLS/IAM private state. Private
   roots and administrator credentials must not enter hub/collector mounts.
6. Added provider states are absent, prepared and running; partial preparation
   and retained-state loss are explicit retry/recovery cases, not fallbacks.
7. No provider watch, timer controller or machinery-specific tuning is added.
8. Storage durability, Kubernetes Secret protection and browser-trusted HTTPS
   remain installation prerequisites. Upstream backend behavior needs tests.
9. One server per selected provider; Keycloak adds at most5 SQL connections.
   Preparation performs bounded named reads/creates, no LIST/watch or polling
   daemon. Scoped S3 reload/setup costs are measured separately.
10. Preserve data/identity through restart, upgrade and uninstall. Actual restore,
    wrong/missing state, capacity exhaustion and disable/migration tests remain
    required before claiming qualification.
11. Documentation alone cannot supply the missing services. A self-contained
    packaging path using existing adapters is the smaller complete solution.

## Acceptance evidence

Component tests, rendered manifests and an image build are separate evidence.
Qualification must install the integrated candidate into an owned fresh cluster,
perform real login, context acquisition and exact native download, verify expiry
and managed deletion, restart with the same identities/keys and exercise retained
state failures. Backend backup/recovery claims require their own actual tests.
The current ledger records actual results and remaining gaps. No homelab or
publication action follows merely from this candidate.

## Initial object-store provisioning join

The implementation consumes the original bootstrap state's installation/
request IDs and its persisted initial audit credential. Generate raw key bytes
before that state is created, then bind a typed initial-audit principal only to
actual stored IDs. A lost create reply never substitutes newly generated keys.

Observed retry problem: S3 CreateBucket and ownership tags are separate effects.
The existing setup adapter's narrowly allowed pending retry therefore needs an
original durable producer, not a caller-created pending boolean. Use one bounded
ConfigMap in the trusted bootstrap namespace to record the original backend,
state/PVC IDs, installation/request, endpoint/image/bucket and storage deadline
before bucket effects. It contains zero credentials, hashes of secret payloads
or evidence and grants no authority alone. Pending-to-ready is monotonic; mark
ready after ownership/version/policy readback and before enabling an ordinary
writer. Unknown writes permit exact lookup only; changed inputs stop.

Cost/benefit reassessment: this addresses a real non-atomic provider boundary and
routine retry for every fresh bundled installation, not a speculative runtime
attack. No maintainer-accepted risk is reopened. Existing S3 initialization tags
and the current installer journal provide precedent. Cost is one cold control
object, bounded named reads and two acknowledgement transitions, zero watches,
zero runtime polling, zero new SQL connections and zero runtime privilege grants.
The installer already creates/reads/updates ConfigMaps; required named provider
reads/exec are scoped separately. No additional tuning is introduced. Source or
data replacement requires explicit recovery. Merely refusing every uncertain
CreateBucket is smaller code but leaves routine installation failures requiring
manual intervention; a bounded original record is the smaller complete workflow.
