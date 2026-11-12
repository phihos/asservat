# ADR-326 — Individually selectable small services

Status: implementation candidate; installed qualification pending.

## Decision and scope

The maintainer cannot try the external-services context trial without an
external database and object store. On 2026-11-11 the maintainer additionally
requested bundled Keycloak, with every built-in service independently
configurable. This extends ADR-063's packaging options; it does not cancel its
local-identity/static-key capabilities or change evidence guarantees.

Use independent `services.postgres`, `services.objectStore`,
`services.identity` and `services.keyService` provider choices in the official chart. Bundle one
PostgreSQL server, pgBackRest with a separate retained encrypted repository,
SeaweedFS and Keycloak. Selecting an external provider must omit the associated
bundled workload. Keycloak can use the bundled PostgreSQL server or a separately
selected PostgreSQL database. The accepted isolated static-key alternative still
requires complete purpose/PKI composition. The first usable vertical slice also
offers optional bundled OpenBao using the existing provider adapters. This is
an implementation choice to supply the missing service, leaves external defaults
unchanged and does not replace the accepted static-key alternative.
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

## Runtime storage join

The continuation explicitly selects `objectStoreSource=bundledSeaweed` and reads
the existing fixed public plan/CA files. It resolves actual roots before ordinary
consumers, then compares namespace, preparation-root name, endpoint and DER roots
with the original protected preparer. It does not infer ownership from a URL.
The first bundled profile uses one owned bucket and region for audit and evidence,
with the existing disjoint prefixes and purpose-specific policies. External
configuration keeps its complete explicit endpoint/root/bucket/region requirements.

`ReadReady` is a separate read-only provenance operation: four named GETs, no
mutation or new deadline. It accepts an expired historical storage cutoff without
changing it. Initial Begin/MarkReady still refuse after their original bounds.
The continuation supplies its own original finite operation for later effects.

Runtime credentials are generated into their existing protected original Secrets
before IAM enablement. One CAS fill plus exact readback handles uncertainty;
later reads recover the stored key. No new credential journal, watch, SQL pool or
runtime mount is introduced. The sanitized bootstrap seed no longer retains the
initial key, so the installer reads only that exact installation's known
initial-audit principal from its original pinned private IAM source. It does not
import arbitrary provider identities or permissions as authority.

The worker grant uses the existing compiled provider recipe's prefixes. Storage
setup precedes worker-input acknowledgement. Once those inputs are acknowledged,
replay skips that smaller IAM compilation so it cannot remove later hub roles.
The complete hub-role provisioning and automatic provider inbox remain unfinished;
focused checks are not installed runtime-storage qualification.

## Bundled OpenBao composition

The optional exact2.7.2 backend uses native HCL self-initialization with a retained
static seal key and encrypted persisted state. A partial initialization refuses
to unseal; the installer cannot repair it by wiping or reinitializing storage.
The final marker is a fixed deny-only policy binding the original backend UUID.
Health and that marker supply no application or recovery authority. The original
Ready/PVC acknowledgment additionally refuses lost or replaced retained data.

The local server reviewer has only TokenReview create. The setup login is bound
to the exact original runner account, dedicated audience and same native API/root
pins. Existing configuration and owner auth mounts use local reviewer tokens;
external provider profiles keep their explicit reviewer requirements. Setup has
API-scoped sudo only on those two exact auth-mount paths, needed by actual
OpenBao admission; wildcard sudo, tune, delete and root credentials are absent.

The initial issuer records the independently observed setup entity and original
namespace/account UIDs privately. Its actual expiry and all children are bounded
by that original setup expiry minus10s. No login/renewal refreshes the bound.
External tokens retain the original empty-entity profile. Initial minting uses a
single-use acknowledged intent in the existing bootstrap seed; unknown POST
results remain uncertain and never cause automatic replacement issuance. Pending
provider material cannot enter SQL provisioning or the public projection.

One server/PVC/state Secret and one TokenReview-only account are added for the
selected backend. No watch, worker, broker, SQL pool or evidence privilege is
added. Only public plan/CA/backend fields enter ordinary runner projections;
seal and private CA keys stay in private provider state. Component and local
checks do not complete the required fresh installed workflow.


### Mixed-provider private input

`provider-material.json` is an operator fragment described by
[`initial-bootstrap-provider-input.schema.json`](../../specs/contracts/initial-bootstrap-provider-input.schema.json).
It keeps the existing material format and field names. Supply only the external
provider's credentials: `issuerToken` for an external key provider, `storage` for
an external object store, and an original `storageUseUntil` for either mixed or
fully external selection. Omit credentials for bundled providers; dummy values
are refused. A fully bundled pair needs no provider material file. These external
requirements are checked before setup login or generated provider material.

The installer fills selected provider fields and persists complete or pending
private material under the separate retained material schema. Operator fragments
cannot supply `setupToken`, observed `bundledIdentity`, or registry configuration.
No new mode flag or backend-selection fallback is introduced.

## Automatic continuation and private material

Selecting bundled key and object storage reuses the existing worker/owner provider
recipes. Worker setup uses its original retained audit Secret; no phase-1 inbox
is needed for this selection. Once worker inputs are acknowledged, replay does
not reapply its smaller IAM set or overwrite a later outbox. Phase3 compiles the
complete initial/worker/owner/federation/publisher/download/deletion/cleanup set
from actual recipe prefixes, preserving all existing purposes in one bucket.
The full case has10 nonadministrator principals plus the original backend admin.

The existing phase3 inbox is the original private credential carrier. Persist
its winner before IAM enablement, then perform create-only provider setup and
fill only the actual short-lived inspection token through UID/RV CAS. Unknown
writes get one exact readback, never repeated issuance or key replacement.
Pending inboxes contain no placeholder credential and cannot be consumed by the
ordinary reader. The original source checks and actual configuration-transition
guard refuse same-principal key changes; a lost pending carrier requires its
original restoration, never silent adoption. There is no new object, watch,
SQL role, controller or runtime mount. Existing completion removes the inbox.

`bootstrap.continuation.materialSecretName` optionally names an existing private
Secret in the trusted bootstrap namespace. It supplies the public API's TLS pair
and, with external identity, its OIDC client secret; selected federation/key-service
listeners use their existing closed TLS filename groups. Bundled Keycloak supplies
its own original console secret. Only required fields are copied and private TLS
is checked for its actual selected hostname before effects. These bytes never
enter Helm values/release data or the public continuation document. Retained
inbox TLS/client bytes must match the checked source before IAM enablement.
This does not create browser certificate trust or qualify installed login.

## Initial issuer response compatibility

The pinned OpenBao implementation emits an informational notice whenever both
role and request provide explicit maxima, reporting their smaller value
([provider source](https://github.com/openbao/openbao/blob/9e0a0d3c3504a0a00b45e61355afac5e35c78379/internal/vault/token_store.go#L4492)).
Both bounds are intentional: the role caps issuance at900s, and the request
selects a shorter original-parent-bound interval. Accept only the single exact
notice for that computed interval. Other, altered or additional warnings refuse.
Keep all independent role/policy/entity/nonrenewal and actual-expiry checks;
there is no broader warning bypass or added provider read, privilege or state.

The durable mint claim consumes the existing operation's original deadline,
normalized downward to microseconds; its positive interval is at most5s. It
never creates another five-second window after blocking work. The Fresh/CAS,
unknown-reply and original parent bounds are unchanged.


### Explicit bundled processing-operator group (proposed)

`services.identity.keycloak.processingOperators` defaults false. True is retained
in the original immutable settings and creates one initially empty
`asservat-processing-operators` group. Its UUIDv5 is derived with the existing
UUID implementation from the protected original random users-group UUID as
namespace and that fixed group name. This is public identity derivation, not a
secret-payload hash. No extra Secret field, API call, role, watch or service is
added. Legacy false settings and realm bytes remain unchanged. Existing retained
settings cannot be upgraded by changing this flag.

Only this explicit selected profile may omit the processing-operator list before
normalization. It fills an empty list with the dedicated Group principal and
actual console client/issuer; an explicit nonempty list is preserved. Ordinary
users remain in their separate eligibility/fleet group. No users/default password
or default memberships are created. An administrator deliberately assigns real
humans to the dedicated group through Keycloak; ordinary evidence AccessBindings
and current privacy authority checks remain independent. The selected example
omits the derived list rather than inserting fabricated IDs.
