# ADR-190 — Capacity readiness around the promoted owner launch

Date: 2026-10-15. Status: accepted; steps 1–4 implemented and natively qualified
([continuation run 33](../../test/results/adr183-continuation-native-33/result.json));
step 5 implemented with unit tests. Step 7 is natively qualified with an
observation-mode owner, through capacity root `ReadyAt`
([run 43](../../test/results/adr183-continuation-native-43/result.json),
[ADR-192](192-capacity-before-download-paths.md)). Step 6 and the promoted
binding of step 7 are implemented with unit tests (ADR-194 step 9): a
raw-connection server-name router (`native.ServerNameRouter`) hands each
ClientHello, unterminated and replayed, to the unchanged native or
observation server, and both handler sets share the process's one server
credential. The promoted variant is natively qualified by
[ADR-194 run 9](../../test/results/adr194-continuation-native-9/environment.json):
capacity reaches `ReadyAt` through the promoted owner's observation handler.
Pending: step 8's audit profile reads by a promoted hub-api, which need a
public operation. Runs 27–32 are retained
failures: three on a shared Docker network without egress, then a CRD enum
without a type, a missing required policy field and the setup's five-second
budget.
Requirements: REQ-CAP-004–006, REQ-DB-004, REQ-DEP-005, S-02; TASK-11.
Amends [ADR-184](184-promoted-owner-first-launch.md). Builds on
[ADR-141](141-protected-capacity-production.md),
[ADR-182](182-installed-owner-promotion.md) and
[ADR-189](189-installed-permission-stream.md).

## Context

The capacity production chain and the promoted first launch depend on each
other:

- **Capacity needs a launched owner.** The capacity projection carries the
  local owner: the owner input, its source and its observation pin
  (template, image and protection digests). The hub-worker observes
  hub-cluster workloads through that owner's observation handler. The
  carrier requires the owner launch receipt, and today
  `CapacityLocalOwnerBinding` also requires `Native == nil`.
- **The promoted owner needs capacity.** Its `Public` input carries the
  capture, normal and resolution audit policies. They become readable
  (`read_capacity_audit_profiles`) only after the hub-worker publishes the
  capacity root (`ReadyAt`), which needs the capacity projection.
- ADR-182 also records that a promoted process does not serve the identity
  layer's observation handler.

Under ADR-184's single immutable launch, neither order works.

## Decision

1. **Before the launch: initialize capacity.** Everything that does not need
   a running owner happens in the continuation before the owner
   projection:
   - the capacity guard, the hub cluster's namespace guard, and the
     processing source with its guard;
   - the qualification;
   - `InitializeCapacity`, once the ADR-189 permission stream is fresh and
     acknowledged.

   The qualification's ID and digest and the account version are then
   final.
2. **The owner input pins, the hub reads.** `OwnerPublicDeployment`
   replaces the three embedded audit policies with the capacity
   qualification ID, its digest and the account version. At startup and
   while running, the hub-api reads the current profiles through its
   existing `capacity-profile-read` login. That reader already checks its
   pinned receipt and the complete ACL after its locks. Until the profiles
   are readable, the capture and operation audit lanes are unavailable,
   and every request that needs them fails closed. Reads and the identity
   layer still run.
   - Each lane has a selecting auditor. Each new `Begin` reads the lane's
     current profile and builds one healthy auditor per policy on first use.
   - A `Finish` uses the policy its own `Begin` used. That policy is kept
     per intent, because callers finish with the original, unbound intent.
     A renewal therefore never rebinds work in flight.
   - A `Finish` this process never began fails closed, and overdue recovery
     owns that intent.
   - The capture lane keeps its pinned policy. Its journal checks only the
     stable root, installation and store identities and the layout.
3. **After the launch: publish capacity.** The continuation reads the
   local owner carrier from the launched, promoted owner and publishes the
   capacity projection. `CapacityLocalOwnerBinding` accepts a promoted
   installed owner (`Native` and `Public` present) only in the
   provider-installed layout. The observation pin still binds the launched
   template.
4. **The promoted process serves observation.** The installed promoted
   hub-api serves the identity layer's observation handler and the native
   handler on 9444, selected by TLS server name. This closes ADR-182's open
   item.
5. **Operator inputs, minted identities, derived values.** No measured
   release values exist for the history footprints. The docs make them,
   like the backup horizon, inputs that an operator profile must qualify
   ([capture intent lifecycle](../architecture/capture-intent-lifecycle.md)).
   - **Operator profile** (continuation input):
     - pool and policy names and the approved selector keys;
     - accounts, records per account and per-lane sizes;
     - retention and admission seconds;
     - the backup profile: horizon, cleanup budget, proof window, backup
       and WAL copies;
     - the history and metadata footprint values;
     - the root envelope;
     - per backend, the storage profile and usable capacity.
   - **Chart:** renders the `EvidenceStoragePool` and
     `EvidenceBudgetPolicy` objects from the same values and ships their
     CRDs.
   - **Installer-minted:** the qualification, store, policy,
     backup-profile, backend and processing-epoch identities, as fresh
     UUIDs.
   - **Derived:**
     - the root (the permission root) and the account version (from the
       role setup);
     - the pool UID (from the pool object);
     - the guard digests (from the created guards);
     - the processing source UID;
     - the slot and backup arithmetic.
   - **Evidence digests:** each opaque digest is the SHA-256 of the
     canonical profile section it stands for, so it names exactly the
     operator input it qualifies.
   - **`ValidUntil`:** starts as the setup time, which keeps the capture
     root closed until the hub-worker's reserve phase sets the planned
     date.

6. **Hub-cluster selector guard probe.** The hub cluster's capacity
   namespace guard proves its denial with a dry-run namespace UPDATE. The
   probing account must hold `update` on the namespace it probes. Neither
   the hub-worker nor the owner may hold `update` on the hub namespace:
   the owner workload guard covers only namespaced resources, so that verb
   would let them change the hub namespace's Pod Security labels.
   - The probe namespace is a dedicated empty namespace,
     `asservat-<id>-capacity-probe`, with its own ServiceAccount
     `capacity-probe`. That account's only right is `get` and `update` on
     its own namespace.
   - The serving side of the hub cluster's observation, which is the owner,
     mints that account's ten-minute tokens. That serving composition
     (`ClusterObservationMetadata`) has no product caller yet; it is part
     of step 7.

7. **Local observation serving.** No product server answers the capacity
   observation purposes: the owner serves only the connector identity path,
   and the local path, `LocalHandler` and `ClusterObservationMetadata` have
   no product caller. So the owner:
   - adds the local path with `LocalHandler`. Its exchange is the hub
     cluster's metadata service, and its caller check is the hub-worker's
     `ClusterObservationCallerAdmission`.
   - mints the dedicated probe account's ten-minute tokens through the
     existing Pod-bound `CapacityTokens` helper. It gets only narrowly named
     RBAC: the probe namespace, its account, the selector guard and the
     cluster-wide workload lists the metadata reader needs.
   - takes these inputs from the `Native` section: the selector guard pin,
     keys, probe namespace and account, and the hub-worker caller pin. That
     section is final before the projection claim (ADR-184), after the
     capacity step created the guard. The owner selection, which pins
     `Observation`, comes earlier.
   - in the promoted process, serves both names on 9444. `GetConfigForClient`
     selects by TLS server name: the exact native name with required
     connector client certificates, or the common bootstrap name with the
     observation peer roots and optional client certificates. Each side
     keeps its own connection slots.

## Consequences

The owner keeps a single promoted launch. Public capture is unavailable for
the short interval between the owner launch and the hub-worker's capacity
publication, and stays unavailable if capacity never becomes ready. The
download path configuration (worker configuration revisions) must precede
the capacity projection, because `CapacityDeployment.Processing.Paths`
references them.

## Implementation

1. Storage pool and budget policy CRDs (generator, chart, helm check) and
   chart-rendered objects.
2. Capacity, namespace and processing guards with pins; the processing
   source ConfigMap.
3. Qualification builder from continuation input and pool UIDs.
4. Continuation: wait for a fresh, acknowledged permission stream, then
   `InitializeCapacity`.
5. Runtime audit profile reader in the public composition; owner input
   change.
6. Server-name dispatch on 9444 in the promoted process.
7. Local owner binding for the promoted layout; capacity projection after
   the launch; hub-worker readiness.
8. Native qualification: `ReadyAt` set and profiles readable by the hub-api.
