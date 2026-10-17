# ADR-179 — Outbound-only scope of the first installed investigation profile

Date: 2026-10-15. Status: accepted; fences, hub-held capability and target queries implemented with unit and real-TLS tests; hub-api composition pending.
Requirements: REQ-FED-001/003, REQ-DEP, S-02; TASK-03 / TASK-11.

## Context

REQ-FED-001 and [ADR-168](168-rotating-cluster-enrollment-credential.md) keep
regional connectivity outbound-only: the hub stores no workload cluster
kubeconfig and does not call that cluster's API. An inventory of the hub-side
S-02 composition found these undelegated reads and writes of a workload
cluster:

1. Preview and request target resolution (`ContextInvestigation.Targets`).
2. The context capability source, which pins the reading client to the
   target cluster.
3. Retention selector facts, local retention sources, and namespace metadata
   for automatic permission sources.
4. Download worker configuration, Job dispatch and cleanup (writes), worker
   enrollment proofs, and the `WorkerAPIs` download-peer proofs.

The single-cluster native journey could not show these, because hub and
region shared a cluster. ADR-171, ADR-172 and ADR-178 already delegate the
execution ports, owner discovery and the connector source.

REQ-FED-003 requires each storage and analysis profile to declare its
locality: "Raw artifacts and decryption remain local by default."
[ADR-068](068-download-worker-attestation.md) already lets the download
worker's cluster differ from the evidence cluster.

## Decision

The first installed profile is defined so that the hub reads only its own
cluster. Regional facts arrive only as delegated proof.

1. **Hub-region storage and download workers.** The first profile's evidence
   store and its download (acquisition) workers declare the hub's region as
   their locality boundary. Collectors in workload clusters upload ciphertext
   with write-only credentials and wrap keys through the hub's local key
   service ([ADR-176](176-artifact-keys-local-key-service.md)). These all
   become hub-local:
   - worker configuration;
   - Job dispatch and cleanup;
   - enrollment proofs;
   - download-peer proofs.

   A regional-local storage and decryption profile is a later profile. It
   needs a connector-side dispatch effect and delegated worker proofs, with a
   separate ADR.
2. **Hub-held capability.** Each workload cluster's context capability is an
   installer-managed, guarded ConfigMap in the hub control namespace. The hub
   reads its own cluster. The region still enforces its own installed
   settings independently: the executor's settings pin the collector image
   and projection, and the signed work binds both.
3. **Delegated target resolution.** Preview and request target resolution are
   pre-work target queries on the existing outbound context-start exchange
   ([ADR-171](171-hub-run-context-execution.md)). They are answered while the
   region waits for work, like [ADR-178](178-delegated-connector-source-on-context-start.md)'s
   source requests, so a query does not consume the standby.
   - `resolve-workload` resolves a workload by name to one current Pod.
   - `resolve-pod` re-pins one exact Pod.

   Before sending each query, the hub pulls a fresh regional source and checks
   the region's receiver. The region checks the hub owner and answers from its
   own cluster, as delegated proof with its original five-second freshness. The
   hub caps that freshness at the receiver's validity. Queries are not
   operations: a region still executes no operation without verified work.
   Each exchange answers at most four queries.

   The [ADR-144](144-cluster-local-observations.md)/[150](150-operation-owned-native-observation-proof.md)
   cluster observation channel was considered and rejected for this purpose.
   The product composes neither its regional client nor its local callers. It
   connects regions to the observation-mode owner pool, not to hub-api, so the
   investigation would need a second caller identity and federation owner reads
   for a second pool. Composing that channel remains required for capacity
   observation of workload clusters.
4. **Selector-free retention and permissions.** The first profile accepts
   retention policies without workload or namespace selectors, hub-topology
   policy sources and explicit permission bindings. A selector-based policy or
   a local retention source fails closed (unavailable) until delegated label
   facts exist. Those facts could reuse the guarded namespace labels of the
   `capacity-workload` observation. No present-day label is ever substituted.
5. **Fences now.** `WorkerAPIs` and the legacy non-installed capacity observer
   accept only the hub's own cluster.

## Consequences

The first profile stores evidence in the hub's region. A user who needs
evidence to stay in its workload region waits for the regional-local profile;
the profile's declared locality makes this visible. Each preview costs one
query on an idle standby. The connector needs read access to target
workloads and Pods in its own cluster, which it already has for collection.
Selector-based retention and automatic namespace permission sources are
explicitly unavailable in this profile, not silently approximated.

## Implementation

1. **Fences:** `validateOwnerNativeInputs` and the capacity worker refuse
   non-hub clusters.
2. **Capability:** a hub-held mode for `kube.ContextCapabilitySource`, where
   the reading client is the hub's own cluster and the capability names the
   target cluster.
3. **Targets:**
   - query and answer frames (11 and 12), with the source and frame budgets
     raised for four queries;
   - the region answers in `AwaitWork` through its existing
     `kube.NewAPIContextTargets`;
   - `contextstart.Targets`, the hub's implementation of the investigation's
     target port over idle standbys.
4. **Retention:** the first-profile composition passes no selector reader to
   `AcceptedRetentionReader`. That reader already refuses new collection
   whenever an applicable policy has a selector, and
   `TestAcceptedRetainedReaderKeepsOriginalPoliciesAndAvoidsUnneededMetadata`
   covers this. Local sources have no reconciler in this profile, so the
   reader reports them unavailable.

## Progress

- **Fences.** `validateOwnerNativeInputs` rejects any `WorkerAPIs` cluster
  other than the owner's own. `capacityClusterEndpoint` refuses a direct
  cluster API for any cluster other than the control cluster when no installed
  local owner exists. Both have unit cases.
- **Capability.** `kube.NewContextCapabilitySource` no longer pins the
  installed cluster to the reading client's cluster. The `hub-held` unit mode
  reads a workload cluster's capability from the hub's control namespace;
  targets of any other cluster stay refused.
- **Target queries.** Frames 11 and 12; `Router.Query` on idle standbys;
  `frameStream.query`/`answerQuery`; `contextstart.Targets` with exact answer
  checks and freshness capped at the receiver's validity.
  `TestContextStartActualHTTP2TargetQueriesKeepTheStandby` passes over actual
  TLS 1.3/HTTP/2:
  - workload and Pod queries are answered;
  - a closed `changed` failure keeps the exchange;
  - an invalid request never reaches the region;
  - a fifth query exceeds the exchange budget;
  - the same standby then serves signed work.

  The race detector passes for `contextstart`, `contracts` and the mtls
  context-start tests.
- **Remaining.** hub-api composition: a capability router per cluster, the
  investigation `Targets` port and a retention reader without selectors. Then
  native two-cluster qualification.
