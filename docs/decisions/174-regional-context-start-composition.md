# ADR-174 — Regional context-start composition in the connector process

Date: 2026-10-14. Status: accepted; composed with component tests; native qualification of the product binary pending. Decision 2 is superseded by [ADR-176](176-artifact-keys-local-key-service.md); the open capacity question is decided by [ADR-175](175-capacity-token-request.md).
Requirements: REQ-FED-001/002, S-02 regional context start; TASK-03 / TASK-11.

## Context

[ADR-171](171-hub-run-context-execution.md) leaves only cluster-local
operations in the region, and [ADR-172](172-delegated-owner-discovery.md)
delegates owner discovery and authentication to the federation channel. The
product `asservat connector` process still only supervised its credentials.
Composing context start there exposed three missing inputs:

- **Recovery.** The verify-only work-trust reader
  (`kube.APIContextWorkTrustSource`) needs the hub's current recovery state.
  The region has no SQL.
- **Artifact key wrapping.** Wrapping through the local key service
  (`kms.RemoteSealer`) needs a current exact-operation wrap authority, and only
  the download unwrap authority exists. The key service has no production
  composition yet.
- **Capacity account credential.** The capacity account that creates and marks
  Ready the `CapacityReservation` is a separate ServiceAccount. A Pod projects
  only its own account's token.

## Decision

1. **Delegated recovery.** The federation channel gains a read-only `recovery`
   purpose. The hub returns its current recovery state, and only for the
   presenting installation. The region uses it solely as the work-trust
   reader's recovery input. Nothing in the region can clear or change recovery.
2. **Encrypt-only OpenBao Transit wrapping** for the first installed profile.
   The regional output wraps the three artifact keysets with an OpenBao token
   whose policy allows only encryption with the artifact key
   (`evidence-wrap.token`). The region can create ciphertext and never unwrap
   it. The local key-service wrap authority stays a separate gap for the
   static-key profile.
3. **The capacity token is a fixed projected file.** `kube-capacity.token` is
   read on every request, like the other tokens. How the installer delivers it
   is open; options are recorded below. The process code does not depend on
   that choice.
4. **Pinned hub owners.** The installer pins the hub native listener address
   and the exact accepted owner configuration document (pool and issuer
   roots). Owner root rotation therefore needs regional reconfiguration.
5. Context start runs only while the connector credentials are active. The API
   process is built then. A stopped run is retried after the fixed delay as a
   new process observation and new exchanges, never resumed.

## Capacity token delivery (open)

- A long-lived ServiceAccount token Secret for the capacity account, mounted
  only into the connector Pod.
- A narrowly admitted TokenRequest by the connector account for the capacity
  account. Admission would require Pod-bound, ≤10-minute tokens.
- A separate regional capacity process that accepts only hub-signed start
  instructions. This keeps capacity and execution in different processes.

The first two give one process both identities, as ADR-135's regional runner
already did. Admission still separates which identity may perform which start
write. The third is the only option that keeps a compromised executor from
creating its own starts. It needs hub-signed prepare/ready instructions and a
second outbound process.

## Implementation

- `contracts.RegionalDeployment.APIContext` (`RegionalAPIContext`): settings
  ConfigMap and guard, installed settings, capacity/execution accounts,
  work-trust ConfigMap and guard, evidence store, wrap service, pinned owners
  and concurrency. `validRegionalAPIContext` checks it as a whole.
- `bootstrap.newRegionalContext` and `regionalContext.run`. The connector
  attester, settings protection, capacity client, start journal, Pod targets,
  API collector, write-only custody store, encrypt-only sealer, work-trust
  source with delegated recovery, verify-only signatures, and the
  pinned-endpoint context-start client go into `RegionalContextStartConnections`.
  The regional workload guard plan includes the API context start accounts.
- `connectorlifecycle.PurposeRecovery`, `Runners.Recovery`,
  `RegionalLifecycle.RecoveryState`; the federation supplies its existing
  recovery reader.

Tests: `TestRegionalDeploymentAPIContextInputsAreClosed`; the channel test
covers the recovery purpose, including refusal of another installation's
state; `TestRegionalLifecycleOwnerReadsRequireLocalSessionVerification` covers
the delegated recovery read.

## Remaining

The hub's work signer and context-start route in hub-api, the installer
(including the capacity token decision), and native qualification of hub-api,
federation and connector together.
