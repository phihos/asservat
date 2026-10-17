# ADR-198 — Installed key service

Date: 2026-10-17. Status: accepted; implemented and natively qualified
([ADR-196 continuation run 8](../../test/results/adr196-continuation-native-8/environment.json)).
Requirements: REQ-DEP-003/005, REQ-FED-002, artifact-downloads, S-02; TASK-03, TASK-11.
Gap 5 of [ADR-196](196-regional-cluster-join.md). Installs the
[ADR-176](176-artifact-keys-local-key-service.md) key service with the
[ADR-064](064-local-key-material.md) and
[ADR-067](067-protected-local-key-lifecycle.md) key material. Amends ADR-176
decision 3 and ADR-196 decision 6.

## Context

A regional connector wraps every artifact keyset through the hub's local
key service (ADR-176), and a failed wrap stops acquisition. The
`asservat key-service` command exists. No integration test starts it, and
nothing installs it. These are the code facts:

- **Root key and configuration.** Only the lifecycle test creates the
  immutable `keys.json` Secret and its configuration ConfigMap. No product
  code generates key material. ADR-064 places randomness in bootstrap and
  forbids lazy generation. ADR-067 forbids the service writing Secrets.
- **SQL logins.** The service opens three logins: `key-configuration`,
  `key-wrap` and `key-verify`.
  - `key-wrap` and `key-verify` have product grant lists
    (`ContextKeyWrapGrantSQL`, `ContextKeyUnwrapGrantSQL`).
  - `key-configuration` has only a fixture grant.
  - None of the three has a permanent ordinal or a projection.
- **Connector pins.** The deployment input requires one to sixteen pinned
  connector sources. At continuation time no region has joined, so the
  list would be empty. Pinning a joined region later would change the
  immutable input and the Pod template, which is the replacement problem
  ADR-196 describes.
- **Precedent.** The federation already dropped its pinned peer list.
  ADR-193 resolves each presented connector from its staged SQL profile.
- **Serving identity.** The service reads a static `tls.crt`/`tls.key`
  pair. Nothing produces it.

## Decision

1. **A separate key-service Deployment.**
   - Placement: in the hub namespace, under its own ServiceAccount, with
     one replica and the `Recreate` strategy, under Pod Security
     `restricted`.
   - Mounts: none of the hub-api, hub-worker, publisher or federation
     Pods mounts the key Secret or the key-service credentials.
   - RBAC: named `get` on the namespace, the key configuration ConfigMap
     and the key Secret. No list, watch or write.
   - Exposure: an L4 Service on port 9447, with the federation's service
     type and an optional pinned NodePort, because regions dial it
     outbound (ADR-176).
2. **The continuation generates the root key once.** After the federation
   workload, the continuation:
   - creates the immutable Opaque Secret with 32 bytes from `crypto/rand`
     as version 1 of `asservat-local-keys/v1`, and clears the buffer;
   - creates the ConfigMap `asservat-local-key-configuration/v1`, which
     names the Secret by name, UID and SHA-256, at revision 1, with the
     fleet issuer epoch as `RecoveryEpoch`, unsuspended.

   A rerun reopens both by UID and digest and never regenerates. A guard
   (ValidatingAdmissionPolicy and binding) refuses writes to the ConfigMap
   by anyone except the installation administrators. The Secret needs no
   guard: it is immutable, and the ConfigMap pins its UID and SHA-256, so a
   replaced Secret is refused rather than used. The continuation
   prints a fixed instruction to back up the Secret, because losing it
   makes stored artifacts unreadable and ADR-067 recovery is unfinished.
   The root key passes through the installer process's memory once, and
   only the key-service Pod ever mounts it.
3. **Key-service SQL logins are permanent.**
   - `key-configuration`, `key-wrap` and `key-verify` get ordinals 82–84.
   - They use product grant lists. `key-configuration` gets the fixture's
     list. `key-wrap` gains column SELECT on the staged connector profile
     (decision 4).
   - The logins ride in their own immutable key-service projection, with
     its own claim in the role state, as the federation's do.
   - The role layout digest changes, which applies to fresh installations
     only.
   - The service accepts its configuration itself on first observation
     (ADR-067 `ObserveLocalKeys`). That requires the live recovery
     observation and the issuer epoch.
4. **Connectors resolve from SQL.** This amends ADR-176 decision 3 and
   ADR-196 decision 6.
   - The deployment input drops `Connectors` and gains
     `ConnectorClientRoots`, the installation connector issuer roots.
   - TLS accepts connector client chains from those roots, and key-client
     chains from the key-client roots.
   - For a connector leaf, the peer union:
     1. parses the leaf URI into its peer binding;
     2. reads that exact peer's staged profile (unsuspended, unblocked);
     3. verifies the chain against the profile with
        `ConnectorCredentialVerifier`.
   - Staged profiles are cached by their exact bytes, at most 16.
   - Resolution needs the request context, so the key handler's peer
     verifier receives it.
   - What authorizes a wrap is unchanged: `ContextKeyWraps` binds the
     wrap to the activated leaf of the prepared attempt's own serving
     process.
5. **The serving identity is an operator Secret.** It holds `tls.crt`,
   `tls.key` and `ca.crt`, as for the federation. The continuation reads
   its roots. The regional offer gains `KeyService` (endpoint, roots and
   artifact key ID), and installer-cluster passes it to the connector's
   `RegionalWrapService`.
6. **Key clients are the promoted owner's worker PKI.** `KeyClientRoots`
   are the acquisition issuer roots (ADR-194). The key service therefore
   requires promotion and federation.
7. **No download unwrap.** `NativeKeyAuthority` stays uncomposed, and the
   hub keeps no raw unwrap. The `key-verify` login is provisioned now
   because the service requires it, and its verifier peer has no installed
   issuer yet.

## Consequences

Adding a region needs no key-service change. A key-service outage stops
regional captures before any source opens. A cluster administrator of the
hub cluster can still read the root key; that is
[small-deployments.md](../research/small-deployments.md)'s stated
limitation. The hub cannot prove the key guard live, and the service does
not check it: an administrator-changed configuration still has to pass the
ADR-067 monotonic SQL acceptance. Root rotation, retirement and
OpenBao-wrapped roots stay future work.

## Implementation

1. Contracts: deployment input `ConnectorClientRoots` (connectors
   dropped), the key-service settings (endpoint, server name, node port),
   the offer's `KeyService`, port 9447 and the object names.
2. Postgres: ordinals 82–84, the grant lists and the key-service
   projection claim and verification.
3. mtls and key service: the SQL connector peer resolver and the
   context-aware peer verifier.
4. kube: the root key and configuration producer with its guard, the
   key-service workload (Deployment, Service, RBAC, inputs) and its serving
   roots.
5. Continuation: the steps after the federation workload, and the offer.
6. installer-cluster: the offer's key service into the connector input.
7. Native run:
   - the continuation installs the key service;
   - its configuration is accepted in SQL;
   - its TLS endpoint answers with the offer's roots;
   - an unknown client chain is refused;
   - no other hub Pod mounts the key Secret.

   A real wrap is part of ADR-196's capture run.

## Progress

- **Contracts.** `KeyServiceDeployment` drops `Connectors` and gains
  `ConnectorClientRoots`. The key service listens on port 9447. The
  federation settings gain `keyServiceEndpoint` and `keyServiceNodePort`,
  and the offer gains `keyService`. The three logins take ordinals 82–84 in
  their own `key-service` connection compartment (two retained processes),
  and stay out of the hub projection.
- **SQL.** The role plan grants:
  - `key-configuration`: the fixture's ADR-067 list;
  - `key-wrap`: `ContextKeyWrapGrantSQL` plus the profile columns
    `configuration`, `suspended` and `blocked`;
  - `key-verify`: `ContextKeyUnwrapGrantSQL`.

  `ConnectorIdentityProfiles.ReadConnectorProfile` reads one staged
  profile without its root backing.
- **Peers.** `mtls.ConnectorKeyPeerVerifier` resolves the presented leaf's
  peer through a read function on each request and caches at most 16
  verifiers by exact staged bytes. A suspended profile, another root or
  installation, or another issuer epoch is refused. The key handler passes
  its request context to a `ContextPeerVerifier`.
- **Kubernetes.**
  - `EnsureLocalArtifactKey` generates the root once, guards the
    configuration and reopens exactly.
  - `BuildKeyServiceWorkload` reuses the federation's object set and
    `EnsureFederationWorkload`.
  - `ReadKeyServiceServingRoots` verifies the endpoint host, which may be an
    IP address.
  - `PublishKeyServiceRuntimeProjection` projects the three logins.
- **Continuation.** `KeyService` runs inside `FederationWorkload`, before
  the offer: projection, root, serving roots, account, workload and
  settle. It prints the fixed backup instruction.
- **Unit tests.** Contracts, mtls, postgres, bootstrap and the affected
  Kubernetes tests pass.
- **Native runs 1–3 failed and are retained.**
  - Runs [1](../../test/results/adr198-continuation-native-1/environment.json)
    and [2](../../test/results/adr198-continuation-native-2/environment.json)
    installed the key service. In both, its configuration was accepted in
    SQL at revision 1, and each failed on a check in the test.
    - Run 1 queried the `bytea` snapshot as `jsonb`.
    - Run 2 expected `tls.AlertError`. Go reports a remote TLS alert as a
      plain error, and the client withheld its unknown certificate because
      the server's acceptable-CA list did not name its issuer.
    - The check now forces the certificate and accepts any remote TLS
      alert after the server is verified under the offer's roots.
  - [Run 3](../../test/results/adr198-continuation-native-3/environment.json)
    stopped earlier, at the owner launch's
    `projection.final-native` (`finalize-commit`). The finalization
    transaction exceeded its narrowed freshness bound after 4.0 s. This is
    the first stop at that stage in all recorded runs, and it is on a path
    this change does not touch. It is recorded as an intermittent timing
    failure; validation was not weakened.
  - All three runs exited with no cleanup failures and unchanged sources.
- **Natively qualified** in [ADR-196 continuation run 8](../../test/results/adr196-continuation-native-8/environment.json), which
  passed (exit 0, all four tests, no cleanup failures, source unchanged):
  - the continuation installs the key service, and SQL accepts its
    configuration at revision 1;
  - it serves under the offered roots;
  - an unknown client chain gets a TLS alert;
  - no other Pod mounts the root key or its logins.

  The same checks passed in ADR-196 runs 2–7, each of which failed later at
  the regional executor. A real wrap needs a prepared attempt, and belongs to
  ADR-196's capture run.
