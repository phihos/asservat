# ADR-180 — hub-api public composition and its protected inputs

Date: 2026-10-15. Status: accepted; P1–P5 composed in product code with unit tests; P6, the hub-worker and installer producers, and native qualification pending.
Requirements: S-02, REQ-DEP, REQ-DB-004, REQ-FED-001; TASK-03 / TASK-11.

## Context

`asservat hub-api` starts only the owner subsystem. The browser, MCP and
download layer exists as assembly functions (`NewPublicContextOperations`,
`NewPublicContextHandler`) that only tests call. The native public journey
composes that layer from real adapters, but supplies many of its inputs
synthetically:

- identity and browser sessions;
- the work signer and its trust;
- the capability source;
- worker jobs, enrollment proofs and PKI;
- audit keys and policies.

The installer already projects the public SQL credentials
(`sql-public-<purpose>.json` plus `public-roles.json`), but no hub loader reads
them. `ContextPublisher` has no product caller.

[ADR-177](177-hub-sql-connection-governor.md) fixes the SQL model.
[ADR-179](179-outbound-only-first-installed-profile.md) fixes what the hub may
read.

## Decision

1. **One optional public section.** `OwnerDeployment.Public` enables the
   public layer, and requires `Native`, because downloads use the native
   listener. Without `Public`, hub-api stays owner-only, as today. All public
   inputs are installer-owned fixed files and closed DTO fields. No request,
   flag or environment variable selects an endpoint, credential or audience.
2. **Public SQL pools.** One pool per purpose comes from the installer's
   projection, opened on first use:
   - `MaxConns=1`, governed by the hub-api's single ADR-177 governor;
   - verified with `VerifyPublicRuntimeCredential` before first use.

   Hot purposes are the browser session and refresh lanes, both audit lanes,
   capture admission with its journal and acknowledgement, the download
   session and native owners. Every other purpose is cold. hub-api never opens
   `browser-settings` or `browser-cleanup`; those belong to the hub-worker
   under ADR-177.
3. **Identity** uses the Keycloak profile ([ADR-053](053-keycloak-access-profile.md))
   only.
   - **Issuer, client ID and origin** come from the protected browser settings
     ConfigMap, pinned by name and UID.
   - **Browser login** verifies access tokens for one explicit installer
     audience.
   - **MCP and download bearer tokens** are verified for the audiences the
     transports already derive: `<origin>/mcp` and `<origin>/api/v1/downloads`.
   - **Provider CA and client secret** are fixed files: `oidc-roots.pem` and
     `oidc-client-secret`.
   - **Organization and client policy** comes from the pinned
     identity-settings ConfigMap.
   - **Browser session ciphertext** uses an OpenBao Transit key through two
     fixed token files, one encrypt-only and one decrypt-only.
4. **Investigation and regional start:**
   - **Targets** use `contextstart.Targets` over the owner's context-start
     router.
   - **Capability** has one hub-held guarded ConfigMap per workload cluster,
     routed by target cluster.
   - **Retention** uses `AcceptedRetentionReader` over the native retention
     topology pins, with no selector reader.
   - **Work signing:**
     - one OpenBao Ed25519 signing key, read through a fixed token file;
     - signing is routed per target cluster;
     - each cluster has a hub-held guarded work-trust ConfigMap.

     Like the capability source, the work-trust source no longer pins its
     settings to the reading client's cluster. The regional validation keeps
     its own pin.
5. **Audit:**
   - The operation MAC comes from `public-audit-keys.json`.
   - Operation and capture audit objects use the existing audit store and
     audit Transit sealer and opener.
   - Lifecycle policies come from their installer-provisioned SQL backings,
     never from code constants.
6. **Downloads.**
   - **Worker configuration and download environment** are hub-held guarded
     ConfigMaps.
     - hub-api reads the worker profile from its source and serves only a
       revision already current in SQL (ADR-070). Accepting a revision is
       the hub-worker's duty, and a later revision takes effect through a
       new process.
     - Worker Jobs run in a pinned `Native.WorkerAPIs` namespace on the hub
       cluster.
   - **Enrollment proofs** read that namespace.
   - **Worker leaves** come from an OpenBao PKI role, whose token is the fixed
     file `worker-issue.token`.
   - **Download, window, stop and operation audits** use the owner audit
     store (`AuditStoreID`).
   - **Artifact key binding** names `ArtifactKeyID` on the local key service.
7. **HTTPS.**
   - hub-api terminates TLS 1.3 with the mounted `public-tls.crt` and
     `public-tls.key`, and follows rotation.
   - Forwarded headers confer no trust.
   - The console package is image-owned (`/usr/share/asservat/console`).
   - The public listener shares the deployment's lifetime. Shutdown waits for
     in-flight requests, and a failed public server stops the deployment.
8. **Publication** (P6) and its verifier unwrap authority follow in a later
   revision.

## Consequences

hub-api's public startup fails closed when any listed input, credential or
pinned object is missing or changed. The process holds every public purpose's
credential, as ADR-177 already accepts. Changing an audience, issuer or origin
requires a new installer revision, never a runtime switch.

## Implementation

1. **P1:** `OwnerDeployment.Public`, the manifest reader and governed public
   pools.
2. **P2:** identity, browser sessions and refresh owners.
3. **P3:**
   - the investigation, intents and regional start;
   - capability and work-signer routing;
   - targets and retention.
4. **P4:** downloads, native runtime, stop and transfer.
5. **P5:** the public HTTPS listener.
6. **P6:** the publication owner.

Each phase adds its fields, validation and unit tests. Native qualification
follows the whole composition.

## Progress

- **P1.** `OwnerDeployment.Public` requires `Native`, an exact HTTPS origin and
  a governor budget that leaves cold slots.
  - `readPublicRuntimeManifest` binds the projection to the owner's
    installation, cluster, namespace and configuration.
  - `publicPools.open` refuses unknown purposes, the hub-worker's browser
    settings and cleanup purposes, and another purpose's login. Each pool runs
    under the shared governor and is verified before use.
- **P2.** `newPublicIdentity` reads the pinned browser settings once and requires
  their origin to equal `Public.Origin`. It then composes:
  - the Keycloak-profile browser provider and three access verifiers (browser,
    MCP and download audiences);
  - identity policy;
  - the Transit session cipher;
  - the SQL session store.
- **P3.** `newPublicContext` composes:
  - per-cluster connector admissions over the owner native-read registry;
  - hub-held capability and work trust (`kube.NewAPIContextWorkTrustSource` no
    longer pins the reading cluster; a unit test covers the hub-held read);
  - the routed work signer over one OpenBao Ed25519 key;
  - the context-start router and `contextstart.Targets`;
  - selector-free retention;
  - the investigation, capture audit intents with the installer's capture
    policy, the hub-run runner, progress and cases.

  The owner native runtime receives the context-start configuration.
- **P4.** `newPublicDownloads` composes:
  - the download authority gate;
  - worker configuration and environment sources;
  - Jobs, the dispatcher, enrollment with its attester and issuer, and
    request owners on the owner router;
  - native owners and key bindings;
  - stop through the two-login `publicStopLedger`;
  - the coordinator and download plans.

  These all go through `NewContextNativeDownloadRuntime` on the actual owner
  runtime.
- **P5.** `newPublicHandler` composes:
  - both audited operation lanes, under their installer policies;
  - browser refresh owners over the three refresh logins;
  - the complete operation set and `NewPublicContextHandler`.

  `OwnerDeployment.RunPublic` serves it, and `RunHubAPI` opens the listener
  only with `Public`. Unit tests cover the input bounds and certificate
  rotation.
- **Gaps found.** The owner `routing` and `native-read` roles have no product
  provisioner (`contracts.OwnerRuntimePoolPurposes`). `native-read` also needs
  the connector registry read grants. Both are installer work. The
  hub-worker must still accept worker configuration revisions and run browser
  settings observation and cleanup. Every public input, backing and key named
  here still needs its installer producer.
