# ADR-194 — Promoted owner inputs

Date: 2026-10-16. Status: accepted; implemented and natively qualified
([continuation run 9](../../test/results/adr194-continuation-native-9/environment.json):
the promoted owner is Ready, capacity reaches `ReadyAt` through its 9444
observation handler, and the regional cluster still enrolls).
Requirements: REQ-DEP-001/003/005, REQ-DLD-001–004, S-02; TASK-11.
Completes the open inputs of [ADR-184](184-promoted-owner-first-launch.md)
steps 5, 7 and 8, and amends its decision 9. Builds on
[ADR-185](185-public-sources-and-cluster-catalog.md),
[ADR-190](190-capacity-readiness-and-promoted-owner.md),
[ADR-192](192-capacity-before-download-paths.md) and
[ADR-193](193-installed-federation-and-regional-enrollment.md).

## Context

The continuation still launches an observation-only owner: `Native` and
`Public` are nil. ADR-184 fixed how the first launch is promoted, but not
where each input comes from. Most fields are already derivable:

- The public sources step creates the browser settings, identity settings and
  cluster catalog, but the continuation discards the result.
- The capacity qualification holds the capture lane policy, the audit store
  ID and the qualification digest.
- The federation settings hold the connector issuer roots.
- The public runtime projection publish returns the projection's name and
  UID, which the continuation also discards.

Three inputs have no producer, and the hub-api cannot start without them:

- the worker configuration source, read at startup;
- at least one worker API;
- at least one retention topology.

## Decision

1. **Opt-in promotion.** `public.promotion` selects a promoted launch.
   Without it the continuation launches the observation-only owner, so the
   existing qualified path is unchanged. Promotion requires the capacity and
   federation settings.
2. **Operator settings without defaults:**
   - the browser audience;
   - the provider roots PEM;
   - one Transit mount for the session and work-signing keys (distinct from
     the audit and owner PKI mounts);
   - the worker PKI mount (distinct from the owner PKI mount).
3. **Derived names.** The session key, the Ed25519 work-signing key and the
   worker PKI role are derived from the installation. Like the federation's
   keys, the phase-3 artifact creates them create-only. The continuation reads
   back the signing key's version and public key and the worker PKI roots
   through the inspection token, checking the key types. The key ID is
   `<name>-v<version>`. The public provider recipe digest is computed last,
   because it covers the public key and the roots.
4. **Worker configuration (D1).** The continuation creates the fixed,
   guarded worker configuration source holding an exact unconfigured
   document (`contracts.UnconfiguredWorkerConfiguration`), compared byte for
   byte. The hub-api reads the source at process start. When it holds that
   document, downloads are composed without a native runtime:
   - prepare fails closed before any reservation;
   - the content paths answer 503 instead of reaching the console;
   - existing sessions stay readable and stoppable.

   Configuring a worker takes a new process, as any later revision already
   does (ADR-070). *Amended during implementation:* the first draft resolved
   the source per download. No product component accepts a worker
   configuration revision into SQL yet (ADR-192), so there is nothing to
   resolve per download, and every download service is bound to one worker
   profile.
5. **Worker APIs (D2).** The provider-installed layout allows an empty
   list. *Amended during implementation:* the first draft created a worker
   namespace in the hub cluster. ADR-192 decision 3 places the worker
   namespace, together with its source, in the download path's acquisition
   cluster during regional provisioning. A hub-cluster namespace now would
   be speculative, and it would also need an observer token.
6. **Retention topologies (D3).** The provider-installed layout allows an
   empty list. Per-cluster topology pins move into the ADR-185 cluster
   catalog with fixed slot names in the owner Role, as clusters did.
7. **Download environment.** The owner's `-download-environment` ConfigMap
   with its own guard. It carries the same settings as capacity's processing
   source (ADR-192): an empty path list and the capacity settings'
   processing operators. Both sources are named by the existing owner Role
   and workload guard. Because the settings need the permission root, the
   continuation creates both download sources in a second public sources
   call after the capacity and federation steps.
8. **Limits (D7).** Standby, captures, preview, operation, MCP and download
   limits default to the values of the existing owner input tests. Native
   connections and concurrency equal the owner's. These defaults are not
   qualified capacity claims.
9. **Artifact key ID (D8).** A derived constant until the regional
   key-service work installs the local key service.
10. **Projection reference (ADR-184 decision 6).** `Public.RuntimeProjection`
    names the immutable public runtime projection. Admission requires the
    fixed name and a UUID. At startup the owner reads the Secret and requires
    it to be immutable, with the same UID and annotations, and with every key
    equal to its mounted file. Native needs no reference: `routing` and
    `native-read` are identity purposes in the already bound identity
    projection, the observation Secret is mutable, and the operator Secret is
    excluded.
11. **Operator public Secret.** The phase-3 inbox carries the OIDC client
    secret and the public TLS certificate and key. The continuation writes
    them into `asservat-<id>-owner-public`. Operators cannot write the guarded
    namespace themselves; later rotation is an administrator update.
12. **Order (amends ADR-184 decision 9).** Public roles and the runtime
    projection stay before permission and capacity, since ADR-189 and ADR-190
    need them. The order is:
    1. accepted source and public roles;
    2. selection;
    3. permission, capacity and federation;
    4. deriving Native and Public;
    5. the outbox and the inbox;
    6. key readback, the recipe digest, the observation projection (empty
       catalog) and the operator public Secret;
    7. owner projection and launch.

## Consequences

A promoted launch still depends on three other pieces:

- The capacity projection binding rejects `Native != nil`.
- ADR-190 step 6 (TLS server-name dispatch on port 9444) is not implemented.

These are part of the implementation below. Downloads stay disabled until a
worker is configured and the regional key service exists. With an empty
topology list every retention effect is denied, so captures need the
per-cluster topology pins that move into the cluster catalog (decision 6;
ADR-193 step 7).

## Implementation

Steps 1-9 are implemented with unit tests:

- the reference admission and the startup projection check;
- the guarded sources (`EnsurePublicSources` with the environment);
- the derivation (`derivePromotedOwner`, checked by `validateOwnerDeployment`);
- the artifact (four public roles, two create-only Transit keys, the worker
  PKI role and eight public audit prefixes on the owner principal);
- the readback (`VerifyOwnerPublic`);
- the inbox public files and `WriteOwnerPublicSecret`;
- the continuation's `promote` step;
- the capacity binding and the 9444 server-name router (ADR-190 step 6).

The derivation runs `validateUnprojectedOwnerDeployment`: the owner's own
check, minus the observation activation, which the owner projection
attaches later. The launched owner still runs the full check.
[Run 1](../../test/results/adr194-continuation-native-1/) and
[run 2](../../test/results/adr194-continuation-native-2/) are retained
failures:

- Run 1 stopped at `public/derive`, which carried no cause yet. The
  derivation and the validator now name the failed check.
- Run 2 named it: `validate/provider-authentication`. The check required
  the activation before the projection exists.
- Run 3 passed the derivation and stopped in the owner installation at
  `projection.final-native: native.source-branch`. Earlier observation runs
  hit this step intermittently; the tail and finish checks now report
  whether their context expired or was cancelled, and the stop message
  reports how much of the original window was left at the start.
- Run 4 completed the installation. The promoted process then exited at
  startup with only `phase=full-deployment`; `NewOwnerDeployment` now
  reports its own phase for each region.
- Run 5 named `phase=owner-runtime`. The context-start ingress required at
  least one connector admission. It now accepts an empty catalog, as
  ADR-185 decided, and denies every start.
- Run 6 found the cause of the intermittent owner installation failures
  (observation runs 35, 41, 46, 48 and 50, and run 3 here). The
  administrator identity was compared as the whole `SelfSubjectReview`
  `UserInfo`. That includes the token's own credential ID, and the kubelet
  refreshes the continuation's 600-second projected token after about
  480 seconds, which is when the owner phase runs. The comparison now drops
  that one extra: the name, UID, groups and Pod binding still have to match.
- Run 7 still stopped at `phase=owner-runtime`. The composition passed a nil
  admission list for the empty catalog, which the ingress refuses. Run 7's
  harness reports `sourceUnchangedDuringTest: false`: the fix was edited
  after its owner failed but before the harness finished.
- Run 9 passes (exit 0, no cleanup failures, source unchanged).
- Run 8 passed the owner runtime and the unconfigured downloads and stopped
  at `phase=public-handler`. The harness image had no console package. It
  now builds one fresh into the image at `/usr/share/asservat/console`
  (recorded as `consolePackageSHA256`), as a product image must ship it.

Two further amendments came out of implementation. `Version` is a required
operator setting, because no build-version source exists to fall back on.
One operation-audit retention uses the shorter of the normal and resolution
lane retentions, which never exceeds what either lane prepaid.

1. Contracts: `public.promotion` settings and `Public.RuntimeProjection`.
2. Reference admission and the startup projection check.
3. The owner download environment and worker configuration sources, and the
   worker namespace.
4. Pure derivation of Native and Public, checked against the owner's own
   input validators.
5. Artifact public roles, keys and the worker PKI role.
6. Key and root readback with type checks.
7. Inbox public material and the operator public Secret.
8. Continuation wiring.
9. The capacity binding and server-name dispatch.
10. A native continuation run with a running promoted owner.
