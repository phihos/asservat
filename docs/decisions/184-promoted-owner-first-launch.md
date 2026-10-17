# ADR-184 — Promoted owner on its first launch

Date: 2026-10-15. Status: accepted; steps 1–4 and 6 implemented and natively
qualified ([continuation run 18](../../test/results/adr183-continuation-native-18/result.json));
steps 5, 7 and 8 pending.
Requirements: REQ-DEP-001/003/005, S-02; TASK-11.
Builds on [ADR-182](182-installed-owner-promotion.md) and
[ADR-183](183-installer-runtime-continuation.md).

## Context

The ADR-183 continuation launches the owner through the existing identity
chain. The resulting `OwnerDeployment` has Observation and
ProviderAuthentication only. No product code produces:

- the Native or Public sections;
- the backend projection (`sql-routing.json`, `sql-native-read.json`,
  `worker-controls.json`, worker API tokens);
- the public projection contents the hub-api reads.

The public runtime projection is written as `asservat-public-runtime-<id>`,
while the installed owner template mounts `asservat-<id>-owner-public`.

Two ways exist to reach a promoted owner:

- **A. Relaunch.** Launch as today, then write a new input revision and roll
  the Deployment.
- **B. First launch.** Produce every Native and Public input before the
  first owner projection claim, so the one launch already carries them.

## Decision

1. **B: the first and only owner launch is promoted.** A relaunch is
   incompatible with the existing invariants:
   - The owner inputs ConfigMap is immutable and pinned by UID, resource
     version and the projection digest.
   - The journal holds one identity claim and one launch claim inside its
     original 30-minute end.
   - Startup, capacity and enrollment proofs bind the launch generation,
     revision `"1"`, the template digest and the ReplicaSet.

   The selection claim does not pin Native or Public. The projection claim
   does, so both sections are final and deterministic before that claim.
2. **Backend logins are identity purposes.** `routing` and `native-read`
   become owner identity role ordinals 4 and 5, with grants from the
   existing routing and native-reader statements. They are provisioned with
   the four identity roles inside the same installation driver, which
   amends ADR-182's backend root for these two files.
3. **Observation projection.** The continuation writes the
   `asservat-<id>-owner-observation` Secret with `worker-controls.json`.
   - The worker-control catalog is public, grants no authority (ADR-089),
     and changes as download workers are configured. The owner rereads it
     every second.
   - The Secret is therefore administrator-written and mutable, not part of
     the input receipt.
   - The first launch carries an empty catalog, which removes all worker
     trust until a configured worker control is added.
   - The local worker API uses the owner's projected observer token; a
     token stored in a Secret would expire.
4. **Public roles before launch.** The public runtime role root accepts an
   owner with zero replicas only while it is the inert original Recreate
   Deployment. The continuation then:
   - provisions and verifies the public roles;
   - publishes the runtime projection after the worker binding from phase 2
     exists.
5. **Public root as a projected volume** of two Secrets:
   - `asservat-public-runtime-<id>`: the immutable product role projection,
     unchanged;
   - `asservat-<id>-owner-public`: the operator's OIDC client secret and
     public TLS certificate and key.

   The operator Secret is not part of the input receipt. Operator
   credentials must rotate: TLS reloads per handshake, and a client-secret
   change takes effect at the next process start. Only installation
   administrators can write it, under the existing namespace guard. The
   continuation copies it from the inbox; later rotation is an
   administrator update.
6. **Input as receipt.** `OwnerNativeDeployment` and `OwnerPublicDeployment`
   carry the name and UID of each immutable product projection Secret. At
   startup the owner reads each Secret and compares immutability, UID and
   the mounted bytes.
7. **Native guards relax for the provider-installed layout only.** The
   checks are replaced by:
   - port 9445;
   - the pinned public provider recipe;
   - the presence of the projection references.
8. **Provider artifact and applier.**
   - The phase-3 owner artifact adds the four public purpose roles of
     ADR-182 and the public keys.
   - The applier additionally admits create-only Transit key creation
     (`<mount>/keys/<name>`), for the session key and the Ed25519
     work-signing key.
   - Mounts and PKI CAs remain operator prerequisites, as in ADR-149.
   - The continuation reads the signing public key back through the
     inspection token.
9. **Order in the owner phase:**
   1. accepted source, identity root and SQL, selection;
   2. derive Native and Public;
   3. outbox and inbox, audit Secret;
   4. observation projection, public roles and projection, operator public
      Secret;
   5. owner projection and launch.

## Consequences

The owner launch moves later inside the original window. Two operator waits
and about forty public role claims must fit before the journal end;
qualification measures this. The owner Role and ClusterRole are original
journal objects, so every name the public and native layers read must be
fixed before the first claim.

Inputs without a producer remain explicit gaps, each a later continuation
step:

- retention topologies and connector roots;
- browser and identity settings ConfigMaps;
- executor startup digests;
- worker PKI roots;
- the hub-worker's browser-settings and browser-cleanup roles, since the
  worker launched in phase 2.

## Implementation

1. Identity purposes `routing` and `native-read`: grants, call budget,
   projection keys, template items, inputs.
2. Observation projection producer.
3. Public role root before launch; continuation phase for public roles.
4. Projected public volume and operator Secret.
5. Projection references in the Native and Public DTOs, with startup
   checks.
6. Native guard relaxation for the provider-installed layout.
7. Owner artifact public roles and keys; applier key admission.
8. Continuation ordering and native qualification through a running
   promoted owner.
