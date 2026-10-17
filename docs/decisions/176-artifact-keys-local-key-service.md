# ADR-176 — Artifact keys through the local key service with attempt-scoped wrap authority

Date: 2026-10-14. Status: accepted; wrap authority, connector key peers, per-attempt regional sealer and the `asservat key-service` command implemented; the wrap authority passes on real PostgreSQL; unwrap composition, installer and native end-to-end qualification pending. Amends decision 2 of
[ADR-174](174-regional-context-start-composition.md).
Requirements: REQ-DEP-003, REQ-FED-002, artifact-downloads, S-02; TASK-03 / TASK-11.

## Context

ADR-174 had the regional collector wrap artifact keysets with an encrypt-only
OpenBao Transit token. Every unwrap path that exists cannot read such keys:

- The native context reader always unwraps through `kms.RemoteOpener`, the
  local key service.
- `KeyRequest.Valid` accepts only `asservat-local-keyset/v1/…` references for
  unwrap.
- Both unwrap resolvers (`DownloadKeys`, `NativeKeyAuthority`) check the same
  prefix.

There is no bounded OpenBao unwrap authority. A freely renewable unwrap token
is rejected by [ADR-066](066-download-key-authority.md). OpenBao-wrapped
regional artifacts would therefore be permanently unreadable. The native
journey test wrapped in-process with the local root key, which is a test
shortcut, and unwrapped through the real key-service handler.

[ADR-065](065-local-key-service-boundary.md) and
[local-key-service.md](../architecture/local-key-service.md) already require
every key operation to be authorized against current exact authority, never a
certificate or role ACL alone, with three wraps per prepared attempt. Only the
download unwrap authority exists.

## Decision

1. **Artifact keys use the local key service in every profile.** The
   artifact purpose (collector wrap, regional reader unwrap) always goes
   through the local key service, an unprivileged Deployment in the hub
   cluster with its own SQL credentials. OpenBao stays the default for audit
   keys, owner/connector PKI and certificates. Giving the key service an
   OpenBao Transit backend later is possible; it would need a new reference
   format.
2. **Wraps need attempt-scoped authority.** Wrapping discloses nothing.
   Without authority, though, a compromised connector could mint correctly
   bound ciphertext for any cluster, artifact or attempt, which is a forgery
   primitive. The new SQL authorizer `ContextKeyWraps` grants a wrap only when
   all of the following hold:
   - The scope is the artifact purpose, the operation is `wrap` and the
     authority ID equals the attempt UUID.
   - Locks are taken in this order: recovery, then the permission root, then
     the `context_execution` row of that attempt. That row must be in phase
     `prepared` with no object UID.
   - Database time is before its `not_after`.
   - The request's key binding is exactly
     `ArtifactKeyBinding(expectation.Binding(), role)` for the execution's
     expectation.
   - The presenting certificate is an activated, unretired connector client
     leaf of the execution's own serving process (Pod UID and process epoch
     from `process_json`).
   - A monotonic spent mask allows each of the three keyset roles at most
     once.
   - The permit lasts until the earliest of the execution's `not_after`, the
     leaf's expiry and five seconds.
3. **The connector client leaf is the collector's key-client identity.** The
   key-service peer verifier accepts it as role `collector`, resolved through
   the connector registry rather than through a separate key-client
   certificate usage.
4. **Per-attempt sealer.** The regional producer wraps with a per-attempt
   `RemoteSealer` whose authority is the attempt ID. The client presents the
   connector process's current client certificate.
   `contracts.RegionalWrapService` becomes an endpoint, roots and key scope;
   the OpenBao `evidence-wrap.token` is dropped.
5. **One authorizer per operation.** A key-service scope dispatches its
   authorizer by operation: wrap goes to `ContextKeyWraps`, unwrap to the
   existing native download authority.

## Consequences

The hub keeps neither wrap nor unwrap authority, and root keys never enter the
hub-api, federation or any regional Pod. A key-service outage blocks capture,
because a failed wrap stops acquisition before the source is opened. A lost
wrap reply spends that role's slot, and the runner reports the attempt as
Indeterminate.

The key service runs in the hub cluster, so regions need an outbound path to
it, just as they already need one to the federation and the hub native
listener. A cluster-admin compromise of the hub cluster can still expose the
mounted root keys ([small-deployments.md](../research/small-deployments.md)).

Publication verification must fully decrypt
([context-publication.md](../architecture/context-publication.md)) and has no
product unwrap authority yet. The journey test unwraps in-process. It needs
its own verifier unwrap resolver; the hub must not receive unwrap.

## Implementation

1. **Migration.** A `context_key_wrap` table with attempt, root, peer
   certificate digest and a spent-roles mask that may only increase, plus a
   narrow role. It has SELECT on the execution, connector registry and
   recovery tables, and INSERT/UPDATE on its own mask.
2. **Authorizer.** `postgres.ContextKeyWraps.Resolve`, and an operation
   dispatcher for the key-service scope.
3. **Peer verifier.** `mtls` key-peer verification for connector client
   leaves as role `collector`.
4. **Producer.** A per-attempt sealer in the regional producer, and the
   amended `RegionalWrapService` contract.
5. **Process.** An `asservat key-service` command composing the protected
   local key loader (ADR-067), the handler, the SQL pools and the peer
   verifiers.
6. **Hub download composition.** The hub's native download preparation and
   window keys (`NativeAttachmentConfig`).
7. **Installer and Helm.** The key Secret and ConfigMap, the Deployment, the
   SQL roles and the key-client trust.
8. **Verifier unwrap.** A publication verifier unwrap resolver, which is a
   separate follow-up.

## Progress

- **Migration 62 (`context_key_wrap`).** Spending can only add roles and is
  never deleted. `postgres.ContextKeyWraps` reads the prepared execution and
  its expectation under the recovery lock, checks the executor's activated
  client leaf of a serving process, and spends each keyset role once.
  `postgres.ContextKeyWrapGrantSQL` is the exact grant list of its login.
- **Real PostgreSQL.** [Result](../../test/results/adr176-sql-1/result.json):
  the authority runs under its own NOINHERIT login with exactly that grant
  list. The executor leaf wraps the data and manifest keysets. Denied are a
  repeated role, another certificate, an attempt that is not prepared, a
  non-collector role, and any wrap after the start object is bound. The
  ledger refuses a superuser pool. The test also had to issue the server
  leaf, because a connector process serves only with both leaves activated.
- **Key peers.** `mtls.ConnectorKeyPeerVerifier` maps a pinned connector's
  client leaf to role `collector`. `mtls.KeyPeerUnion` selects the verifier by
  URI form, with no fallback. `authapp.KeyOperationAuthorizers` dispatches
  authority by operation. All three have unit tests.
- **Region.** `regionalArtifactOutput` creates one `kms.RemoteSealer` per
  attempt, using the connector's own client leaf.
  `contracts.RegionalWrapService` is now an endpoint, roots and key ID.
- **Key service.** `asservat key-service` (`bootstrap.NewKeyService`)
  composes:
  - the protected local key source and ledger (ADR-067);
  - the wrap authority;
  - the peer union over key-client roots and pinned connector sources;
  - a TLS 1.3 server that requires client certificates.

  Input validation has a unit test. Download unwrap joins with the hub
  download composition.
