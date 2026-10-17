# ADR-181 — Asynchronous publication in a dedicated verifier process

Date: 2026-10-15. Status: accepted; authority, queue, roles and the `asservat publisher` process implemented; authority and roles pass on real PostgreSQL; installer producer and native end-to-end qualification pending.
Requirements: S-02, REQ-DEP-003, REQ-FED-002; TASK-03 / TASK-07 / TASK-11.
Amends [ADR-177](177-hub-sql-connection-governor.md) decision 4 ("publication
stays in the request path").

## Context

A stored context artifact becomes visible only through `ContextPublisher`
([context-publication.md](../architecture/context-publication.md)). The
publisher fully decrypts and verifies the manifest, index and native object
against the accepted expectation and the original ciphertext receipts.

Decryption needs the three keyset unwraps. There are three possible places,
and none of them fits:

- [ADR-176](176-artifact-keys-local-key-service.md) keeps unwrap out of
  hub-api.
- The key service holds the root keys and no evidence-store credential.
  Giving it store reads would turn one compromise into plaintext disclosure
  of all evidence.
- The region produced the artifact, so it cannot be its independent verifier.

No product component runs the publisher today. The native journey calls it
from the test.

## Decision

1. **A dedicated publisher process.** `asservat publisher` is a hub-cluster
   Deployment.
   - It owns the four publication SQL purposes: publication gate, context
     verify, verification audit and publish. These purposes leave the hub-api
     compartment.
   - It holds a read-only evidence-store credential and a key-client
     certificate with role `verifier`.
   - It does no collection and serves no public route.
2. **Asynchronous.** The request path still returns `StoredPendingVerification`.
   - The publisher polls a bounded SQL queue: stored API context executions
     whose capture has no catalog entry.
   - It publishes each through the unchanged `ContextPublisher`.
   - Progress and cases show the published case once it exists.
   - A crash or lost reply replays the same capture and immutable copies; it
     never recollects.
3. **Verification unwrap authority.** A new SQL authorizer,
   `ContextKeyUnwraps`, grants artifact `unwrap` to a `verifier` peer only
   when all of the following hold:
   - the authority ID is the attempt of a stored execution;
   - its capture is not yet published;
   - the request's key binding is exactly
     `ArtifactKeyBinding(expectation.Binding(), role)` for one of the three
     keyset roles;
   - a monotonic per-attempt counter stays within a fixed allowance. The
     allowance is three roles times four verification attempts.

   Each permit lasts at most five seconds. Spend is never refunded. A published
   capture gets no further verification unwrap. Download unwraps keep their
   own native authority.
4. **Key-service dispatch by operation and peer role.** `wrap` goes to the
   collector authority. `unwrap` goes to the verifier authority for role
   `verifier`, and to the download authority for acquisition workers.

## Consequences

- **What a compromise yields.** A compromised publisher can decrypt only
  artifacts that are stored and not yet published, within the allowance. A
  compromised hub-api still has no unwrap. A compromised key service still
  has no ciphertext.
- **Visibility delay.** Publication now lags the request by at most the
  queue's poll interval plus verification time.
- **Installer.** It provisions the publisher's SQL roles, its read-only store
  credential and its key-client certificate.

## Implementation

1. **SQL.** Migration 63 adds `context_key_unwrap`, with the attempt, root,
   peer certificate digest and a monotonic unwrap counter. Two queries follow:
   the verification authorizer's reads, and the bounded publication queue.
2. **Authorizer.** `postgres.ContextKeyUnwraps` and its exact grant list.
3. **Key service.** Operation and role dispatch, and the `verifier` key peer.
4. **Process.**
   - `bootstrap.RunPublisher`, built from its protected inputs:
     - governed pools;
     - the gate, facets and verification audit;
     - `objectstore.NewContextVerifier` over a read-only custody store;
     - one `kms.RemoteOpener` per attempt.
   - The command `asservat publisher`.
5. **Roles.** The publication purposes move to a publisher compartment.

## Progress

- **Migration 63 (`context_key_unwrap`).** Unwraps only ever increment, are
  bounded at twelve and are never deleted. `postgres.ContextKeyUnwraps` and
  `ContextKeyUnwrapGrantSQL` implement the authority; `ContextPublicationQueue`
  lists stored, unpublished captures with their attempt and copies.
- **Real PostgreSQL**
  ([result](../../test/results/adr181-sql-2/result.json)). The authority and
  queue run under narrow logins with their exact product grants. The checks
  cover:
  - the queue listing;
  - the verifier unwrap;
  - refusal of the acquisition role and of an unknown attempt;
  - the allowance shared across two certificates, with unwrap 13 refused;
  - removal from the queue and refusal of unwraps after publication.

  [Run 1](../../test/results/adr181-sql-1/result.json) failed on a test
  fixture whose key peer spanned 61 minutes; key peers are limited to one
  hour.
- **Roles.**
  - The four publication purposes left the hub projection, which now has 46
    purposes. They form the publisher compartment together with
    `publisher-identity-read` (65) and `publisher-retention-read` (66).
  - `context-verify` gained `SELECT(capture_id)` on `context_catalog` for the
    queue.
  - The [initial-installation suite](../../test/results/adr181-roles-1/result.json)
    provisions and verifies all 66 roles: exit 0, 87 tests.
- **Key service.** `authapp.KeyOperationAuthorizers` dispatches `operation/role`
  before `operation`. The key service composes `unwrap/verifier` over its own
  `key-verify` login. The domain admits role `verifier` for artifact unwrap.
- **Process.** `asservat publisher` (`bootstrap.RunPublisher`) consists of:
  - a closed `PublisherDeployment`;
  - publisher-manifest-verified pools;
  - the gate over hub-held retention topologies;
  - the three facets;
  - verification audit on the owner audit store;
  - a read-only custody store, and one remote opener per attempt that
    presents the rotating verifier certificate.

  A unit test covers its inputs.
