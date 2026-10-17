# ADR-172 — Delegated owner discovery and authentication for regional exchanges

Date: 2026-10-14. Status: accepted; channel purposes, regional authenticator, pinned-endpoint client and federation owner-read composition implemented with component tests; native qualification pending.
Requirements: REQ-FED-001/003, S-02 regional context start; TASK-03 / TASK-11.

## Context

After [ADR-171](171-hub-run-context-execution.md), the regional process
performs no SQL effect, but its outbound clients still read hub SQL and the hub
cluster for two things:

- **Owner discovery.** `ReadContextStartOwners` returns the current complete
  owner candidate set, from SQL.
- **Owner authentication.** `OwnerAuthenticator` reads the owner registration
  in SQL (twice) and the owner pool's workload protection in the hub cluster
  (twice), and checks the current route against the owner configuration (SQL)
  and EndpointSlices (hub cluster).

The context-start client dials route-supplied owner Pod addresses with the
owner's exact server name. None of this is reachable outbound-only. Dropping
the checks and relying on the owner CA and the signed work alone was
rejected: it would remove the current registration, revocation and protection
checks on the hub peer.

## Decision

1. The federation channel ([ADR-169](169-delegated-regional-lifecycle-channel.md))
   gains two read-only purposes. Each is presented with the cluster credential
   for the presenting process:
   - `owner-candidates`: the hub returns its current context-start owner
     candidate set (the existing SQL read).
   - `owner-authentication`: the region sends the owner certificate it observed
     in an actual TLS session. The hub runs its own unchanged `OwnerAuthenticator`
     (registry, protection and route checks) and returns the authenticated facts
     and the first registration's configuration observation. The hub's own
     verify step can only require the certificate to be exactly that one.
2. The region completes authentication locally. It verifies the same TLS
   session against the returned configuration (`VerifyCurrentOwner`), requires
   the identical certificate, and bounds the result by the hub's `ValidUntil`.
   A federation answer alone never authenticates a TLS peer.
3. Dialing follows ADR-157 without widening the native listener. The region
   dials one installer-pinned hub endpoint with the exact SNI and HTTP
   authority of a current candidate owner. The native listener's exact-SNI rule
   stays unchanged: its common bootstrap name never widens context start or
   native transfer. With the first installed profile's single hub-api replica,
   the pinned Service endpoint always reaches that owner. With several
   replicas, an exact-name connection that reaches another Pod fails its
   handshake and is retried at the next poll. Deterministic multi-replica
   routing (an SNI-routing edge, or a separately reviewed context-start-only
   common-name exception) remains open.
4. The federation process gains the hub's owner reads: one more fixed role
   with the owner registry/configuration read grants, and read-only access to
   the owner namespace's EndpointSlices and workload guard. It still holds no
   owner signing, audit or activation authority.

## Consequences

Regional context start, ADR-150 observation and later native transfer can share
one owner discovery/authentication port without hub SQL. Each authentication
costs one federation conversation; the existing five-second bounds and finite
standby budgets apply unchanged. A region trusts the hub's federation answers
under the same credential model as ADR-169. Combining the federation answer
with the region's own TLS verification keeps an answer without that session
from authenticating anything.

## Implementation

- `connectorlifecycle`: the `owner-candidates` and `owner-authentication`
  purposes, opening validation (a server-usage certificate of the presenting
  installation, only on the authentication purpose), and an answer only for
  the observed certificate. `Runners` runs the hub's unchanged `OwnerAuthenticator`
  through a presented-certificate connection that records the configuration.
- `bootstrap.RegionalLifecycle`: `ReadContextStartOwners` and
  `AuthenticateOwner`, presented by the admitted process. Authentication
  completes only when this side's own session verifies against the returned
  configuration and yields the identical certificate.
- `mtls.NewRegionalContextStartClient`: dials one pinned host:port with each
  owner's exact SNI and authority. It reads no route and authenticates through
  an `OwnerPeerAuthenticator`.

Component tests pass:
- The channel's owner purposes, including refusal of an answer for another
  owner and of malformed openings.
- `TestRegionalLifecycleOwnerReadsRequireLocalSessionVerification`.
- `TestContextStartRegionalClientDialsPinnedEndpointWithExactName` over real
  TLS 1.3/h2.

Federation composition:
- SQL: `connector-owner-read`, permanent public runtime ordinal 56 in the
  federation compartment (connection limit three). Its grants are exactly the
  hub-api owner `registry` grants: SELECT on the owner configuration,
  enrollment and certificate tables plus the row-lock columns. No owner write.
  The role inventory is now 42; the connection plan grows to 65 for one hub
  and 161 for four retained hub processes.
- Input: `FederationDeployment.Owner` is a `contracts.OwnerGuardInputs`. The
  installer copies it from the hub-api input with `OwnerDeployment.Guard()`, so
  both prove the same guard plan and protection digest. A reflection test pins
  that `Guard()` carries every guard field. Without it, the owner purposes stay
  refused and the role's credential file is not read.
- Kubernetes: projected `kube-observer.token` and `kube-probe.token` for an
  account with the owner namespace's EndpointSlice list, Deployment and
  ReplicaSet reads, namespace and guard policy/binding reads, and the
  guard-denied dry-run Deployment update the probe needs. Validation and guard
  construction are shared with hub-api (`validOwnerGuard`,
  `ownerWorkloadGuard`).

Real PostgreSQL: the initial-installation suite provisioned all 42 public
runtime roles through the product role producer with exact ACL verification
([result](../../test/results/adr172-roles-1/result.json): exit 0, 87 tests,
empty cleanup, unchanged sources).

## Remaining

The installer's federation owner projection and RBAC, the product regional
composition that uses these purposes, and native qualification.
