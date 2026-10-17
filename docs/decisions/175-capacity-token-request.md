# ADR-175 — Capacity account token by admitted, Pod-bound TokenRequest

Date: 2026-10-14. Status: accepted, amended after the first native run (Pod binding is impossible); implemented and natively qualified (installer RBAC and quota pending).
Requirements: REQ-EXE-002, S-02 regional context start; TASK-03 / TASK-11. Resolves the open question in [ADR-174](174-regional-context-start-composition.md).

## Context

A separate capacity ServiceAccount creates API context `CapacityReservation`
records and marks them Ready. The connector's own Pod-bound account only
consumes Ready starts, and native admission enforces the split
([local-start.md](../architecture/local-start.md), `StartAdmission`). A Pod
projects only its own account's token, so the connector process cannot
receive the capacity token as a projection.

The options considered:

- **(a) A long-lived ServiceAccount token Secret.** It never expires, is not
  Pod-bound and carries no `pod-uid`. That contradicts
  [ADR-094](094-native-hub-worker-projections.md) ("do not copy tokens into
  Secrets"), [ADR-141](141-protected-capacity-production.md) ("static
  remote service-account token files are not an installed solution") and
  specs/deployment-profiles.md (Pod-bound, bounded-lifetime API credentials).
  Kubernetes also no longer creates such Secrets automatically.
- **(b) A narrowly admitted TokenRequest** by the connector account for the
  capacity account.
- **(c) A separate regional capacity process** that accepts only hub-signed
  prepare/ready instructions.

Since [ADR-171](171-hub-run-context-execution.md) the hub's SQL binding of the
start object UID and recording of the consumed start are the authority.
Publication requires them. The connector already holds the observer token that
performs the Pod-status capture and answers every regional operation as
delegated proof, so the local record does not gate capture for the API class.
Option (c) would make local records authentic against a compromised executor.
It would need a new hub-signed instruction binding the full start binding,
`MayCreate` and the SQL-bound object UID: the current work JWS binds none of
these and is tied to the connector's channel. It would also need a second
Deployment, account, enrollment key, trust ConfigMap and guard.

## Decision

Option (b). The connector process mints the capacity account's token in memory
through TokenRequest. This is a regional-only, explicitly admitted exception to
ADR-094's "no token minting" for the hub-worker.

The first native run ([result](../../test/results/adr175-native-1/result.json))
showed that the token cannot be bound to the connector's Pod. The API server
rejects the request: "cannot bind token for serviceaccount "capacity" to pod
running with different serviceaccount name". The decision is therefore an
unbound token, admitted only when the requester is the execution Pod's own
Pod-bound credential.

1. **RBAC.** The connector account may `create` on `serviceaccounts/token`
   with `resourceNames: [<capacity account>]` only. The capacity account may
   `create`/`get` `capacityreservations` and `update`/`get`
   `capacityreservations/status` in the control namespace only. No Pod runs as
   the capacity account, and it has no automounted token.
2. **Admission.** The connector workload guard's API context branch admits
   exactly one shape of TokenRequest. It is a CREATE on `serviceaccounts/token`
   for the capacity account by the execution account (exact name and UID) with
   exactly one `authentication.kubernetes.io/pod-uid` extra, meaning a
   Pod-bound credential. The audience must be exactly the installer-pinned API
   audience, `expirationSeconds` must be 600, and there must be no
   `boundObjectRef`. Every other TokenRequest in the namespace stays denied, as
   before. The guard bytes change only when a capacity audience is pinned, so
   existing pins without one are unchanged.
3. **Process.** The token is requested with the connector's own client and
   kept only in memory. It is cached until 60 seconds before expiry, so no
   TokenRequest lands on the five-second start path
   ([ADR-173](173-work-scoped-process-observation.md)). It is never written to
   disk or logged.
4. **Requester check.** The token source refuses to start unless its own
   client is this Pod's Pod-bound execution credential (SelfSubjectReview
   `pod-uid`). `ConnectorAPIStartPreparer` keeps requiring the capacity
   account's exact identity.

## Consequences

One process holds both identities, as ADR-135's regional runner already did.
Admission still decides which identity may perform each start write. A
compromised connector can forge, mark Ready and consume local records. It
still cannot get evidence published without the hub's SQL binding, and the
hub's checks remain the backstop. A ResourceQuota on
`count/capacityreservations.asservat.io` bounds record flooding. A stolen
capacity token lives at most 600 seconds. Because it cannot be Pod-bound, it
also survives the Pod's deletion within those 600 seconds. Control over
admission remains a trust boundary.

If authentic local start records are later required against an executor
compromise, option (c) remains possible. It would need a new signed
prepare/ready instruction purpose.

## Verification plan

Native tests must cover:

- **Allowed:** the connector's Pod-bound credential mints the unbound
  600-second capacity token.
- **Denied:**
  - TokenRequests for another account;
  - bound TokenRequests (for example to a Secret);
  - expirations other than 600 seconds;
  - other audiences;
  - requests by a connector credential that is not Pod-bound.
- **Start path:** the minted token performs the CapacityReservation CREATE and
  Ready under both guards.
- **Quota:** the ResourceQuota limits record creation (installer step).

## Native result

[Run 4](../../test/results/adr175-native-4/result.json) passes all of
`TestConnectorAPIProcessWithRealKubernetes` (exit 0, empty cleanup, unchanged
sources):

- The connector's Pod-bound credential minted the unbound 600-second capacity
  token.
- That token performed the CapacityReservation CREATE and Ready under both
  guards.
- The ADR-173 start path took 2.57 s of 5 s.
- Denied: a 3600-second lifetime, another audience, a Secret binding, a
  connector requester that is not Pod-bound, and a token for another account.

Runs 1–3 are retained failures:

- **Run 1:** the API server refuses Pod binding for another account.
- **Run 2:** `!has(boundObjectRef)` failed.
- **Run 3:** the per-condition diagnostic on the real API server located the
  cause. An unbound request still reaches admission with `has(boundObjectRef)`
  true. The clause now accepts an absent or empty reference and rejects any
  named binding.
