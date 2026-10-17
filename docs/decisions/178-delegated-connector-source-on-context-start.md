# ADR-178 — Delegated connector source on the context-start exchange

Date: 2026-10-14. Status: accepted; source frames implemented, tested over real TLS 1.3/h2 and passing the native public journey; hub-api composition, `native-read` grant and the `WorkerAPIs` fence pending.
Requirements: REQ-FED-001/003, S-02 regional context start; TASK-03 / TASK-11.

## Context

The hub-api context-start ingress (`mtls.ContextStartIngress`) checks a
connector peer in a fixed order: owner serving, the connector identity source,
the leaf against the source's issuer roots, the SQL49 activated-leaf registry,
the source again, and owner serving again. Each step narrows the result to at
most five seconds. The check runs at accept, at attach, at work send and at the
final result. The registry adapter reads the source twice more around its SQL
call.

The only production source reader in hub-api would be
`kube.ConnectorIdentitySource`, which calls the regional Kubernetes API.
[ADR-168](168-rotating-cluster-enrollment-credential.md) forbids that: the hub
"does not call that cluster's API", and tunnelling hub-side API requests
through the connector stream was also rejected. The registry function
`read_connector_activated_leaf` is granted only to the federation's
`connector-read` role. The hub replica's SQL budget is governed by
[ADR-177](177-hub-sql-connection-governor.md).

Options rejected:

- **The installed pin as the current source.** Hub-api would invent
  observation times for a ConfigMap it cannot observe, which
  [ADR-150](150-operation-owned-native-observation-proof.md) forbids. It would
  also stop noticing regional suspension or revision changes. The pin remains
  the expected profile.
- **Asking the federation.** The federation sees a fresh source only inside a
  conversation the region opens, so this still needs an in-band source. It
  only moves one SQL call, at the cost of a new internal RPC.
- **Moving ingress and standby into the federation.** The human request
  attaches to a standby on the same hub-api process that runs the hub runner
  with the human's identity.

## Decision

1. **Source probes on the exchange.** The context-start exchange carries
   numbered source probes. The hub sends a source request frame; the region
   answers with its current `ConnectorIdentitySource` observation, bound to
   the exchange channel and challenge. It answers only for its own verified
   channel, with one probe outstanding at a time.
   - Probes are allowed in standby, around work send and before the final
     result, never after the receipt.
   - Each check's probe count is fixed, and the whole-exchange frame budget
     grows by exactly that amount.
   - On the hub, `contextStartRemoteSource`, modelled on ADR-150's remote
     observation source, spends each probe before I/O, compares the first and
     last replies (`SameSource`, `Roles`) and only narrows deadlines.
2. **Cheap reads inside a bracket.** As in ADR-150, the region answers probes
   within an exchange-owned observation bracket. The expensive guard proof is
   taken once per bracket, within its original five-second interval, and each
   probe is a fresh source-value read. A captured value is never returned as a
   fresh read.
3. **Pinned expected profile.** The installer pins each connector peer's
   exact installed source document, ConfigMap UID, protection digest and
   executor in hub-api's native input. These are the same values the
   federation pins (`FederationDeployment.Peers`). Hub-api derives the expected
   profile with the shared decoder.
4. **Registry on hub-api's `native-read` login.** The activated-leaf registry
   runs on that login, which gains EXECUTE on
   `read_connector_activated_leaf(uuid,uuid,text,bytea,jsonb)` and SELECT on
   `fleet_current_trust`, verified by exact-ACL tests. SQL still checks
   fencing, recovery, retirement, detachment and the observation times against
   database time.
5. **Download-worker proofs (`WorkerAPIs`).**
   - **Now:** they are fenced to the hub's own cluster under the outbound-only
     profile. hub-api rejects worker API inputs for any other cluster.
   - **Migration (accepted direction, implemented later):** the connector,
     which already receives the worker's Pod token and checks it locally,
     runs the existing dispatched download-peer attester in its own cluster.
     It returns the resulting key-worker proof on the forwarded native
     exchange as delegated regional proof, bounded by the original deadlines,
     and the hub's SQL binder re-checks it after its locks.
   - **Forwarded native peer checks** (`CheckForwardedNative`) move from the
     legacy `fleet_peer` registry to the same SQL49 registry with the
     delegated source.
   - **Connector SQL reads:** the connector's remaining hub-SQL reads on the
     native path move to the hub and federation sides, following ADR-171/172.

## Consequences

The hub trusts the region's own source observations under the same delegated
proof model as [ADR-169](169-delegated-regional-lifecycle-channel.md). All
other checks stay independent and current: leaf verification, SQL
registration, fencing, recovery and the owner checks. Regional suspension or
revision changes are still observed at every check. Probe traffic shares the
connector's 20 QPS client with the
[ADR-173](173-work-scoped-process-observation.md) start path, so a native run
must count regional API calls per five-second window. Until the migration
lands, native downloads through regional workers stay unavailable under the
outbound-only profile.

## Implementation

1. **Frames.** Source request/response frames and DTOs. ADR-163 phase rules
   are extended to cover them.
2. **Hub ingress.** `contextStartRemoteSource`. Admissions hold the pinned
   profile, executor and registry; the source is bound per exchange. The
   accept-time check moves after the HTTP/2 stream opens so it can probe.
3. **Region.** Probe answering in `ServeRegionalOperations` and standby, with
   an exchange-owned bracket.
4. **Pinned peers.** Per-peer source pins in `contracts.OwnerNativeDeployment`.
   `nativeConfiguration` fills in `ContextStarts`.
5. **SQL.** The `native-read` grant addition and exact-ACL verification.
6. **Fence.** `WorkerAPIs` limited to the hub cluster.
7. **Qualification.** Real TLS/HTTP2 tests covering source change,
   suspension, revocation and fencing at each check, and a native run counting
   regional API calls per window.

## Implemented protocol

Implementation deviates from the bracket idea in decision 2. Each source frame
is a full regional source read, about 12 API calls.

- **Frames.** `APIContextSourceRequestFrame` (hub to region) and
  `APIContextSourceFrame` (region to hub). There are at most six source
  frames per exchange, and the frame budget grows by exactly that number.
- **Accept.** The region sends source 0 immediately after Hello. The hub reads
  it into a new per-exchange `SourceFeed` before authentication.
- **Attach and work send.** The hub's stream pulls a fresh source: it writes a
  numbered request and reads the reply before its peer check. The region
  answers while it is still passively waiting for work (`AwaitWork`). Pulling
  inside the stream avoids re-entering it from a check callback.
- **Result.** The region pushes one more source immediately before its
  result. The hub's `Receive` absorbs it before the final peer check. A source
  frame never reaches application code.
- **Feed rules.** The feed accepts only its own exchange, the expected
  sequence and no older observation. Readers apply `Valid` at their own time,
  so nothing is renewed.
- **Registry.** The ingress binds the SQL49 registry per exchange through
  `app.ConnectorObservationRegistry` and the installer-pinned profile.

Tests:

- `TestSourceFeedBindsExchangeSequenceAndOrder` and
  `TestReadSourceAfterHelloRequiresSourceFrame`.
- The mtls actual HTTP/2 context-start tests, which now run the whole source
  flow (accept, attach pull, work pull, pre-result push).
- The native transport tests, with their clients sending the source frame.

Native: [journey run 2](../../test/results/adr178-journey-2/result.json) passes
the whole public journey with the source frames (exit 0, empty cleanup,
unchanged sources). The first request took 3.48 s, against 4.285 s before; in
this fixture the hub no longer makes its own source reads.
[Run 1](../../test/results/adr178-journey-1/result.json) is retained. Its first
request also succeeded (3.48 s), but it then failed in the unchanged download
phase: a preparation continuation returned NotAvailable after two worker
openings admitted no native command. The rerun did not reproduce it, so it is
recorded as an intermittent download-phase failure to investigate separately.
