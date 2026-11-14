# Internal interfaces

Public browser/MCP operations and schemas are in the [interface package](../interfaces/README.md). The internal ports below implement them. Interface IDs, callers and providers are recorded in the [catalog](catalog.yaml); none is a user permission API. Mechanisms follow [ADR-330](../decisions/330-event-driven-system-design.md).

## Common contract rules

Internal control uses versioned strict JSON over authenticated TLS connections (ServiceAccount token on the connector connection, ADR-334; mutual TLS between hub replicas and inside a cluster). Enforce wire limits before decoding; reject duplicate keys, nonfinite numbers, malformed UTF-8, unknown fields and ambiguous normalization. Never put an arbitrary callback, object URL, shell command or evidence row in a control message. Protected references resolve only inside a configured pool and authorized region; they are not bearer capabilities.

The [internal-work/v1 schema](../../specs/contracts/internal-work.schema.json) defines disjoint purposes and their receipts. `operationId` is the idempotency key of the parent operation; action `attemptId`, recording `snapshotId` and analysis `stageGeneration` identify effects independently of delivery. `scopeDigest` binds the accepted scope and `notAfter` caps a new start. The hub authorized the operation once at admission and recorded its charge and audit row in SQL under that ID; the receiver deduplicates by ID and never treats a reference's presence as authority. No generic "execute this payload" handler exists. Work messages are not signed: the mutually authenticated connection identifies the sender (D2).

| Purpose | Payload | Required receiver behavior |
| --- | --- | --- |
| armSource | Source session, activation and action IDs | Verify ongoing mode, observation approval/resources and target before attaching. A duplicate cannot create another source. |
| runAction | Capture/action/attempt IDs | Resolve the frozen `onTrigger` plan and consume its [start row](local-start.md); no action/argv override. |
| saveRecording | Capture/snapshot/source, immutable end time, bounded lookback, policy execution digest | Verify the recording-save scope, source rights and reviewed enablement. Dispatch only SnapshotExecutor. The lookback is bounded by the source ring's actual coverage. |
| analysisStage | Analysis ID, stage, generation, input ref, output slot | Only the connector schedules the matching reviewed Job template. |
| eraseCopy | Copy identity/generation and deletion-work ID | Check cleanup authority and the copy ledger. Expired acquisition grants never block required deletion. |
| downloadArtifact | Download/artifact/digest | Stream the artifact through a regional reader replica; no analysis, new acquisition or arbitrary destination. |
| projectLive | Watch/source, approved projection, view revision | Verify the live-purpose authorization and view budget. Never arm a source or borrow capture authority. |

Receipts bind work, operation and a monotonically increasing sequence. `Completed` means the work stopped; its result distinguishes success, partial, cancelled and failure. A receipt is not proof of artifact commit or deletion. A stale receipt never overwrites a newer state.

## Network contracts

### I-01 — Hub federation

Each connector holds one outbound, multiplexed HTTP/2 connection to the hub's one HTTPS endpoint, through any Ingress or Gateway including one that terminates TLS (D2, ADR-334). Commands, receipts, cluster-state pushes, live rows and download bytes are separate streams on it, with per-stream flow control so bulk bytes cannot starve control. The connector authenticates with a projected ServiceAccount token of its cluster, verified against the issuer registered in the hub's `clusters` values ([connector identity](connector-credentials.md)). The hub routes to the replica holding a connector's connection through one SQL row naming that replica. Routes under `/internal/v1/federation/` are internal protocol, not public OpenAPI.

Negotiation binds peer build identity, protocol major/minor, supported action/projection schema versions and maximum byte/item limits. Hub and connector support N/N-1 minors of one major; required capabilities fail explicitly and no downgrade omits a limit.

Work is pushed: a hub transaction that makes work eligible issues `NOTIFY`, and the replica holding the connection sends it on the command stream. Work moves `Queued → Sent → Running` and then to a terminal state; `Sent` records the connection epoch. After a reconnect the hub resends every non-terminal item and the connector returns the existing state for a known `workID`. Commands carry no signatures. A command or control frame is at most 64 KiB, which holds the largest typed command payload (a 4096-instruction classic-BPF program of 32 KiB) plus envelope; download and live data frames are at most 1 MiB, the memory one in-flight frame costs. A receipt batch fills at most one control frame; further receipts go in further frames.

Cluster state (namespaces, workloads, Pods, EndpointSlices, AccessBindings, permission sources) is pushed when it changes. After a reconnect the connector compares a digest and resends only on mismatch. HTTP/2 PING frames detect a dead connection; there is no separate heartbeat request.

Delivery is at least once. The connector acknowledges Accepted only after its durable local state exists; a lost acknowledgement causes redelivery of the same ID. Error vocabulary: UnsupportedVersion/Capability, Denied, Expired, Conflict, CapacityUnavailable, DependencyUnavailable, Indeterminate.

### I-02 — Node control

Each collector holds one server-TLS connection to its regional connector, with the same work/receipt message family. The collector authenticates once per connection with its audience-bound projected ServiceAccount token, checked by TokenReview; there is no node certificate or CSR ([node collector](node-collector.md), D3). Node identity comes from the reviewed Pod's node, never from a request field. A collector credential cannot receive another node's work or resolve another source's references. One collector process per node; a replacement process's new connection supersedes the old one.

Work kinds include `armSource`, `stopSource`, `snapshot`, `peerGeneration` and `packetCapture`. Start consumption goes through the [start row](local-start.md). Typed ports `lookup-start`, `checkpoint-source` and `report-usage` accept no CRD YAML or SQL.

Node status is sent as a delta when a source, ring or accounting state changes. Live-viewing counters (active cohorts, buffered rows, scan and delivery totals, refused admissions, source-loss and dropped-row counts) are cumulative and included in those deltas; they carry no source, filter or payload labels. C-19 aggregates node totals per cluster for fleet status. A first report or nonmonotonic counter marks rates incomplete.

A started source runs to its admitted hard end while the connector is disconnected; a pending stop is delivered on reconnect. While disconnected, natural cores (I-03) and policy-triggered starts spend only the connector's local budget under unexpired local policy permits; other new intrusive starts need their hub `capture_start` row and wait for the connection. Multi-node admission may produce partial outcomes; it is not atomic across nodes.

### I-03 — Host core handoff

Use an installation-owned Unix-domain stream socket with restricted ownership/mode and peer credentials. The helper verifies the collector peer; the collector verifies the helper and resolves the kernel-provided process identifiers itself. No caller-supplied executable path or argument becomes authority.

A fixed-version header of at most 4 KiB (one page, a fixed allocation while the crashed process is held) carries numeric IDs, process start identity when available and a nonce. The node refuses promptly or returns an acceptance tied to one prepared envelope, a local-budget allocation and a byte/time limit. Only then consume bytes, with bounded backpressure and a hard close deadline. No remote call occurs while the crashed process is held. The encrypted spool has its own budget. Exact Linux header/pidfd behavior is a required native-core spike; socket credentials alone do not solve PID reuse.

### I-04 — Gadget observation

The C-23 adapter drives pinned approved gadget definitions through the engine linked into the collector process ([ADR-246](../decisions/246-node-collector-role.md)). Its port is `Attach(VerifiedSource, Limits) → Session`, bounded event reads, atomic membership-generation replacement and `Stop`. No user gadget registry, script, path or BPF program is accepted. It reports attach/restart/map-overflow/filter-update and entry/exit-pairing gaps.

### I-07 and I-12 — Live delivery and ingress routing

SQL stores a LiveWatch's control state (filter, view revision, last activity) and delivered bytes; open and close each write one audit row. Live views have one rate limit (delivery per watch) and one concurrency limit (node projection headroom) ([REQ-LIV-004](../../specs/live-watch.md#req-liv-004--protect-collection-and-workload-resources)). Row content never enters SQL or audit ([ADR-310](../decisions/310-finite-approved-live-observation.md)).

Live rows arrive on the connector's live stream (I-01) at the A-HAPI replica holding the connection. Any A-HAPI replica accepts the viewer's request; if another replica holds the connection, the viewer's replica opens the row stream from it over hub mTLS, found through the connection's SQL row (I-12). There is no separate projection owner. The browser receives rows over one Server-Sent Events stream per page; MCP waits server-side up to 30 seconds (ADR-330 D1) and returns on the first batch. The viewer is authorized once per operation (D5). Rows carry their original observation/expiry/coverage metadata; there is no durable replay, SQL row per event or outbox body. Bounded queues drop with a recorded gap or close; a slow viewer never backs up acquisition. If the connection moves to another replica, the stream reports a gap and resumes from the current source head. A view that would violate region policy is rejected.

## In-process and staged contracts

### I-05 — Evidence commit and copy ledger

C-14 registers pending copies with C-15 before writing: store/version, class, source times, parent lineage, charge, read cutoff and deletion deadline. The writer compresses when useful, encrypts with unique material and sends each object's SHA-256 to the store. Finalization records the copies; [manifest verification](manifest-verification.md) and [publication](context-publication.md) commit the artifact. C-16 and C-17 consume commit references, never an upload-complete callback. Original and derived copies share one privacy ledger; deletion and indexes cannot extend their age. [Custody](custody-transactions.md) defines registration, receipts and deletion.

### I-06 — Analysis handoff

C-18 owns one stage-generation state machine. C-15 registers input/output volumes before use. Acquisition writes inputs and exits; the analyzer mounts input read-only and output under its bounded policy with no network. After the analyzer Job completes, a separate publisher walks outputs with confined paths, no-follow/type/size/count rules and trusted manifest fields. The controller watches the Job and starts the next stage only on its terminal condition. No shared emptyDir, executable input script, plaintext fallback PVC or user-supplied Job spec.

### I-08 — Configuration projection

C-01 consumes Kubernetes objects through shared informers and keeps each object's resourceVersion. The cache stays valid until a watch event replaces it; a watch failure marks it unavailable until the relist completes. Remote clusters push the same objects through I-01. Permission writes use Kubernetes RBAC; previews never become an alternate configuration store.

The [identity/eligibility facet](identity-eligibility.md) defines `TokenVerifier`, `PolicyReader`, `ProjectionReader` and `AudienceReader`. The eligibility result names the contributing bindings and sources for one caller; it is not an execution permit or the audience to persist. Ordinary scope checks precede artifact lookup. The [permission observation](permission-observation.md) facet supplies bindings, denies and namespace metadata from the informer cache.

### I-09 — Transactional facets

Application services call named transactions such as AdmitCapture, PublishSelection, RegisterCopy or ExpireScope. Each receives the operation ID and expected versions. Counters change with conditional updates on the affected workload row (plus one pool row only when burst limits apply); there is no installation-wide lock. The database incarnation is compared, not locked. The pure database callback may be retried on serialization failure, never process actions or remote I/O. An unknown commit is resolved by looking up the operation ID. Each security-relevant transaction inserts its audit row (D6).

[Context admission](context-admission.md) atomically checks authorization, charges workload storage, reserves the four objects and saves the manifest expectation.

### I-10 — Collector adapters

The consumer-owned Go ports below describe responsibilities. Every method receives a framework-constructed verified scope, finite limits and cancellation context, never just a Pod name or argv. A port is not a plugin ABI or network endpoint.

```go
// Illustrative interfaces.
type ActionAdapter interface {
    Describe() MechanismDescriptor
    Acquire(context.Context, VerifiedAction, BoundedEvidenceWriter) (ActionOutcome, error)
}
type RecordingAdapter interface {
    Arm(context.Context, VerifiedSource) (SourceHandle, error)
    Snapshot(context.Context, VerifiedSnapshot, BoundedEvidenceWriter) (Coverage, error)
    Stop(context.Context, VerifiedStop) (StopOutcome, error)
}
type LiveProjectionAdapter interface {
    Read(context.Context, VerifiedLiveRead) (BoundedLiveBatch, error)
}
```

Descriptors include mechanism/schema/projection versions, supported action kinds/modes, kernel/runtime/privilege prerequisites, qualification reference, data classification and impact rule, budget dimensions, readiness and cancellation/loss behavior. Describe never attaches, samples or reads user data. Snapshot-only dispatch depends on the snapshot port, not ActionAdapter, so it has no callable dump path. The producer runs its type's structural check before encryption ([manifest verification](manifest-verification.md)).

### I-11 — Analyzer adapters

`Analyze(context, VerifiedInputs, TypedQuery, BoundedOutputTree) → AnalysisOutcome` runs only in the offline role. Descriptors pin tool/image/runtime pack, input kind/sample units, supported approved/raw queries, required private symbols and output classification. No network fallback, shell interpolation, target code execution or arbitrary debugger commands. Stdout/stderr are bounded and treated as potentially sensitive evidence. Publisher validation ignores an analyzer's self-reported paths, class or retention. Missing symbols or incompatible profiles produce explicit unavailable/partial results.

### I-13 — Native artifact byte relay

Downloads and stored-evidence queries are served by the long-running regional reader Deployment (D4). The hub replica serving the browser GET authorizes once (D5), writes the audit row and sends `downloadArtifact` on the connector's command stream; a reader replica streams the decrypted range back on a byte stream of the same connection to that replica ([REQ-DLD-003](../../specs/artifact-downloads.md)). The started response runs to its original bounds ([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)); Stop and retention cut-offs arrive as events. Bytes are never stored in SQL, the outbox or a durable queue, and there is no storage redirect or plaintext disk cache. Range bytes use their own streams, separate from live rows and control. A hop that violates region policy blocks the transfer.

[Context projection](context-projection.md) queries use the same readers with their own approved DTO and admission; a download is never implicitly query-capable.

### I-14 — Private local key operations

[Local key service](local-key-service.md): the optional A-KEY mTLS wrap/unwrap boundary ([ADR-065](../decisions/065-local-key-service-boundary.md)). Unwrap is authorized by the caller's mTLS role (`download-reader`, the A-READ regional reader) and the AEAD binding of the wrapped keyset; there is no hub ticket or per-call SQL lookup. It carries key material, never artifact payloads.
