# Runtime walkthroughs and failure ownership

These walkthroughs are specification simulations, not executed integration tests. Component IDs resolve through the [catalog](catalog.yaml). They expose state ownership at the important boundaries; exact behavior still follows the linked specifications.

## R-01 — Manual collection and useful partial results

```mermaid
sequenceDiagram
  actor User
  participant UI as Browser or MCP / C-20
  participant Plan as Planning / C-06
  participant Cap as Capture / C-09
  participant DB as PostgreSQL facets
  participant Conn as Connector
  participant Node as Execution / C-11
  User->>UI: Preview selected profiles and whole-pod target
  UI->>Plan: Resolve current definitions, target, effects and bounds
  Plan-->>User: Stateless preview: resolved plan and digest; no acquisition
  User->>UI: Submit plan digest with idempotency key
  UI->>Cap: Authenticated command
  Cap->>DB: Accept scope, per-action state and audit row in one transaction
  DB-->>Cap: Operation/capture identity
  Cap-->>User: Accepted; independent actions and approval prerequisites
  Cap->>Conn: Push finite work on the connector connection
  Conn->>Node: Push work on the collector's stream
  Node->>Node: Verify Pod UID and execute once per operation ID
  Node-->>Conn: Result/commit references
  Conn-->>Cap: Idempotent progress keyed by operation ID
  Cap-->>User: Useful artifacts, gaps and pending/expired actions
```

C-09 allocates the capture identity before intrusive review and freezes the selected pod/node bindings. C-06 does not inspect processes or network traffic during preview; explicit discovery uses this same acquisition flow. Acceptance records pending review without holding expensive capacity indefinitely. Dispatch admission later reserves the required grant/resource facets close to start. C-03 accepts independently verified human approval for the exact action scope; context may already have completed.

A lost submit response is resolved with the original idempotency key. A submit whose plan digest no longer matches reports what changed and preserves permitted draft values. A response timeout never turns into a fresh capture. Cancellation blocks unstarted work; accepted committed artifacts stay under their existing audience/deadlines. If the dump cannot start before its original deadline, C-09 reports partial evidence rather than extending the request. See [execution](../../specs/execution.md).

## R-02 — Policy activation, trigger storm and source reuse

C-01 accepts policy/profile generations and executor provenance. C-06 compiles detector and source activation separately from the incident graph. C-10 resolves all authorized replicas under the administrator ceiling; C-07 independently reserves observation resources and smaller incident resources. C-12 arms each admitted source once and reports Warming/Ready/Degraded with actual coverage. Optional source failure cannot suppress independent useful context.

C-10 consumes bounded log/resource/probe/exit/alert signals, applies event/level/rearm/correlation rules, and coalesces repeated matches. An admitted occurrence selects contributing pods and allocates stable incident/action/snapshot identities. C-11 checks the policy's local permit and quota counters, pins the existing source window around original t0 and dispatches eligible onTrigger work. During a hub disconnection this local admission spends only the connector's local budget under unexpired permits; subsequent hub import uses the cluster occurrence identity and never repeats the effects.

If 1,000 matches arrive during cooldown, the suppression counter changes; there are not 1,000 core jobs or ring allocations. C-07 protects other workloads' allocations and prioritizes admitted snapshots over live readers. C-12 continues recording under its admitted source session while each admitted snapshot has a separately charged frozen/upload budget. Missing history is reported; post-window time is not shifted to when upload becomes available. See [triggers](../../specs/triggers.md), [capacity](../../specs/capacity.md) and [action lifecycles](../../specs/action-lifecycle.md).

## R-03 — Local start and ambiguous retry

```mermaid
sequenceDiagram
  participant N as Node executor
  participant C as Connector
  participant P as Target process
  N->>C: start(operation ID, scope)
  C->>C: Record operation ID; charge workload counter
  C-->>N: Start accepted for this operation ID
  N->>P: One intrusive start
  Note over N,C: Node crashes or start result is lost
  N->>C: start(same operation ID) after reconnect
  C-->>N: Existing outcome or Started-without-result; do not start again
```

Every effect carries an operation ID stored with it. A retry with the same ID returns the existing outcome; it never starts the effect again. An outcome left unknown by a crash is reported as Indeterminate for that operation and the charge is released once the node reports the outcome or the operation's deadline ends. An explicit new capture is a new user/policy decision with a new operation ID, subject to current budgets. No public phase enum is added.

C-11 owns local start records; C-07 owns the per-workload counters; C-09 owns hub attempt projections. Counters change with conditional updates on the affected workload row. Deadline expiry invalidates new starts but does not prove an old start was cancelled. Revocation and Stop reach a running collector as pushed events over its connection; during a hub disconnection a started source runs to its admitted hard end and a pending stop is delivered on reconnect.

## R-04 — Save existing recordings now

C-12 provides passive authorized source inventory; C-09/C-06 return a typed recording-save preview containing exact source epochs, original executor and current maintainer checks. On submit C-09 persists t0 once, reserves snapshot resources and optional independent per-save sharing. C-11 routes the `saveRecording` purpose only to C-12 SnapshotExecutor; it has no ActionAdapter invocation.

C-12 freezes the available intersection of requested lookback and source coverage, ending at original t0, under the source's existing age/audience. C-14 commits available output. A rotating, warming or stopped source may yield Partial. Retry uses the same snapshot/window; a later repeated request opens fresh selection. Policy recurring sharing is not inherited. Leaving a live view for Save does not pin the row being viewed. See [recording saves](../../specs/recording-saves.md).

## R-05 — Natural crash while remote services fail

Before readiness, C-11/C-14 prepare a finite pool of unique prewrapped encryption envelopes backed by unexpired policy permits and the connector's local budget. C-22 receives a kernel crash invocation, verifies the local socket peer and passes numeric identity to C-11. Local checks either consume a prepared single-use slot or refuse promptly. Accepted bytes are bounded and immediately encrypted into the admitted spool; remote upload can occur after process handoff ends.

A pool entry is single-use and cannot be restored after collector-state loss; a restarted collector prepares a new pool. If KMS, hub, DNS, S3 and Kubernetes are all down, no synchronous refill occurs on the crash path. Pool exhaustion rejects the stream; subsequent loss reporting is content-minimized and bounded. A crashArtifact signal references this already acquired core rather than acquiring it again. OOM/SIGKILL is not evidence of a core. See [natural-core architecture](../architecture.md#natural-core-readiness-without-remote-crash-path-waits).

## R-06 — Evidence commit and isolated analysis

```mermaid
sequenceDiagram
  participant E as Evidence / C-14
  participant L as Privacy copy ledger / C-15
  participant S as Regional object store
  participant A as Analysis coordinator / C-18
  participant J as Staged Jobs
  E->>L: Register pending copies and earliest deadlines
  E->>S: Encrypt/upload bounded objects and protected manifest
  E->>S: Regional reader verifies envelope, manifest and index
  E->>L: Publish in one transaction; settle charge to actual size
  E->>E: Artifact/lineage, audit row, NOTIFY
  A->>L: Register encrypted input/output scratch copies
  A->>J: Acquire exact inputs with scoped credentials
  J-->>A: Acquisition stopped and unmounted
  A->>J: Analyze offline with read-only inputs
  J-->>A: Analyzer stopped and unmounted; bounded outputs
  A->>J: Separate publisher validates and encrypts outputs
  J->>E: Commit child with trusted lineage and inherited deadlines
  A->>L: Schedule independent scratch cleanup
```

An uploaded object awaiting commit is an accounted pending copy, not catalog-visible evidence. Publication requires the reader's envelope, manifest and index verification; data frames are authenticated by AEAD on every read. SQL and object storage are not one transaction: an object without a published row is resolved by its operation ID or deleted. C-16 indexes only approved committed projections under current access and region rules.

A stuck analyzer, unconfirmed volume detach or malicious output tree prevents publication and remains in the copy ledger. C-18 may retry a qualified idempotent offline analysis under the same parent/deadline with a new fenced stage generation; it cannot repeat the original live collection. Raw query grants remain per-principal/purpose/limits. A completed Job does not grant access to raw bytes. See [evidence](../../specs/evidence.md) and [runtime profiles](../../specs/profiles.md).

## R-07 — Live view, slow reader and connection failover

C-13 inventories existing sources and opens an explicitly bounded view after maintainer/source-audience/current-executor checks. C-07 reserves independent projection/transfer/fanout resources. No source activation is part of this command. Node projection reads only approved fields and delivers bounded transient batches as a stream on the connector's hub connection; the browser receives them over one Server-Sent Events stream. The view is authorized once when opened and runs to its original bounds; Stop, revocation and expiry reach it as events.

A filter edit changes only the display revision and reports gaps as needed; it cannot widen acquisition. Pause stops row delivery. Managed rows expire even when paused. Slow readers consume their finite buffer budget, then receive a gap or disconnection; they never block acquisition or pin a raw ring. Protected incident saving sheds live work first.

Rows are never stored in SQL. If the hub replica holding the connection fails, the view either closes or resumes from the same authorized source head with an explicit replay gap. New source/pod requires a fresh request. An unauthorized region path or lost rights stops delivery and clears managed rows; copied external agent content is outside managed deletion. See [live watching](../../specs/live-watch.md).

## R-08 — Multiple owner teams and future sharing

C-17 accepts resolved manager/recipient identities and a concrete selection or explicitly bounded future instruction. The immutable creator remains distinct. Capture acceptance stores the share instruction with the capture. When C-14 publishes an artifact, the same transaction materializes only matching authorized projections after manager, parent, grant, lineage and deadline checks. Each share change writes its audit row in the same transaction.

Stopping future publication does not revoke existing concrete children. Revoking an instruction first commits parent denial, then cleans up dependent child shares. C-03 checks that parent when each dependent read operation is authorized, so delayed cleanup cannot preserve access through that path. An unrelated independent entitlement remains separately evaluated. Manager transfer cannot extend retention or turn ownership into raw access. See [sharing](../../specs/authorization.md).

## R-09 — Expiry, storage failure and fair capacity

C-15 computes read cutoff and deletion budget from original acquisition/parent time. Reads fail at cutoff even if deletion is unavailable. Local cleanup continues from stored deadlines through hub outages; C-15 coordinates objects, versions, multipart uploads, indexes, scratch and applicable backups. A successful deletion request is followed by backend-specific absence verification. C-07 releases the charge of each copy whose deletion is verified.

If one workload's object deletion is denied, report Overdue and block new admission into the affected backed allocation as specified. Other independently backed protected allocations remain available. If the backend failure cannot be isolated, widen the block truthfully. No automatic eviction of another workload's evidence. Storage locks and backup horizons conflicting with deadlines are readiness failures, not silent exceptions. See [privacy](../../specs/privacy.md).

## R-10 — Hub restore, configuration churn and upgrade

After a database restore, C-04/C-21 keep new effects disabled until the informers have resynced and every connector has compared its state digest and resent changes. Grants and shares that cannot be confirmed against current sources are invalidated. Outcomes recorded after the backup point are resolved through their operation IDs from the connectors' records, without redispatch. C-13 never resumes a restored live watch as if it were fresh. C-10 reports missing source/history after node loss.

A changed namespace UID or source definition cannot inherit its namesake's authority. During rolling N/N-1 upgrades, decoders ignore unknown fields, each connection's Hello carries the peer's capabilities and C-19 dispatches only work the peer supports; unsupported mechanisms remain unavailable while stored evidence is readable where dependencies permit. Database expansion/contraction and object format readers must cover the compatibility window before older writers are removed.

## Responsibility at failure boundaries

| Failure / ambiguity | Primary owner | Persistent residue / next action |
| --- | --- | --- |
| Lost submit/COMMIT response | C-09 / C-21 | Original operation uniqueness; lookup, never new request key |
| Audit row cannot be written | C-08 | Effect transaction rolls back; the operation fails |
| No local admission response | C-11 / C-07 | Look up the operation ID; charge released when the outcome is known |
| Lost target / PID reuse | C-05 / C-11 | LostTarget/partial; never substitute process or pod |
| Node/collector loss | C-11 / C-12 | Explicit coverage gap; unknown outcomes resolved by operation ID |
| Interrupted upload / KMS outage | C-14 / C-15 | Bounded encrypted pending copies, no plaintext fallback |
| Analyzer or volume handoff uncertainty | C-18 / C-15 | Fence stage, retain tracked volumes until safe cleanup |
| Slow/expired live client | C-13 | Bounded gaps/close; rows end at min(privacy deadline, watch deadline); no durable rows |
| Watch lost for identity / config source | C-03 / C-01 | Deny dependent starts/reads until the relist completes |
| SQL outage / restore | C-21 / C-04 | New effects disabled until reconciled; only the connector's local budget, unexpired local permits and cleanup |
| Deletion not verified | C-15 / C-07 | Denied reads, retained charge and explicit overdue remediation |

Runtime tests must exercise these boundaries with actual processes, storage and network failures. The architecture gate only checks documented contracts and synthetic state transitions.

## R-11 — Download and finish the investigation locally

A maintainer or authorized recipient selects an existing artifact. C-14 authorizes the download once through C-03, reuses a covering raw grant where needed, charges C-07 output counters and creates one ArtifactDownload with its audit row in the same transaction. C-19 sends the download as a stream on the regional connector connection to the long-running [regional reader](worker-startup.md), which decrypts the exact object and emits bounded native bytes through I-13. The started stream runs to its original bounds (ADR-312); Stop, revocation and retention cut-offs reach it as events. Disconnect produces Interrupted; a range retry keeps identity, version and deadline. The developer verifies the checksum and opens the file in their own tool; that local copy is outside C-15 managed deletion. A core may be downloaded with separately authorized exact companions; no current-image substitution.

## Combined review in the local-investigation flow

Before the native-download flow, a manual capture can ask for collection plus selected output access. One reviewer binds both scopes. The publication transaction of each verified commit creates an existing-artifact child for each explicitly approved client of the same human. The parent pool is shared across children. Artifact download/query resolves the child automatically and checks parent, artifact and entitlement. Parent revocation stops output even before child cleanup; capture budget exhaustion alone does not. Original expiry never moves. These are required fault cases, not a measured implementation.
