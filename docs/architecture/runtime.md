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
  participant Audit as Audit / C-08
  participant Conn as Connector
  participant Node as Execution / C-11
  User->>UI: Preview selected profiles and whole-pod target
  UI->>Plan: Resolve current definitions, target, effects and bounds
  Plan-->>User: Expiring preview; no acquisition
  User->>UI: Submit preview with original idempotency key
  UI->>Cap: Authenticated command
  Cap->>DB: Accept immutable scope and per-action state
  DB-->>Cap: Operation/capture identity
  Cap-->>User: Accepted; independent actions and approval prerequisites
  Cap->>Audit: Durable dispatch intent for admitted work
  Audit-->>Cap: Object acknowledgement
  Conn->>Cap: Poll compatible eligible work
  Cap-->>Conn: Signed finite work
  Node->>Conn: Poll and reserve exact local start
  Conn-->>Node: Durable bounded ticket
  Node->>Node: Recheck target and execute once
  Node-->>Conn: Protected result/commit references
  Conn-->>Cap: Idempotent progress and receipts
  Cap-->>User: Useful artifacts, gaps and pending/expired actions
```

C-09 allocates the capture identity before intrusive review and freezes the selected pod/node/boot bindings. C-06 does not inspect processes or network traffic during preview; explicit discovery uses this same acquisition flow. Acceptance records pending review without holding expensive capacity indefinitely. Dispatch admission later reserves the required grant/resource facets close to start. C-03 accepts independently verified human approval for the exact action scope; context may already have completed.

A lost submit response is resolved with the original idempotency key. A stale preview returns an actionable re-preview while preserving permitted draft values. A response timeout never turns into a fresh capture. Cancellation blocks unstarted work; accepted committed artifacts stay under their existing audience/deadlines. If the dump cannot start before its original deadline, C-09 reports partial evidence rather than extending the request. See [execution](../../specs/execution.md).

## R-02 — Policy activation, trigger storm and source reuse

C-01 accepts policy/profile generations and executor provenance. C-06 compiles detector and source activation separately from the incident graph. C-10 resolves all authorized replicas under the administrator ceiling; C-07 independently reserves observation resources and smaller incident resources. C-12 arms each admitted source once and reports Warming/Ready/Degraded with actual coverage. Optional source failure cannot suppress independent useful context.

C-10 consumes bounded log/resource/probe/exit/alert signals, applies event/level/rearm/correlation rules, and coalesces repeated matches. An admitted occurrence selects contributing pods and allocates stable incident/action/snapshot identities. C-11 checks the prepaid local authority/accounting bundle, pins the existing source window around original t0 and dispatches eligible onTrigger work. Policy permits allow this local admission during bounded hub disconnection; subsequent hub import uses the cluster occurrence identity and never repeats the effects.

If 1,000 matches arrive during cooldown, the suppression counter changes; there are not 1,000 core jobs or ring allocations. C-07 protects other workloads' allocations and prioritizes admitted snapshots over live readers. C-12 continues recording under its own lease while each admitted snapshot has a separately charged frozen/upload budget. Missing history is reported; post-window time is not shifted to when upload becomes available. See [triggers](../../specs/triggers.md), [capacity](../../specs/capacity.md) and [action lifecycles](../../specs/action-lifecycle.md).

## R-03 — Local start and ambiguous retry

```mermaid
sequenceDiagram
  participant N as Node executor
  participant C as Connector / local journal
  participant K as Local Kubernetes CAS
  participant P as Target process
  N->>C: reserve-start(attempt, scope, boot, prepaid bundle)
  C->>K: CAS unspent local reservation to StartCommitted
  K-->>C: Durable revision
  C-->>N: Ticket for the same exact attempt
  N->>N: Validate ticket, exclusive collector generation and process identity
  N->>P: One intrusive start
  Note over N,C: Node crashes or start result is lost
  C->>K: Mark uncertainty; keep charge
  N->>C: lookup-start(same attempt) after reconnect
  C-->>N: Existing StartCommitted / Indeterminate; do not start again
```

`StartCommitted` is an internal journal disposition: the right to attempt that effect is consumed before the effect. A crash between the durable write and actual process start may lose an acquisition; correctness prefers that loss to an unproven second start. Public state remains Running/Indeterminate as appropriate; this does not add a public phase enum. An explicit new capture is a new user/policy decision subject to current budgets.

C-11 owns local start transitions; C-07 owns the prepaid resource bundle; C-09 owns hub attempt projections. Grant and capacity reservations may span multiple local records. CAS the designated bundle/start record only after all needed reservations are durably held. Abandoned intermediate reservations are reconciled conservatively; never claim multi-object atomicity. Deadline expiry invalidates new starts but does not prove an old start was cancelled.

Collector generations require local process exclusion and receiver-side checks. A node-side lock/lease loss must stop new effects; an old process still possibly running blocks a new incompatible start until exclusion or the remaining authority window is established. A delivery or controller leader fence alone cannot stop a paused process. Partition/duplicate collector qualification must demonstrate this. Revocation remains bounded by the existing disconnected permit expiry, not instant global revocation.

## R-04 — Save existing recordings now

C-12 provides passive authorized source inventory; C-09/C-06 return a typed recording-save preview containing exact source epochs, original executor and current maintainer checks. On submit C-09 persists t0 once, reserves snapshot resources and optional independent per-save sharing. C-11 routes the signed `saveRecording` purpose only to C-12 SnapshotExecutor; it has no ActionAdapter invocation.

C-12 freezes the available intersection of requested lookback and source coverage, ending at original t0, under the source's existing age/audience. C-14 commits available output. A rotating, warming or stopped source may yield Partial. Retry uses the same snapshot/window; a later repeated request opens fresh selection. Policy recurring sharing is not inherited. Leaving a live view for Save does not pin the row being viewed. See [recording saves](../../specs/recording-saves.md).

## R-05 — Natural crash while remote services fail

Before readiness, C-11/C-14 prepare a finite pool of unique prewrapped encryption envelopes backed by durable audited policy authority and C-07 prepaid starts/storage. C-22 receives a kernel crash invocation, verifies the local socket peer and passes numeric identity to C-11. Local checks either consume a prepared single-use slot or refuse promptly. Accepted bytes are bounded and immediately encrypted into the admitted spool; remote upload can occur after process handoff ends.

A pool entry cannot be restored and reused after collector-state loss. A new collector epoch invalidates the old pool and treats unproved consumption conservatively. If KMS, hub, DNS, S3 and Kubernetes are all down, no synchronous refill occurs on the crash path. Pool exhaustion rejects the stream; subsequent loss reporting is content-minimized and bounded. A crashArtifact signal references this already acquired core rather than acquiring it again. OOM/SIGKILL is not evidence of a core. See [natural-core architecture](../architecture.md#natural-core-readiness-without-remote-crash-path-waits).

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
  E->>S: Verify committed identities and integrity
  E->>L: Reconcile actual copies/charges
  E->>E: Finalize artifact/lineage and publication eligibility
  A->>L: Register encrypted input/output scratch copies
  A->>J: Acquire exact inputs with scoped credentials
  J-->>A: Acquisition stopped and unmounted
  A->>J: Analyze offline with read-only inputs
  J-->>A: Analyzer stopped and unmounted; bounded outputs
  A->>J: Separate publisher validates and encrypts outputs
  J->>E: Commit child with trusted lineage and inherited deadlines
  A->>L: Schedule independent scratch cleanup
```

An uploaded object awaiting commit is an accounted pending copy, not catalog-visible evidence. C-14 verifies object/manifest identity before final publication. SQL and object storage are reconciled state machines, not one transaction. C-16 indexes only approved committed projections under current access and region rules.

A stuck analyzer, uncertain volume detach or malicious output tree prevents publication and remains in the copy ledger. C-18 may retry a qualified idempotent offline analysis under the same parent/deadline with a new fenced stage generation; it cannot repeat the original live collection. Raw query grants remain per-principal/purpose/limits. A completed Job does not grant access to raw bytes. See [evidence](../../specs/evidence.md) and [runtime profiles](../../specs/profiles.md).

## R-07 — Live view, slow reader and owner failover

C-13 inventories existing sources and opens an explicitly bounded view after maintainer/source-audience/current-executor checks. C-07 reserves independent projection/transfer/fanout resources. C-19 assigns an owner lease/fence; no source activation is part of this command. Node projection reads only approved fields and delivers bounded transient batches through the connector's outbound hub connection. C-20 routes browser/MCP requests to that owner; C-13 checks authority/deadlines again before disclosure.

A filter edit changes only the display revision and reports gaps as needed; it cannot widen acquisition. Pause stops row delivery while finite status checks preserve current eligibility. Managed rows expire even when paused. Slow readers consume their finite buffer budget, then receive a gap or disconnection; they never block acquisition or pin a raw ring. Protected incident saving sheds live work first.

Owner failover cannot recover rows from SQL. Either close the watch or resume from the same authorized source head with an explicit replay gap and conservative remaining spend. A stale owner cannot deliver after its fence expires/takeover becomes authoritative. New source/pod requires a fresh request. An unauthorized region path or lost rights stops delivery and clears managed rows; copied external agent content is outside managed deletion. See [live watching](../../specs/live-watch.md).

## R-08 — Multiple owner teams and future sharing

C-17 accepts resolved manager/recipient identities and a concrete selection or explicitly bounded future instruction. The immutable creator remains distinct. Capture acceptance registers a finite publication slot when sharing can be authorized; otherwise normal collection can proceed with SharingUnavailable. C-14 commits artifacts, and C-17 materializes only matching authorized projections after current manager, parent, grant, lineage and deadline checks. C-08 durable audit acknowledgement precedes new recipient reads.

Stopping future publication does not revoke existing concrete children. Revoking an instruction first commits parent denial, then cleans up dependent child shares. C-03 checks that parent on every dependent read, so delayed cleanup cannot preserve access through that path. An unrelated independent entitlement remains separately evaluated. Manager transfer cannot extend retention, mint fresh publication slots or turn ownership into raw access. See [sharing](../../specs/authorization.md).

## R-09 — Expiry, storage failure and fair capacity

C-15 computes read cutoff and deletion budget from original acquisition/parent time. Reads fail at cutoff even if deletion is unavailable. Local cleanup continues from signed deadlines through hub outages; C-15 coordinates objects, versions, multipart uploads, indexes, scratch and applicable backups. A successful deletion request is followed by backend-specific absence verification. C-07 releases only the corresponding proven charge; remaining/unknown copies stay charged.

If one workload's object deletion is denied, report Overdue and block new admission into the affected backed allocation as specified. Other independently backed protected allocations remain available. If the backend failure cannot be isolated, widen the block truthfully. No automatic eviction of another workload's evidence. Storage locks and backup horizons conflicting with deadlines are readiness failures, not silent exceptions. See [privacy](../../specs/privacy.md).

## R-10 — Hub restore, configuration churn and upgrade

C-04/C-21 start RecoveryBlocked, fence the old primary/issuer epoch and reconcile current CRDs, identity freshness, independent revocation/audit checkpoints and prepaid spend. Old grants/shares/intents are invalidated when completeness cannot be proved; uncertain charges remain. C-13 never resumes a restored live watch as if it were fresh. C-10 reports missing source/history after node loss. C-19 imports already committed local outcomes by stable IDs without redispatch.

A changed namespace UID, source definition or node boot cannot inherit its namesake's authority. During rolling N/N-1 upgrades, C-04 negotiates supported contracts and C-19 dispatches only compatible work; unsupported mechanisms remain unavailable while stored evidence is readable where dependencies permit. Database expansion/contraction and object format readers must cover the compatibility window before older writers are removed.

## Responsibility at failure boundaries

| Failure / ambiguity | Primary owner | Persistent residue / next action |
| --- | --- | --- |
| Lost submit/COMMIT response | C-09 / C-21 | Original operation uniqueness; lookup, never new request key |
| Failed object audit | C-08 | Pending audit/outbox; no sensitive start/disclosure; denial persists |
| No local admission response | C-11 / C-07 | Look up exact start/bundle; unknown spend remains charged |
| Lost target / PID reuse | C-05 / C-11 | LostTarget/partial; never substitute process or pod |
| Node/collector loss | C-11 / C-12 | Invalidated epoch, explicit coverage gap and uncertain attempts |
| Interrupted upload / KMS outage | C-14 / C-15 | Bounded encrypted pending copies, no plaintext fallback |
| Analyzer or volume handoff uncertainty | C-18 / C-15 | Fence stage, retain tracked volumes until safe cleanup |
| Slow/expired live client | C-13 | Bounded gaps/close and short row expiry; no durable rows |
| Identity / config source stale | C-03 / C-01 | Deny dependent starts/reads after current freshness bound |
| SQL outage / stale restore | C-21 / C-04 | RecoveryBlocked; local finite permits and cleanup only |
| Deletion not verified | C-15 / C-07 | Denied reads, retained charge and explicit overdue remediation |

Runtime tests must exercise these boundaries with actual processes, storage and network failures. The architecture gate only checks documented contracts and synthetic state transitions.

## R-11 — Download and finish the investigation locally

A maintainer or authorized recipient selects an existing artifact. C-14 resolves current C-03 read/download authority, reuses a covering raw grant where needed, reserves C-07 output/read-work and creates one ArtifactDownload. After durable C-08 disclosure intent, C-19 delivers downloadArtifact work to the regional connector. A scoped acquisition Job verifies/decrypts the exact object and emits bounded native bytes through I-13. C-20 authenticates each HTTP request, and stream leases recheck authority; C-14 accounts emitted/uncertain bytes. Disconnect produces Interrupted; a range retry retains identity/version/deadline and reserves retransmitted output. Expiry/revocation stops delivery. The developer verifies the checksum and opens the file in their own tool; that local copy is outside C-15 managed deletion. A core may be downloaded with separately authorized exact companions; no current-image substitution.

## Combined review in the local-investigation flow

Before the native-download flow, a manual capture can ask for collection plus selected output access. One reviewer binds both scopes. On each C-14 verified commit, C-03 idempotently materializes an existing-artifact child for each explicitly approved client of the same human. The parent pool is shared across children. Artifact download/query resolves the child automatically and rechecks parent, artifact and entitlement. Commit before grant publication shows “Evidence saved; access preparing” and retries publication only. Parent revocation stops output even before asynchronous child cleanup; capture budget exhaustion alone does not. Original expiry never moves. These are required fault cases, not a measured implementation.
