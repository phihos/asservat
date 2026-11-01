# Manual saves of existing recordings

Status: implementation in progress; manual SQL108 and installed qualification pending.

Implements the accepted [recording-save contract](../../specs/recording-saves.md)
on [ADR-264's existing-source snapshots](264-existing-source-packet-snapshots.md).
These engineering choices do not narrow the accepted grouped or syscall scope.
The current backend supports one packet source per incident; grouped 1–16 source
saves, syscall sources and the protected reason producer remain unfinished.

## Selection and first acceptance

Discovery reuses the existing named `target_ref`. It does not create another
handle journal in diagnostics. Workload identity observation reads namespace and
Deployment/StatefulSet UIDs without selecting a Pod. Direct Pod references still
need that actual object; deleted names never manufacture historical identity.

Source handles refer to an immutable principal/client-bound SQL selection set:
at most 100 compact references, 65,536 bytes and 60 seconds from first discovery.
SQL filters policy before its 101-row keyset scan. Display pages and selected
previews read exact source IDs, so a later page cannot silently revert to the
first batch. Continuations preserve original creation/expiry and caller/target/
filter binding. A batch cursor cannot be used as a source handle. Existing
10/principal and 1,000/root preview limits include these sets; capacity refusal
remains explicit. MCP/browser presentation caps requested pages at 20 before
querying to retain the existing 24 KiB metadata envelope; oversize output refuses
with `ReduceLimit`, never a cursor that skips omitted rows.

Inventory performs no payload read, source-report RPC, ring pin or reservation.
Unknown history/readiness remains unknown. A selected preview resolves the exact
retained source/process and current authority before assessment. The UI displays
a passive assessment on selection; its Save click refreshes preview and submits
only unchanged material disclosures, without another human approval page.

The canonical `recording-save/v1` scope binds the actual requester and original
policy executor independently. It retains exact source/node/boot/action identity,
original compiled definition and audience digests, lookback/output limits,
incident cap, authored processing timeout and retention/ceiling dependencies.
The full physical source-binding digest remains independently checked.
Preview clocks are not t0. Inside admission, accepted idempotency resolves first;
new acceptance samples database time under the existing permission/policy locks,
then anchors t0, registration and processing in the same transaction. Retries do
not resample it. Original observation, source, grant and parent bounds remain.

## Authority, audit and budgets

The original policy executor remains `CaptureIntent.Actor` and API work actor.
The immutable actual initiating principal is separate `Initiator` provenance;
operation audit attributes the request to that human/workload principal. Both
current initiator and unchanged policy eligibility are evaluated before effects.
Legacy captures omit the new field and retain their original encoding.

A manual save consumes existing workload/policy GCRA windows, accepted execution
and collected-byte budgets, covering grant budget and custody allocation in the
same transaction. It creates no detector Tick, policy occurrence or observation
credit. One capture-linked reservation records that spend. Recurring-policy
sharing is explicitly excluded; an explicit capture-time instruction follows the
existing sharing path. History records origin `manual`, operation `recordingSave`
and typed encrypted repeat settings. Repeating requires fresh source selection;
settings contain no reusable handles, leases, grants or sharing instructions.

## Cancellation and production gate

Cancellation persists intent before delivery. Unknown delivery remains requested
under the existing collector; it is not a joined result. Cancellation before any
start fences later Prepare/Start. A started capture reaches Cancelled only through
the dedicated exact capture/attempt/request/process joined proof. Positively
stored completion wins a cancellation race. No source is stopped or authority,
observation credit or uncertain charge refunded. Existing current rights and
restrictive cleanup remain available when new source acquisition is disabled.

The trusted application `RecordingSaveEnabled` defaults false. It fences new
manual admission and active continuation/start, including direct opaque
`request_capture` calls. Passive metadata and accepted replay receipts do not
confer execution authority. Production bootstrap leaves the gate false until
installed source/clock qualification; this is not a new Helm setting. The finite
public activation compiler is unchanged.

## Cumulative cost and evidence

There is no new service, credential, broker, key, network endpoint, Kubernetes
permission, watch, timer, tuning setting or parallel resource pool. SQL108 adds
two bounded metadata tables and six cancellation columns to existing captures.
Existing selector/admission/execution roles receive only the needed table/column
rights. Downgrade refuses live/manual cancellation state it cannot preserve.

The maximum compact-reference fixture measured 56,501 bytes. A 100-candidate
batch invokes up to 200 retained-Pod eligibility evaluations, three workload
projections, one candidate read and one selection write. With one distinct policy
it makes one policy read; the heterogeneous worst case is 100 policy reads and
compilations. A same-set next 20 rows uses 40 eligibility evaluations, three
workload projections, one exact-source read and no selection write. Synthetic
in-memory timings are not production SQL/Kubernetes latency. Aggregate installed
cost remains qualification work; no cache or added polling is justified yet.

Local app/SQL adapter, transport, console and browser checks are recorded in
implementation-progress.md. The automatic SQL106/107 component qualification
does not qualify manual SQL108, installed collectors, native clocks, real
identity-provider sessions or the entire Save contract. Actual provider results
must be recorded separately before any completion or public enablement claim.
