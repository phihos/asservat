# Bounded approved context projection

[ADR-206](../decisions/206-bounded-context-projection.md) defines the next narrow
S-02 implementation: inspect existing approved pod status through the canonical
browser/MCP `get_file_excerpt` and `get_query_result` contracts. This is an
accepted implementation contract. Pure values, strict decoding/formatting and
the C-18 coordinator component are implemented. Protected adapters, installed
wiring and qualification remain pending; no tool availability is established.

## Exact result

The source must be the exact committed, independently verified artifact for
`asservat-pod-status/v1`, with the existing immutable
`artifact.ContextProjectionDefinition` digest and 4096-byte native limit. Case,
capture, target, attempt, store and ciphertext version come from protected
publication records, not a caller's asserted source. Check provenance, envelope,
manifest, native schema and the expected format before projecting fields.
Unpublished custody, another format or additional properties fail closed.

Display version `approved-pod-status-display/v1` returns `pod-status.txt` and one
line per field in this order:

1. `format`
2. `namespaceUID`
3. `podUID`
4. `resourceVersion`
5. `observedAt`
6. `phase`
7. `ready`
8. `initialized`
9. `scheduled`
10. `runtimeInstances`
11. `running`
12. `waiting`
13. `terminated`
14. `restarts`

Each line is the literal field name, `: ` and its JSON scalar representation.
Strings use JSON quoting/escaping; integers use decimal notation with no exponent.
The timestamp is rendered in UTC RFC 3339 with necessary fractional precision
and no trailing fractional zeros. Preserve the strings `True`, `False` and
`Unknown`; do not infer booleans, add live values or expose excluded fields.
This is a synthetic text view, not a JSON document or a workload filesystem path.
The field list is grounded in the existing collector `statusProjection` and
`specs/contracts/pod-status.schema.json`; changing it requires a display version.

Normalize absent `line_start` to 1 and absent `max_lines` to 200, within the
canonical input bounds. Return the requested contiguous intersection with the
fourteen lines; a start after the final line returns an empty successful list.
`line_start` retains the normalized requested value. An explicitly selected
subset is not truncation. There is no pagination cursor; all fourteen lines fit
the bounded profile. A result exceeding the profile ceiling fails rather than
silently dropping fields. Validate the complete serialized envelope, including
the nested `get_query_result` wrapper, within the 24 KiB structured and 64 KiB
combined wire limits. `data_class` is `metadata`, not an assertion that the
identifiers are anonymous or exempt from privacy controls.

## Ownership and interfaces

C-24 owns pure query/source/batch values in `internal/domain/analysis`. C-18
owns the coordinator in `internal/application/analysis`; C-03 owns current read
authorization; C-14 owns bounded acquisition; C-15 owns managed-copy lifecycle;
C-07 owns capacity; C-08 owns audit. C-20 maps the same canonical operations for
browser and MCP. C-21 supplies separate scoped storage/provider adapters.
No component calls a transport handler as an application port.

These are implementation interfaces, not new public wire fields:

| Owner | Interface/value | Required contract |
| --- | --- | --- |
| C-24 | `ContextExcerptSelection` | Case/artifact IDs and normalized line range only; no caller source, worker, deadline, key or path. |
| C-24 | `ContextProjectionCandidate` | Internal route IDs/whole-pod target, principal/client and normalized selection only. It carries no native facts, version or authority. |
| C-24 | `ContextProjectionScope` | Root/case/capture/artifact IDs, exact whole-pod target, committed ciphertext version, native projection digest, fixed display version, normalized selection, original `identity.Principal` including client ID. |
| C-24 | `ContextProjectionEnvironment` | Current installation/recovery, exact registered attempt/store, processing decision, protected query path/region and actor/client; original observation bounds. It is a distinct type, not a download environment alias. |
| C-24 | `ContextProjectionAuthority` | Exact scope, permission revision, identity policy, retained-policy proof, environment, decision digest, original checked/valid interval and effective access/delete dates. Current effects require every proof, never legacy optional-zero compatibility. |
| C-03 | `ContextProjectionAuthority.CheckProjectionCurrent(ctx, CurrentIdentity, ContextProjectionScope)` | Returns the domain authority after `ReadApproved`, original audience and final current checks; no query creation, SQL effect or decryption. |
| C-03 | `ContextProjectionAuthority.ResolveProjectionCurrent(ctx, CurrentIdentity, ContextProjectionCandidate)` | Initial path: checks ordinary target rights before the protected source lookup, then constructs the exact version-bound scope and returns current authority. No fabricated source version or C-18 policy duplication. |
| C-03 | `ContextProjectionCatalog.ContextProjectionEvidence(ctx, artifactID)` | Verified published source/retained-policy projection. No native fields, native hash or filename. The authorizer checks ordinary target rights before this read. |
| C-03 | `ContextProjectionEnvironmentReader.ProjectionEnvironment(ctx, evidence, principal)` | Independently accepts current processing/recovery/client/region/query path; no static region or download-permit fallback. |
| C-18 | `ContextProjectionRoutes.ResolveContextProjection(ctx, ContextExcerptSelection, identity.Identity, recovery)` | Internal content-minimized route candidate binding case/artifact/target. Never returns evidence or authority to the caller; current ordinary rights precede protected source lookup. |
| C-18 | `ContextProjectionService.BeginExcerpt(ctx, CurrentIdentity, ContextQueryInvocation, ContextExcerptSelection)` | Admits one server-owned query and at most its one worker, then returns a process-owned pending/result delivery. It preserves original request cancellation and acknowledged C-08 lineage. |
| C-18 | `ContextProjectionResults.GetQueryResult(ctx, CurrentIdentity, ContextQueryInvocation, queryHandle)` | Observes the exact existing query; may deliver its bound result using a new paid batch. This type has no worker-admission port. |
| C-18 | `ContextQueryLedger.AdmitQuery(ctx, query, request, authority)` | Atomically fixes query ID, source/selection, principal/client, immutable plan and original bounds; independently consumes current accepted backing and exact acknowledged C-08 intent. Only the first acknowledged insertion returns `Fresh`. Unknown commit retains spend. |
| C-18 | `ContextQueryLedger.LookupQuery(ctx, principal, queryHandle)` | Private bounded exact routing lookup, never sufficient for status/disclosure or a plaintext result cache. `AdmitQueryPoll` charges each new audited invocation; `PermitQuery` is a repeatable current fence. |
| C-18 | `ContextQueryLedger.BeginReadBatch(ctx, query, request, worker, batchID, authority)` | Charges the next generation and three one-use key roles before I/O; refuses concurrent, exhausted, uncertain or expired work. `Fresh` requires the first acknowledged insert. |
| C-18 | `ContextQueryLedger.ClaimReadBatch(ctx, batch, authority)` | Separately consumes a one-use start for the exact generation/worker/live request owner. Unknown or repeated claims never start again; `PermitReadBatch` is only a repeatable current fence. |
| C-14 | `ContextProjectionWorkerAdmission.AdmitProjectionWorker(ctx, admittedQuery, currentRequestOwner)` | Separate creation capability, available only to initial admission. Exact Job/Pod/configuration, original signing intervals, independently audited enrollment and capacity remain mandatory. |
| C-14 | `ContextProjectionReader.ReadProjection(ctx, ContextReadStart, currentRequestOwner)` | Independently verifies the one-use claim, existing exact worker and current typed query authority; decrypts/verifies the pinned source and returns an opaque DTO/closure handle. No launch fallback. |
| C-24 | `ContextProjectionWorkerBinding`, `ContextProjectionWorkerProof`, `ContextProjectionKeyBinding` | Query-only immutable Job/Pod/spec/configuration, actual peer/process/certificate and original observation intervals; structural checks never establish protected admission, live ownership or key authority. |
| C-14 | `RegionalContextProjection.ExecuteProjection(ctx, start, owner)` | Local regional component. Requires a mandatory protected execution guard and query-specific key operations; fixes exact claim ID to batch ID, consumes local generation/role fences and returns only verified status DTOs. |
| C-14 | `RegionalProjectionRead.Projection(ctx)` and `CloseLocal(ctx)` | At most one local current-proof check; closure cancels and joins execution/checks within the original prepaid cleanup horizon. Deliberately does not implement remote `WithProjectionClosed` or SQL completion. |
| C-21 | `ContextProjectionReader.ReadProjectionNative(ctx, source, scope, keys, until)` | Reuses complete pinned commit/manifest/envelope/index/native verification and strict status decoding under the original request. Regional-only keys never reach the hub. |
| C-18/C-20 | `ContextProjectionDelivery.CheckDisclosure(ctx)` and `Close(cleanupCtx)` | Process-owned result guard and joined cleanup, bound to the exact prepared association/query/batch. Recheck after outcome audit and through the final write. The transport supplies its separate original prepaid cleanup context after joining writes. |

`ContextProjectionScope` is constructed by C-03 from the minimal route candidate
and, only after ordinary target rights pass, the protected source record. C-18
does not read evidence to manufacture initial authorizer input. Later checks
compare the complete existing scope, including its original source version.
Neither candidate nor scope is directly decoded from public input. `CurrentIdentity` belongs to
the caller's original request; it is not persisted or passed as human credentials
to a worker. The C-18 catalog dependency gains only C-02 for this shared identity
handoff. Route and catalog adapters implement consumer-owned ports; C-18 does not
import C-16 or use case presentation as evidence authority.

C-03 may reuse unchanged eligibility/retained-policy logic and content-minimized
catalog facts. It must use `ReadApproved`/`evidence:read`, never require
`evidence:download` as a shortcut. A current protected query path must explicitly
authorize this operation's processing/locality and worker purpose. Existing
download policy/schema acceptance is not automatically query acceptance.

The query values reuse neutral `artifact.RetentionProof` and
`artifact.RecoveryProof`. Existing `artifact.DownloadProcessingProof` represents
the complete current root/capture/location processing state despite its name;
it may be reused with those exact bindings and all current checks. Placement is
a distinct `ContextProjectionPath` with explicit `context-projection/v1` purpose,
storage/acquisition/connector/hub regions and accepted worker/hub revisions.
There is no conversion from `DownloadAuthority`, `DownloadEnvironment` or
`DownloadPolicy` into query authority. The independent C-03 evidence record also
binds case, source format/class and native projection digest, rather than
weakening or overloading the existing download record.

The SQL source adapter uses the separate SELECT-only `ContextProjectionEvidence`
facet. It checks the current published capture and verification audit receipts,
exact custody copies digest, fixed metadata profile and every retained policy
origin. It returns a bounded source observation, never native bytes or a read
permit. The private case adapter selects the exact requested artifact from the
recovery-bound case locator and preserves the original whole-pod target and line
selection; missing or duplicate matches fail rather than choosing another source.
Native regressions cover unpublished and malformed-audit denial plus exact source
and route bindings. Their implementation is present; the combined SQL-native
qualification result must be recorded separately before claiming they passed.

## Query and request lifetime

At admission fix an original query start and deadline: start plus the protected
profile lifetime (default ten seconds, maximum sixty), shortened by original
effective evidence access. Store those bounds, not a current credential or
renewable identity lease. A later
shortening is irreversible. A pending handle cannot preserve access across
principal/client changes, revocation, deny, recovery or expired evidence.

Every public call creates its own [current identity](current-request-identity.md)
with the original at-most-five-second interval and inherited cancellation. Every
read, lock, key operation, audit and write retains that interval and the earlier
query/dependency bounds. The query's longer lifetime permits several separate
current requests; it never authorizes a ten- or sixty-second request lease.
Old authority/key slots cannot be renewed by a fresh poll.

REQ-MCP-002 defines bounded query state independently of transport sessions;
REQ-AUT-002/004 require current authorization at each read/delivery, and
REQ-PRV-003 supplies inherited evidence cutoffs. None makes initial token/session
expiry a separate total-query cutoff. A refreshed credential for the same
principal/client can support a fresh result-read request within the original
query/evidence deadline. It cannot revive an old request, renew the query,
restore spent keys or bypass current group/deny checks. The five-second
`CurrentIdentity` observation is never extended into a longer query permit.

The C-18 component bounds the first identity read before calling its resolver,
copies retained groups/scopes, and cancels the single request context at every
monotonically earlier dependency cutoff. All subsequent ports observe that same
shortened deadline. It checks current authority again after the one-use SQL
start claim, before any private read; a late acknowledged claim stays spent.

Initial admission may create one exact worker under the live request. Its
acknowledged Job can start afterward as a consequence of that admission, but no
background plaintext read may proceed without a live authorized result request.
Pending result polls only observe bounded existing state. Existing-worker
authentication/enrollment continuation must retain the original key, immutable
identity, signing spend/interval and current query request owner. It cannot
create a replacement or reset a failed/uncertain attempt. If this continuation
cannot be qualified inside the original bounds, the operation is unavailable.

## Result batches, copies and uncertainty

The protected result reference is the original verified encrypted source plus
the fixed display version/selection. It never permits recollection or a general
transform. The initial profile admits at most two read batches, one worker and
one active batch. Each read charges 4 MiB of bounded read work, up to 24 KiB of
structured output and 64 KiB of complete response. These are conservative
admission ceilings, not measured overhead or permission to increase native size.
The original plan must separately cover bounded worker memory, transient buffer
copies, authentication/key/audit requests, polling/control writes, retained SQL
history and cleanup. A missing qualified resource dimension denies admission.
Principal/workload/installation limits apply across query IDs and OAuth clients.

`ContextQueryResourceProfile` is a typed snapshot of accepted configuration and
qualification, not caller options. `ContextQueryPlan` pins its accepted source,
qualification, path, backing/account/allocation revisions and workload/principal.
Its exact aggregate `ContextQueryCost` covers provider/auth/signing/audit work and
qualified SQL rows/bytes/WAL/backups. The current protected C-07 producer must
derive actual per-poll/control costs, parent-envelope ownership and aggregate
concurrency ceilings; structural validation does not establish that backing.
No producer or permissive default is supplied by this component.

Worker CPU/memory, worker and hub transient copies, provider/auth concurrency,
worker runtime, credential lifetime, provider-effect lifetime and cleanup are
explicit independent dimensions. Each query fixes original worker, credential,
provider and cleanup dates from that profile. Plan `HardUntil` bounds disclosure;
`EffectsUntil`, `CleanupUntil` and `RetireBy` cover later obligations. Neither
query expiry nor passing those funding dates proves quiescence or refunds work.
Overdue uncertainty must remain represented under bounded protected recovery
and cleanup; time alone never authorizes deleting its ledger rows. The download
worker's twenty-minute signing period is not a query-purpose default.

Each admitted batch has a unique ID, increasing generation and three one-use
data/index/manifest unwrap slots. SQL/key facets bind query, batch, exact source,
purpose, worker peer/process and original interval. A consumed slot or unknown
key reply stays spent. Recovery/retention/current permission guards are checked
after blocking locks in the established lock order. Generation fencing alone
does not prove the previous process has stopped or free its resources.

The acquisition worker holds only the bounded verified source/projection needed
for this response. The hub receives only the approved DTO under query authority;
it receives no wrapping root, unwrap capability or general native byte reader.
Record transient copy obligations before plaintext exists. Keep buffers owned
through joined response cleanup, clear them on cutoff/cancellation/completion
and retain uncertain charges. Do not promise Go heap erasure, browser memory
erasure or deletion of a recipient's external copy. There is no disk, PVC,
service-worker or persisted browser result cache in this profile.

A positively joined private read followed by a lost outward reply permits a new
charged delivery of the same query, source and selection, if its original budget
and deadline remain. The new batch receives new key slots; the previous batch
is never executed again or refunded. A pending handle is available only if the
caller actually received it: a lost initial response does not invent recovery by
a user key. A later initial ordinary read can create another independently
charged query, and aggregate limits still cover both.

An uncertain private read/close blocks further work on its worker. EOF, local
cleanup, SQL lease expiry or an owner-row fence is not a remote Joined receipt.
The first profile does not qualify automatic repair/replacement or reuse after
that uncertainty. Passive retrieval reports unavailable; expiry/exhaustion is
terminal. Cleanup remains an independently bounded obligation. The native
download service's separate [interruption rules](native-download-retry.md) remain
unchanged.

`ContextProjectionRead` and `ContextProjectionClosed` are opaque C-14 process
handles. `WithProjectionClosed` holds independently verified exact batch,
worker, peer, process and generation closure while its callback performs only
the restrictive SQL transition. No caller-set Boolean, EOF or pure completion
DTO grants reuse. The batch remains active through outcome acknowledgement and
the final outward write. After transport-owned copies/writes are joined,
`ContextProjectionDelivery.Close` clears its retained lines, joins private
cleanup and asks SQL to consume that guarded closure. An unknown completion
does not refund read/key/audit spend or permit a replacement.

The caller supplies a separate cleanup context bounded by its original prepaid
allowance. C-18 additionally caps synchronous cleanup by the earlier original
query cleanup and invocation audit-write bounds. It never renews an expired
cleanup context. The C-20 reply owner must derive that cleanup context from the
retained original write bound, rather than forwarding the expired public-read
context. Failed close remains uncertain for protected cleanup; a second call
does not issue another SQL completion or invent a later cleanup interval.

## Audit and transport boundary

SC-AUT-005 gives every invocation a new server audit request ID, including polls
and denials. No user-managed read idempotency key is added. Normalize the exact
case/artifact or server-owned query reference, tool, display version and line
selection; SQL/outbox/audit metadata never carry output lines. Use the existing
keyed input/output audit digests and encrypted audit objects. Query admission,
worker starts and read-batch spend must be represented truthfully, even though
the public operation is an ordinary read.

Commit intent before query/worker/read effects, validate the exact bounded result
and acknowledge its durable outcome before disclosure. A result returned by
`get_query_result` is nested under server-selected `tool_name=get_file_excerpt`
and validated against that original tool's output schema. A handle does not
select a weaker schema. Both the nested and outer envelope share the current
request; their combined bytes consume one bounded outward response.

After outcome audit, the request-owned delivery guard checks identity, complete
denies/current rights, original audience, effective retention, processing/path,
recovery, query/batch generation and original deadlines. The transport binds
write/flush cancellation to that guard and joins cleanup before releasing the
slot. Do not return a free-standing byte slice with only an expiry field and
assume the earlier authorizer still applies. Audit records prepared output and
delivery unknown when necessary, not proof of receipt.

C-18 owns no second audit journal. `ContextQueryInvocation` is the process-owned
handoff from the existing C-20/C-08 wrapper after intent acknowledgement. It
checks the exact normalized input and carries the original server request ID,
principal/client and keyed input/principal lineage into query/batch admission.
SQL independently requires that same acknowledged invocation. A
`ContextProjectionDelivery` exposes immutable association values and bounded
copies of its typed excerpt; C-20 serializes/validates once and binds the exact
delivery pointer to its existing keyed output digest and acknowledged outcome.
`CheckDisclosure` refuses that pointer before acknowledgement, including pending
handles. Admission, paid polling and paid reading have explicit effect
dispositions; an uncertain service error never proves no effect.

The concrete C-20 `ContextProjectionOperations` component accepts separate
initial-admission and result ports returning that C-18 pointer. It exposes only
the private-context call path: existing tool registration and installation
composition do not include it. The wrapper creates `contextQueryInvocation`
after its existing `Begin` acknowledgement; the adapter checks the typed input
against the same normalized input MAC before calling either port. The private
reply callback accepts only the unchanged intent, exact prepared byte count and
successful accepted-effect outcome from the existing `Finish`. A late failure
closes the original delivery before discarding its bytes; it cannot transform
unknown query/read spend into a no-effect audit result.

Each prepared delivery freezes `ObservedAt` at that response's preparation,
`QueryDeadline` at the earlier original query/effective-access cutoff, and
`CleanupUntil` at the original prepaid cleanup/write cutoff. These differ from
the current at-most-five-second `ValidUntil`. A late poll must not report query
creation as its observation and thereby restart a browser's remaining TTL. A
later access shortening below the already prepared cutoff rejects that exact
delivery rather than mutating audited output or disclosing the older cutoff.

The browser renders the same fixed projection as text, with no provider token
or HTML interpretation. Its managed view has a finite original cutoff, clears
on scope loss/close and does not silently create a new query after a terminal
result. Result metadata/cutoff must be conveyed through the shared validated
presentation contract; implementation must not invent an unvalidated browser-only
evidence shape. Canonical ordinary-read request schemas need no idempotency or
continuation extension. Native-download actions remain separate.

The two query operations carry `query_observed_at` and `query_expires_at` in
successful/pending `data` only. C-18 fixes the observation timestamp when it
prepares the immutable result. Expiry is the stored original query deadline,
monotonically shortened by effective evidence access, and is distinct from the
private at-most-five-second `OperationReply.ValidUntil`. A successful
`get_query_result` wrapper and its nested original result must have equal timing
and request IDs. The canonical catalog still permits other specified original
tools; the current runtime validator accepts only `get_file_excerpt` and applies
its complete nested output schema. No schema entry activates a service.

The browser records monotonic time at the start of a query request. Its local
clearing bound is that start plus the server's expiry-minus-observation interval,
so time spent making the request is not added to the view lifetime. Reject an
invalid, nonpositive or greater-than-sixty-second interval; retain the earliest
known bound for the same handle. Clear on scope loss, closure and suspension.
This avoids assuming synchronized client wall clocks and does not promise
revocation of external copies. The existing metadata console has no clock-offset
facility; the approved projection view remains pending implementation.

C-20's private reply owner is shared across `OperationReply` value copies. It
binds the serialized body to the exact application delivery, requires the
existing acknowledged C-08 outcome before disclosure and retains cancellation
through transport serialization/write/flush. The wrapper transfers its cancel
and in-flight slot only on a successful owned reply; failure closes locally.
`OperationReply.Close` creates a separate cleanup context from its original
finite cutoff, capped by the invocation's original thirty-second write allowance,
even when passed an expired public request. It joins the application close before
clearing owned bytes and releasing the slot. A failed close retains uncertainty;
it never produces a positive remote-completion receipt. HTTP transport slots
remain held until this cleanup returns.

The delivery's read-only `Done` signal is also linked to that reply owner. The
application request is a child of the HTTP request, so its earlier cutoff or
cancellation would not otherwise interrupt a blocked outward write. One bounded
watcher is joined by reply close; `ResponseContext` links this owner to the actual
browser/MCP write/flush context, whose socket-deadline callback is also joined
before reuse. A final blocking guard that discovers a shorter private lease
rejects the already prepared response instead of using its older socket bound.

## Native reuse boundary

Reuse exact immutable source verification, framing/TLS primitives, protected
worker attestation and original-deadline mechanisms where their contracts fit.
Do not pass a synthetic `DownloadAuthority` into current download workers or
insert query rows into a download session/key-binding table. Existing key
bindings and native exchange kinds are explicitly download-bound.

A query requires its own admitted operation kind, SQL query/batch/key facets,
current worker/owner routing and separate credential grants. Any shared private
wire needs an explicitly versioned, closed query command whose peer/operation
checks cannot accept a download command. The query response sends only the fixed
approved DTO, not arbitrary native ranges. It obeys five-second request bounds,
not the native download whole-response lifetime. Protected installer/provider
configuration and negative cross-purpose probes must establish this authority
before public enablement. No old worker, accepted profile or installation pin is
silently rebound to a new purpose.

Immutable query start, disclosure and worker/credential/provider/cleanup instants
use UTC microsecond precision so JSON and SQL replay retain the same identity.
Creation checks authority and plan freshness against the actual current instant
before flooring any persisted time. Every original derived cutoff rounds down;
normalization cannot revive expired authority or extend a deadline.

### Regional component and unimplemented protected bindings

The local C-14 component holds one immutable query/worker and at most one active
batch. `ContextProjectionExecutionGuard.OpenProjectionExecution` must independently
verify the durable spent start, acknowledged intent, accepted backing, exact live
owner and actual worker proof before returning a process-owned execution handle.
`Fresh`, certificates, DTO validation or constructor arguments cannot substitute
for that guard. The full native worker proof includes exact namespace/account/
Job/Pod identities and specs, accepted configuration, token/public-key digests,
actual peer certificate/process and protected observation interval. The producer
must hold that exact current proof while a SQL binder compares it under locks.
No protected producer or worker/key insertion grant is supplied here.

`ContextProjectionKeyOperations` is a distinct query-only effect boundary. Its
producer must consume the exact data/index/manifest role durably under the full
query/batch/source/worker/request and current authority, including the sealed key
and canonical artifact binding. Existing artifact framing/AAD remains unchanged;
query authority never falls back to a download key resolver. Local role bits are
an additional nonrefundable fence, not the durable grant. Failed/unknown provider
calls retain spend and discard returned key bytes. All three positive roles and
complete authenticated source verification precede a typed result.

Local closure joins the source/key work and any in-flight current-proof read,
then closes the known execution handle even if its opening outcome was uncertain.
An unknown opening/closure retains the local active worker. Cleanup uses the
original minimum of query cleanup and invocation audit-write horizon independently
of an expired public context; it grants no new source/key read. The local type has
no remote-closure method. A separate authenticated private query protocol must
establish exact remote operation/peer/process/generation completion before C-18
can authorize restrictive SQL completion. Socket EOF, local buffer release and
this local join cannot provide it.

The local component's race tests cover wrong claim/source/worker/process,
caller and original proof cancellation through blocking reads/key calls, all
three one-use roles, failed-key clearing, current revocation, two paid batches,
unknown opening/closure, cleanup after public cancellation and joining an
in-flight current check. Tests first reproduced foreign-claim acceptance, a
short caller deadline being lost, skipped known-handle cleanup on uncertain
opening and cleanup suppressed by public cancellation; all now pass. The C-21
TLS object fixture uses actual framing, authenticated manifest/native checking
and the strict parser; tampering with any of the four pinned objects prevents
output. Its wrapping keys and HTTP receipts are explicitly synthetic.

`go test -race -count=1 -timeout=2m ./internal/domain/analysis ./internal/application/evidence ./internal/adapters/objectstore`
and affected-package `go vet` and the Go architecture gate pass for this
component. Domain/C-18 race tests also pass after the timestamp regression.
These results establish neither native provider authorization nor remote closure.

Protected query dispatch/enrollment/signing, the current execution proof producer,
SQL worker/key binding and durable consume composition, purpose-specific private
key routing, private DTO/remote closure protocol and runtime/installer acceptance
remain required. These missing ports keep this component unavailable in production;
no default authority, public route or native qualification is implied.

## SQL query ledger component

Migration 00068 adds eight purpose-specific tables for accepted backing,
workload allocations, principal accounts, queries, bounded invocation
associations, workers, read batches and key slots. The schema inventory is 114
of the existing 128-table ceiling. These tables do not reuse download state or
confer evidence authority. There are no installed query-role grants, backing
producer, worker-binding producer or key-consume API in this component.

The independently configured C-07 guard must establish the complete current
protected source, native resource/history qualification, exact purpose path and
parent envelope, including original disclosure, possible worker/certificate/
provider effects, cleanup and history horizons. A profile, revision or JSON
object supplied by a request is insufficient. Inside the guarded callback, SQL
locks recovery, permissions and the accepted backing/allocation before query
state. It compares the complete profile and qualification revision, account and
workload identity, source revisions and all four accepted horizons. Runtime
admission cannot provision or replace these facts. Principal accounting excludes
OAuth client identity; each query's exact actor and invocation still include the
client. Account creation itself consumes the finite accepted account allowance.

Each admitted query reserves its full finite cost vector against installation,
workload and principal limits. This includes one worker, two batches, six unwrap
attempts, provider/authentication/signing work, CPU/memory/private copies and
qualified SQL/WAL/backup history. Poll and control allowances are explicit;
bounded invocation rows cannot grow independently of them. The accepted
qualification must establish actual row, index, audit and effect backing; shape
validation and the synthetic fixture's arithmetic are not a native capacity
qualification. Every row and charge survives failure, expiry and unknown
results. This component has no history-retirement or capacity-refund path.

Every admission, poll and paid batch binds a different current C-08 invocation
where appropriate: exact operation/root/actor/client, principal and input MACs,
format, tool and original request/write times. The intent must have both its
separate acknowledged receipt and positively joined writer completion in the
current database incarnation. The Go facet verifies the canonical typed record
digest; PostgreSQL JSONB text is never used as its substitute. The two query
operation names use the existing normal audit lane and only
`context-query-input/v1`. C-20 remains the sole prepared-response digest and
outcome owner.

An acknowledged first admission alone returns `Fresh`. Lost commit replies,
failed guard returns and repeated, omitted or late callbacks cannot do so; any
committed obligations remain. A read batch consumes one generation and has one
irreversible start claim. Its active slot remains occupied after its request
lease expires. The mandatory independent C-14 guard and stored exact worker
binding precede every start; an empty proof or download worker is unavailable.
The key table has three monotonic role bits, but no product key effect can use
it until its separate qualified binding/consume producer exists.

Only the process-owned C-14 closure callback can request completion. SQL requires
the same acknowledged, positively closed C-08 outcome and original incarnation
before clearing the active slot; read/key/audit spend remains. Lookup, SQL lock
waits, guard callbacks and return paths preserve original request, proof, query,
write and cleanup bounds. A guard cannot extend the caller's deadline by passing
a background context. Local EOF, buffer clearing, missing objects or expiry do
not establish remote closure. Public read permission and expired-artifact
access are not gained by this restrictive transition.

The native fixture supplies explicit synthetic C-07 qualification, human
identity and C-14 worker/closure guards while using the actual publication,
current C-03/retention/processing/recovery readers, scoped SQL credentials and
healthy encrypted C-08 audit. It owns and closes its helper pools before later
suites. Its source is present but native execution is pending; unit tests and
integration-package compilation are not a native SQL/S3 pass.

## Acceptance

The first component foundation is deliberately limited: pure scope/candidate,
authority/environment and status/excerpt values live in `internal/domain/analysis`;
`objectstore.ParseContextProjection` strictly decodes the bounded native shape;
`analysis.FormatContextExcerpt` in C-18 creates the fixed escaped lines. Domain
code performs no JSON decoding, hashing or I/O. A pinned source-definition digest
has a regression against the actual immutable definition. The decoder checks
inner Pod/namespace/source-profile bindings; it does not establish the ciphertext
version, envelope, manifest or publication provenance. Those still require
independent C-14 verification before the decoder is called. These functions alone
provide no public route, worker, query storage, key authority or disclosure.

The separate C-18 coordinator component now implements `BeginExcerpt` and
existing-worker-only `GetQueryResult` against mandatory consumer ports. Pure
query/plan/batch values pin independent effect horizons, immutable backing and
source identity. Component fakes cover intent/input mismatch, unknown admission
and one-use claims, active delivery ownership, exact outcome acknowledgement,
paid repeat delivery after lost replies, uncertain closure, exhausted batches,
pending polls, final current restrictions and identity slice reuse. Real bounded
blocking route/plan/claim tests establish cancellation at an earlier original
dependency deadline. A regression first reproduced starting a private read after
a late SQL claim; the coordinator now rechecks before provider work.

`go test -race -count=1 ./internal/domain/analysis ./internal/application/analysis`,
`go vet ./internal/domain/analysis ./internal/application/analysis` and
`make go-architecture-check` passed for this component. These tests supply
explicit synthetic ports. Current C-07 accepted backing, SQL implementation and
native transaction qualification, query-purpose worker admission/enrollment,
one-use key binding, private DTO delivery/positive closure, C-20 audit ownership,
protected installer/runtime composition and installed qualification remain
separate work. No constructor substitutes a synthetic production resolver or
advertises a public operation when one of those capabilities is absent.

1. Browser and MCP with ordinary evidence-read rights return exactly the fourteen
   approved fields and matching line selections from the already committed
   artifact. They need no download scope or additional consent. No collector or
   live Pod read occurs; case descriptors and full native download remain intact.
2. Reject wrong case/artifact/version/native or display projection, extra native
   fields, malformed values, unpublished/raw/unsupported-share sources, swapped
   key roles, wrong worker/peer/process and query/download cross-purpose replay.
   A reader lacking ordinary target rights cannot probe protected catalog data.
3. Exercise deny, retained-audience change, identity/client change, retention
   shortening and recovery/processing/path restriction during source lookup,
   SQL/key waits, private delivery and outcome audit. No bytes follow the changed
   authority or original deadline; no fresh observation extends old bounds.
4. Lose the public reply after a positively joined private read. A later result
   read uses the same query/source/deadline and a fresh charged generation/three
   key slots; prior spend remains. Repeating the same batch cannot run again.
   Separately make private closure uncertain: no reuse, replacement or refund.
5. Poll pending, concurrently poll, replay another actor/client's handle and
   exhaust the two batches or total lifetime. Polling cannot dispatch, reset
   capacity or extend the query. A lost initial reply followed by a new initial
   read leaves the old obligations charged under aggregate limits.
6. Delay or fail outcome audit and final authority checks. Both transports send
   no result, preserve original cancellation and join owned cleanup. Validate
   wrapper/nested schema, byte ceilings, text escaping and browser clearing.
7. Qualify installed SQL/S3/key/worker/relay composition, scoped negative probes,
   positive/uncertain closure, bounded copy/history cleanup and sustained browser
   plus MCP reads inside the original five-second requests and ten-second
   default query lifetime under normal background work. Record source/image
   identities, actual exits and terminal cleanup. Component tests and offline
   document gates do not complete this installed qualification or all of S-02.
