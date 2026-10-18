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
