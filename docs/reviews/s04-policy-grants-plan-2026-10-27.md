# Policy grants and prepaid sensitive observation

Status: architecture decisions accepted by maintainer through the root coordinator; implementation in progress. No runtime qualification yet.
Scope: S-04 increment 12b, REQ-AUT-003/004/006, SC-AUT-003/004/006,
REQ-EXE-001 and the accepted team-policy authority contract. ADR-259 and migration
00102 are reserved after the packet funding correction and history. Base is fetched main c70ae164; compose merged
PR100 and history migration 00101 before SQL schema work. PR100 remains a separate
frozen candidate and supplies no policy-grant qualification.

## Observed boundary

- `authorization.Grant` and migration 00097 support only `adHocCapture`. They
  require capture/preview/Pod identifiers and bind later use to the human requester.
  Reusing those requirements with invented policy identifiers would be wrong.
- Existing C-09 activation already stores an independently bounded policy executor,
  delegation and sponsoring assignment set. The current implementation admits only
  pod-status recipes. Its preflight constructs `PodUID=WorkloadUID` and temporary
  positive limits to select the envelope; these must not become a grant scope.
- The current recorder compiler binds raw-predicate observation limits: 1 GiB,
  16 MiB/s, one concurrent session, session seconds from the action timeout capped
  at one hour. These are configured ceilings, not measured load.
- `recorder_approval.go` deliberately refuses every approved plan that has those
  limits. Keep that refusal until actual quota enforcement precedes the predicate.
- `packets.Recorder.Add` currently filters before its `WireBytes` increment, and
  that counter describes retained frames only. It cannot meter sensitive input.
- Published Gadget delivery already provides original `packet_size` separately
  from captured payload bytes. The new gate belongs before `rec.Add`, without
  changing the gadget or introducing a packet parser/kernel program.
- Row 6 of [the S-04 plan](s04-plan-2026-10-27.md) owns ongoing policy source/ring
  arming. A policy grant alone must not pretend that arming is implemented.

## Complete first supported workflow

1. A maintainer authors a schema-valid hub-held DebugPolicy with an explicit
   `onTrigger`, `before: 0s` packet composition and finite incident limits. Extend
   the existing compiler for that supported path; retain the field-specific refusal
   for ongoing policy recordings until increment 6. The grant scope is still the
   pinned workload and its authorized future replicas, never one selected Pod.
2. Activation resolves the real namespace/workload, source, delegation, sponsors,
   compiled recipe/filter programs and policy authority. It accepts that exact
   team scope through existing C-09 persistence/audit. Missing sensitive approval
   blocks acquisition; it does not substitute a pod-status capture.
3. The authenticated human/service requests a policy grant for that accepted
   scope, with finite executions, output bytes, observation bytes/events, rate,
   concurrent sessions and expiry within the resolved ceilings. Keep the original
   requester as provenance, separate from `policyExecutor` and `policyAuthority`.
4. A different current human action-approver reviews the exact workload, recipe,
   predicates, authority, budgets and expiry, then uses actual IdP step-up to decide.
   Self-approval compares issuer/subject with the authenticated requester across
   clients, never with the machine policy executor. Workload identities cannot decide.
5. A current team manager attaches the exact approved grant using the existing
   activation/control path. Prefer this explicit action over a new grant-head
   service, automatic newest-grant selection or a cross-role background update.
   Use optional grant_id on activate_policy: an authored grantRef must match
   exactly; absent grantRef permits an explicit runtime attachment, while changing
   an authored reference stops reuse until reconciliation. The immutable SQL control
   receipt is semantic/idempotency state, not durable object audit. Existing public
   activation acknowledges encrypted intent before attachment and records outcome;
   unknown replies/replay preserve the exact attachment. No new audit worker.
   Renewal can be reviewed while the old grant remains attached; attachment does
   not reissue the policy authority or reset any policy counters.
6. On a real incident, the existing policy occurrence executor resolves and checks
   the actual triggering Pod. Admission atomically reserves ordinary capacity and
   grant executions/output/observation credit, with current authority and deadlines.
   The public requester's token or group snapshot is never retained for execution.
7. The connector sends only the admitted command and finite prepaid observation
   lease over the existing authenticated node channel. The node charges every
   original wire byte before evaluating the approved predicate, including frames
   the predicate discards. No byte is processed without live authority and credit.
8. Publication/native download use the existing custody and current-rights paths.
   Policy approval grants no personal resultAccess, raw-query, download or sharing
   right. Inspection still uses the viewer's independent current rights.
9. Exhaustion/revocation/expiry stops sensitive reads and new starts. Independently
   authorized cheap detectors remain usable. A new node/process, pause/resume,
   grantRef edit or repeated request cannot refill either the grant or policy pool.

This is an actual automatic sensitive-packet workflow, including UI and installed
proof. It is not a completed ring/source implementation, HTTP parser, raw output
mode or syscall argument acquisition. Those later mechanisms must consume the
same accounting boundary before being enabled.

## Scope, storage and authority

Use a discriminated grant scope. Keep existing ad hoc validation unchanged.
`policy` requires real policy UID, policy execution digest, executor and exact
policyAuthority (including original issue/expiry and sponsors); capture UID,
preview ID, Pod UID and resultAccess are forbidden. Workload identity consists of
cluster/namespace/workload UIDs. Review names are metadata, not authority.

Add a purpose-specific workload eligibility type/port. Do not relax
`authorization.Target.Valid()` for artifact reads or replace a Pod UID with a
workload UID. Share the existing assignment evaluation and accepted source reads;
perform concrete per-Pod checks again for each incident/source effect.

Factor the recorder recipe/filter compilation used by manual and policy plans;
attach the appropriate owner/target scope afterward. Do not call a manual compiler
with `CaptureID=PolicyUID`. Frozen programs/provenance must agree with the reviewed
policy digest before execution. A source/recipe/authority change requires fresh
acceptance and applicable review; runtime freshness stays outside approval identity.

Extend the purpose-owned grant ledger where common decision/revocation/audit
rules apply, with conditional NULLs for irrelevant target columns. Keep policy
admission and observation facets narrow. Reuse existing SQL duties; any SECURITY
DEFINER helper is fixed-purpose, schema-qualified and EXECUTE-only for its actual
consumer, with the installer role matrix and reversible migration checked.
Policy aggregate spend must also survive grant replacement: a new grant does not
reset the accepted authority's cumulative ceilings.

For policy grants, requester identity is provenance, not perpetual control.
Current team managers/current approvers control attachment and revocation; creator
logout, departure or personal client removal does not revoke independent team
execution. Ad hoc requester behavior is unchanged. Restrict PR100 preview
resume/resolve/original-client hints explicitly to ad hoc grants when adding the
new kind; policy grants get no invented preview or personal continuation action.

## Lifetime and current settings

Reuse the protected installation settings/cache and canonical
[approval-policy fields](../../specs/contracts/approval-policy.schema.json), not a
new watcher, provider credential or configuration service. Proposed initial values
match the existing example: seven-day default, thirty-day maximum, one-day renewal
notice; the configurable upper bound remains 365 days. These defaults are an
implementation choice, not an additional maintainer requirement.

Policy grant `issuedAt` is the immutable original request/issuance time, distinct
from the decision and policyAuthority issue time. Requested notAfter is fixed
there. Approval clamps it to the current effective maximum from that same original
issue time and the original authority expiry. Persist a monotonic effective
expiry overlay; raising a maximum never extends a stored grant. Every new
reservation/lease renewal uses current accepted settings and rechecks after locks.
Sharing/raw-query maxima stay separate. Renewal is an explicit reviewed new grant,
never a timer that changes the original grant or policy authority.

Reuse the existing protected accepted-settings observation model (currently
30 seconds), not raw ConfigMap history. Persist each accepted lower maximum so
all earlier-issued grants clamp irreversibly from their original issuedAt even
when unused during the lower period. Reuse source identity/epoch/audit acceptance;
benign resourceVersion changes do not revoke grants. A raw change-and-revert that
was never accepted is not claimed as processed. This is the maintainer-approved
bounded-observation contract; no new watch/history service is authorized.

## Observation constraint proposal

Maintain separate authoritative reserved/spent counters for executions, output,
observed bytes and optional observed events. Actual node-observed input is a
separate quantity from the conservative hub reservation. Existing retained
`WireBytes` keeps its meaning.

Piggyback cumulative byte-credit extensions onto the current-authority renewal
required for sensitive policy observation. The present metadata recorder has no
per-capture authority-renewal RPC: status/poll/certificate exchanges are different
purposes. Add one renewal operation on the existing private node channel; count
its entire cost, rather than claiming an already-running renewal stream. Use the original session/fence and idempotent sequence, with one outstanding
RPC. Do not add an independent quota-renewal stream or two-slice state machine.
Keep unconsumed existing credit when the remaining parent pool is zero; an authority
renewal does not require a new debit. Unknown possibly-started credit remains
conservatively spent, with no refund protocol.

Derive the initial/extension quantum from the reviewed maximum rate multiplied by
the bounded authority horizon, provisionally covering two selected renewal intervals.
At 16 MiB/s and a five-second interval this would cover 160 MiB for ten seconds;
a full one-hour prepayment at that rate would request 56.25 GiB, whereas a ten-second
session would request the same 160 MiB. Both are capped by actual remaining policy
and grant budgets. Short/no-traffic sessions may consume the entire prepaid tail;
show conservative spend separately from measured input. Measure actual existing
channel cost plus the eventual SQL renewal transaction and interval before fixing
the quantum. One renewal stream
at five seconds implies 40 requests/s for 200 active sources, rather than the rejected
independent 64 MiB credit stream's approximately 90 requests/s combined.

At the node, use the existing serialized frame callback and original wire length
before any filter. Exhaustion/rate/lease failure cancels capture before another
predicate evaluation; no unchecked fallback. Renewal uses current trusted policy,
grant, source and node identity, is bounded by the original session end and grant
expiry, and never resets byte/event counters. If freshness makes the lease shorter
than the capture, renew it over the existing private channel, retaining those
original bounds. Reused credit can renew authority while its pool has no *new*
credit remaining; renewal must not mistake its own reserved bytes for exhaustion.

One session row can hold the cumulative allocated ceiling and sequence. Bound
active rows by reviewed concurrency and the existing default ceiling of 64.
Finalize/expire reserved credit conservatively, retain aggregate spend, and move
completed receipts to existing immutable audit before bounded retirement. Expiry
may free an authority slot but cannot refund bytes or revive the old session.

The packet rule charges wire bytes, not retained/truncated bytes. Keep an explicit
accounting-rule/adapter digest. Canonical `maxObservedEvents` and its counters are
preserved for future syscall arguments, but no callback after a user-memory read
can qualify the required before-read charge. Keep argument acquisition unavailable
until a published gadget/qualified adapter can enforce that boundary. No custom
kernel/eBPF program or hand-written packet parser is proposed.

Before lifting the raw-predicate guard, qualify captured-prefix/read bounds too:
the current gadget adapter captures at most 1500 bytes while the compiler pins a
65,535-byte filter snapshot. A grant cannot make an unqualified payload-offset
predicate exact. Supported bounded filters must pass actual compiler/engine tests;
unsupported inspection must retain a clear refusal rather than silent false
matches or an unmeasured larger capture buffer.

## Complexity gate

| # | Answer |
|---|---|
| 1 | Observed missing path: every raw predicate stays RecorderUnavailable; policy compiler refuses compositions. Required product feature, not measured incident frequency. Existing WireBytes excludes filtered input. |
| 2 | Accepted: all first-release specification features, independent policy execution, bounded sensitive observation and no refill. No new security requirement. |
| 3 | Applies to every sensitive policy/recorder and admin-required policy approval; ordinary metadata remains unchanged. |
| 4 | Reuse Asservat's existing SQL reservation, current authority and unknown-spend mechanisms. Envoy RLQS documents server quota assignments with TTL and usage reporting; this is precedent for bounded assignment, not a dependency or evidence that its fallback behavior fits Asservat. |
| 5 | Zero collector SQL/KMS/object credentials, extra listener, privileged workload role or custom kernel/parser. Existing hub duties gain narrow grant/slice operations; exact installer privileges need native qualification. |
| 6 | Existing grant phases plus explicit exhaustion/source stop. No automatic approval renewal, best-effort permission fallback or refund state machine. Waiting credit is bounded by the original lease. |
| 7 | Only required approval period and reviewed grant budgets. No watch tuning, retry-disable or collector machinery configuration. Rate-times-authority-horizon credit is internal and must pay for its measured cost. |
| 8 | Existing PostgreSQL/Kubernetes/IdP/Gadget and private TLS channels; upstream before-read support remains a real blocker for syscall arguments, not an assumed capability. |
| 9 | Per packet: local counter/rate/lease checks, no allocation or network call intended; benchmark actual ns/allocations. One required sensitive-authority renewal carries credit too: a hypothetical five-second lease at 200 sources means 40 new requests/s total, with no additional quota-only stream. Measure the current combined path before choosing the rate-times-horizon credit quantum. No added watches. |
| 10 | Additive conditional grant migration with tested Down and no conversion of old scopes. Disable new sensitive activations without disabling cleanup/current metadata. No spent-counter reset on rollback/restart. |
| 11 | Explicit onTrigger policy execution avoids prematurely building ongoing arming/rings. Explicit approved-grant attachment avoids a new grant-head controller. Prepaid slices avoid per-packet hub I/O; conservative tail charging avoids a refund protocol. Do not substitute pod-status or foundation-only tests for the real sensitive workflow. |

[Envoy's primary quota documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rate_limit_quota_filter)
confirms assignments, TTL and reports. Asservat must deny sensitive processing
without an assignment or after expiry; it does not adopt Envoy's optional fallback
behavior or install Envoy/RLQS.

## Public/UI contract and proof

- Request/attach policy approval through the existing policy workflow and typed
  public operations. Approval detail shows policy/team execution, all future
  budgets, original/effective expiry and independent requester/reviewer. No human
  capture resume or resultAccess is offered for this kind.
- Policy status distinguishes detector monitoring, approval availability and
  acquisition/source readiness. Show reserved/conservatively spent input separately
  from actual reported input and retained output. Source implementation gaps are
  explicit. Renew/attach controls require the current manager, not a historical creator.
- Before production edits, reproduce missing policy-kind/observation behavior in
  meaningful tests. Unit/race: typed target/identity separation, cross-client
  self-review, lifetime clamp/raise/replay, before-predicate charge with zero
  matches, rate/session/concurrency bounds and cancellation/lease renewal.
- SQL/S3: atomic capacity+grant debit, concurrent node/replica spend, duplicate
  reservation/renewal replies, revoked/expired grant and source races after locks,
  original issue/expiry, no grantRef/authority counter refill, roles and Down/Up.
- Native collector: published gadget, positive capture plus a predicate retaining
  zero frames while real wire input exhausts a scaled *publicly reviewed* budget;
  actual authority renewal, no processing after expiry/revocation, node restart
  without refill. No knob that mutates immutable plans or bypasses real authority.
- Installed focus: real Kubernetes policy/source/delegation; public request,
  distinct signed Keycloak step-up reviewer; actual automatic packet occurrence,
  encrypted publication/native PCAPNG, policy budget/status and refusal after
  exhausted/revoked authority. Reuse PR100's real helpers and independently current
  rights. A small reviewed grant is product configuration, not a test-only meter.
- Freeze final sources and run the affected repository/role/custody gates before
  one agreed native campaign. Every job stays within 20 minutes; record actual
  full elapsed time, source hashes and cleanup. No collector runs locally.

Expected files: domain/application authorization grants and automation; C-09
policy compiler/activation/trigger/identity; shared recorder planning and context
admission; purpose SQL queries/migration/role facets; private node/connector work
contracts and packet callback; protected settings DTO/schema/installer/chart input;
policy/approval operations/OpenAPI/MCP/React controls; focused tests and native
fixtures. Coordinate shared history/admission files and generated schema head
before edits. No migration or API behavior is implemented by this proposal.


## Implementation checkpoint (in progress)

The isolated policy-grants branch now has discriminated policy scope validation,
original-issue/pending deadline overlay rules, typed workload permission projection,
request/review/revocation service paths, shared transport composition conversion,
shared profile/filter normalization and inert finite policy recorder compilation.
Existing manual network/syscall scope hashes match the original compiler. A local
serialized input meter charges wire length before predicate dispatch and rejects
credit/rate/lease overrun without changing observed counters on a refusal.
On this local Ryzen 7 5700X3D, the initial provided-timestamp microbenchmark
measured 23.92 ns/frame; the later same-domain sample measured 16.19 ns/frame and
51.76 ns/frame including `time.Now`, all zero bytes/allocations per frame. These
are local synthetic meter costs, not collector throughput or installed overhead.
Channel, SQL and aggregate callback costs still need measurement.

Protected policy-period DTO/schema/reader plumbing preserves absent defaults and
copies the cached value. These changes are not wired into production grant
projection, policy activation/attachment, admission, node renewal or UI yet. The
raw-predicate refusal is retained. No policy-grant migration, hosted test or
installed policy/observation qualification exists at this checkpoint. Continue the
full workflow, including source/acceptance compatibility, SQL and native proofs.

## Accepted settings clamp: measured simpler alternative

Maintainer decision after the numeric comparison: use one indexed set-based
monotonic SQL clamp when accepting a lower effective policy-grant maximum. Do
not add revision history, read-time replay, pruning, paging checkpoints or a
new reconciliation service. Accept the protected settings projection and clamp
all affected pending and approved older grants atomically. Derive every lower
deadline from immutable RequestedAt (the policy grant's original issued anchor);
a later raise never extends that persisted deadline. A failed transaction
publishes neither a new accepted projection nor a partially clamped grant set.
The existing loop may retry the same observation within its original bounds.
Unobserved ConfigMap ABA changes are not claimed as processed.

There is no enforced global grant-row ceiling. The separate specification's
64 value limits concurrent reservations within a grant. One accepted settings
change per day is an explicit workload assumption, not observed deployment data.
The 3,200-row scenario assumes 100 clusters × 16 policies × two grant rows;
pending renewals can exceed it, so it is not a product cap.

The isolated PostgreSQL 18.6 comparison used two CPUs, 768 MiB, 64 MiB shared
buffers, fsync and synchronous_commit enabled, an indexed synthetic table with
256-byte payloads and a simple monotonic trigger. Each scenario had three
paired actual UPDATE samples. Both methods verified pending and approved
original-anchor clamping. Median database execution/commit times:

| Active rows | Expired retained rows | One set UPDATE | 64-row committed pages | Commits/pages |
| --- | --- | --- | --- | --- |
| 64 | 0 | 1.026 ms | 5.362 ms | 1 |
| 3,200 | 0 | 18.917 ms | 197.653 ms | 50 |
| 10,000 | 0 | 61.413 ms | 641.941 ms | 157 |
| 100,000 | 0 | 786.484 ms | 7,132.902 ms | 1,563 |
| 64 | 100,000 | 2.024 ms | 12.938 ms | 1 |

The 100,000-row set samples ranged 728.534–1,885.476 ms. PostgreSQL chose a
sequential scan when all rows matched, and an index scan for 64 live among
100,000 expired rows. At an assumed one page per existing one-second loop,
1,563 pages would require about 26 minutes; that cadence was calculated, not
slept through. Docker command/setup time is excluded from database times and
is retained separately in the report. These measurements cover synthetic SQL
only, not the final grant schema, lock contention or a production scale claim.
At the assumed one change/day, the measured set cost does not justify the extra
history/read path or a partially applied clamp state. Existing bounded operation
and transaction deadlines still apply; beyond the measured bound, failure must
leave acceptance unchanged rather than inventing an unbounded grant-row cap.

Corrected benchmark exit 0 in 67.629 seconds, all 15 paired samples, no cleanup
failures; owned container and volume independently absent. Report SHA-256
`3eeee0bd2eb578b7ee9ecfdfb20493999e0a2ea7a88dab26bfbb009b969922c7`.
Two prior attempts failed (non-keyset page cost and temporary-init-server
readiness) and are retained separately; they are not successful measurements.


## Original-request replay and settings supervision

A policy-grant request first performs one indexed lookup in the existing immutable
request row, scoped to the full authenticated actor (issuer, subject, client and
kind), idempotency key and canonical caller-input digest. The digest includes the
original explicit lifetime choice, including zero for the then-current default,
and reviewed budgets. An acknowledged retry returns the frozen request even if
current defaults change or the plan reader is unavailable; it never creates a new
grant, extends a deadline or refills spend. Changed caller choices conflict.
Current workload rights and final identity bounds precede returning metadata.
The immutable scope also stores the original approval maximum alongside its
settings revision, binding it and the resolved recipe digest in the review digest. Public maxAgeSeconds can be
rendered from that frozen value without settings history; later lower maxima
remain a separate monotonic deadline overlay. The persisted accepted lower-maximum
overlay still applies on replay. No table,
credential, public operation or additional background work is added for recovery.

The maintainer accepted one joined child of the existing permission worker for
settings observations, using its existing protected identity client/credential.
The ten-second cache-driven cadence adds at most 0.3 Kubernetes GET/s per
installation (the existing three-source proof), not per workload, and one SQL
acceptance per new cached observation (about ten seconds), plus the measured
set-based clamp only for accepted lower changes. Cached source reads retain their
original timestamps. The client releases its lock during API work, shares pending
refreshes and serves valid cached observations without waiting for a pending
refresh outside its existing safety margin. No watcher, configuration or separate
client is added. A bounded source/SQL failure only expires policy-grant availability;
it cannot stop permission/browser loops. Parent cancellation joins the observer's
original bounded request. This observer and SQL effects remain unwired until the
00100/00101/00102 schema sequence is composed and qualified.


Static Gadget review confirms the pinned tcpdump config exposes `snaplen` as a
maximum-byte parameter; v0.57.0 source declares a uint16 constant with default 1500
and appends packet bytes through perf-event context output, rather than a fixed
1500-byte packet array. That parameter type is not proof that 65535 is usable:
Linux perf record headers have a 16-bit total size including event metadata and
alignment. The current adapter's 1500 guard therefore remains while effective
published sample bounds and compiler byte-access assumptions are investigated.
Sources: [published v0.57.0 program](https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.57.0/gadgets/tcpdump/program.bpf.c),
[Linux perf record layout](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/perf_event.h),
and [perf output implementation](https://github.com/torvalds/linux/blob/v6.18/kernel/events/core.c).
This is source evidence, not a native jumbo-packet qualification or a new product
restriction. No Gadget program or host kernel is changed for this investigation.


### Pending SQL 00102 replay compatibility check

The current 00097 request uniqueness/read key is root+issuer+subject+idempotency key;
client is stored but not part of that key. Policy requests need the full principal
(including client and kind) as agreed above. Keep legacy ad hoc key semantics
separate; do not silently alias a policy request from another client. Assess the
actual 00101 schema before generating 00102. A fixed-size hash of an unambiguous
length-prefixed actor encoding can index the existing actor columns plus key;
the read must still match the full actor columns and original caller-input digest.
This avoids relying on a wide B-tree key for the maximum issuer/subject/client
strings and adds no table or principal service. Hash collision may refuse a request
but must never return another actor's row.

Old binaries use the old nondiscriminated lookup and cannot interpret policy grant
rows. The migration compatibility floor must refuse such binaries if the final 00102
layout admits multiple full-client keys that the old query would conflate. Down
must refuse when surviving rows cannot satisfy the old unique key; it must never
delete a reviewed grant or rewrite its idempotency key to force rollback. This is
a pending migration design check, not implemented SQL or a tested upgrade claim.


## Source review corrections before SQL composition

Policy revocation evaluates the returned workload projection against the grant's
expected workload, never against the returned projection's self-selected target.
This corrects one argument in the existing read/evaluator path: zero added reads,
credentials, watches or state. A wrong-target projection now refuses without
calling grant mutation.

Recorder collection scope explicitly projects collection fields. Sharing and
grantRef stay separate controls; changing recipients, sharing deadline or sharing
capture count cannot reissue collection authority or reset its accepted spend.
The activation regression observes that no second acceptance is dispatched and
original issue/expiry, authority and modeled counters remain. SQL spend preservation
is not qualified by this unit test. Activation replay returns the existing sharing
instruction, not the newly authored control; separately authorized sharing control
composition remains required before the complete workflow is enabled.

Policy requester Get/requested-list require current CollectContext on the exact
workload. Historical requester provenance is insufficient: absent/denied/wrong
or unavailable rights yield NotFound or an omitted row. Independent current
approvers keep their existing ApproveAction view. Ad hoc requester visibility is
unchanged. Service identities match the entire original principal/client; same-human
metadata across clients never changes full-client request idempotency.

This adds one current workload read per policy Get and at most one per distinct
workload in a bounded list (existing maximum 100 candidate rows), using the existing
request-local result map. The existing final identity read now reuses C03's canonical
identity comparison for visible policy metadata; changed groups/scopes/policy and
expired original bounds refuse delivery. No extra final identity read, background
cache, watcher, configuration or credential is added. Tests cover departed groups,
current denies, unavailable/wrong projections, expiry after blocking reads, service
client separation, one read for multiple grants on one workload, and unchanged
ad hoc/current-approver behavior. Policy scope/period/max/recipe and original request
journal recovery remain frozen; SQL 00102/public/node/bootstrap are still unwired.
