# Policy grants and prepaid sensitive observation

Status: architecture decisions accepted by maintainer through the root coordinator; implementation in progress. No runtime qualification yet.
Scope: S-04 increment 12b, REQ-AUT-003/004/006, SC-AUT-003/004/006,
REQ-EXE-001 and the accepted team-policy authority contract. ADR-259 and migration
00102 follows packet funding 00100 and history 00101. Local composition
`822e79b5` now includes the reviewed history cc2 and approved-recording 218 source;
SQL implementation on that local schema 101 base is authorized. Canonical PR100/main
composition remains required before publication or an installed campaign. PR100
supplies no policy-grant qualification.

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
| 9 | Per packet: local counter/rate/lease checks, no allocation or network call intended; benchmark actual ns/allocations. One required sensitive-authority renewal carries credit too: a hypothetical five-second lease at 200 sources means 40 logical renewals/s, with node→connector and connector→hub RPC legs counted separately and no additional quota-only stream. Measure the current combined path before choosing the rate-times-horizon credit quantum. No added watches. |
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

## Migration 00102: reviewed composition and SQL plan

Base: local merge `822e79b5` composes history
`cc2ccae0b73fc7179a296f529e9aa8ae583ab547`, with approved-recording
`21806d0d2612d33bb039b6daf2971849796a999d` independently verified as an ancestor.
Packet funding remains 00100, encrypted history 00101, policy grants 00102.
Later 100 diagnostics are intentionally excluded until their canonical result.
The one code conflict preserved both current policy metadata rights and ad hoc
continuation hints; policy grants explicitly offer no personal resume/resolve.
At that merge checkpoint no SQL 00102 file or runtime/public/node wiring existed.
The source-only SQL draft below is now being implemented; runtime/public/node
wiring remains absent.

1. Extend the existing AccessGrant row with a closed discriminated policy shape.
   Preserve legacy ad hoc required preview/capture/Pod IDs, human requester,
   decision-anchored eight-hour maximum and result-access pools. Policy grants
   instead require real workload/policy identity, authenticated human/service
   requester kind, frozen accepted authority/scope/recipe/original maximum,
   original RequestedAt anchor and separate finite execution/output/observation
   spend. Forbid fake preview/capture/Pod IDs and all personal result access.
   Resolve current accepted execution by collection identity/intent version,
   not equality to every latest whole-source resourceVersion/spec revision.
   Keep original source/acceptance provenance immutable.

2. Keep the request journal in that existing grant row, separate from encrypted
   operation audit. Preserve the old partial ad hoc uniqueness/read semantics.
   Policy request keys include root, full issuer/subject/client/kind and closed
   operation plus idempotency key; use a fixed-size unambiguous actor digest for
   the index and recheck all full fields and caller-input digest. Lookup precedes
   current plan/default resolution. Original lifetime-zero/default choice,
   scope/max/recipe, periods and spent pools survive lost replies/replay.
   Hash collision can refuse, never alias another request. No new journal table.

3. Add a protected policy-period projection distinct from browser settings and
   their five-second lifecycle. The already reviewed ten-second joined observer
   accepts an original bounded protected observation. Publish it and apply any
   lower maximum to all older pending/approved policy grants in one transaction,
   using indexed set-based min(existing, RequestedAt+maxAge). Later raises never
   extend earlier deadlines. Approved historical rows remain valid records when
   a later clamp moves effective expiry before DecisionAt; new approval after
   effective expiry refuses. No revision history, paging machinery, invented
   global grant cap or unseen raw ConfigMap ABA guarantee.

4. Reserve policy grant and accepted-authority shared spend atomically under
   existing current recovery/delegation/source guards and lock order. Replays,
   restart, grant replacement and attachment cannot refill either aggregate.
   Unknown possibly-started effects remain charged. New admission resolves a
   real current Pod of the reviewed workload; no grant lifetime follows the
   historical requester's login. Current requester metadata rights stay separate.
   Add only the durable session/fence/sequence state needed for cumulative
   observation credit on the required authority renewal; do not add a quota-only
   renewal stream or fix its quantum before composed cost measurement.

5. Persist explicit attachment control receipts on the existing activate-policy
   boundary. They are semantic/idempotency state, not durable object audit:
   encrypted intent must already be acknowledged before mutation, with the
   existing outcome/replay handling. Bind exact original acceptance/grant and
   current authored grantRef; no newest-grant selection or Kubernetes writes.
   Do not let sharing/control-only changes replace accepted authority or spend.
   Separate authorized sharing control remains an explicit workflow dependency.

6. Update only necessary closed role facets, SQL queries/generated models and
   installer schema inventory. Reuse existing credentials and protected source
   producer; record any narrow added SQL execution privilege explicitly. Raise
   the binary compatibility floor to 102 because older grant readers conflate
   the new kinds/client keys. Up validates old rows before changing constraints.
   Down refuses incompatible policy/session/attachment survivors or old-key
   collisions; it never deletes/rekeys grants, refunds uncertainty or resets
   spend to force rollback. Keep the old ad hoc contract exactly testable.

Before any local external run, coordinate the owned fixture slot with root,
freeze all relevant sources, retain actual selected tests/exits, source hashes
and terminal cleanup, and cap the run at twenty minutes. No collector locally.
Planned real PostgreSQL cases (new test names will be added with implementation):
conditional row negatives and role denial; same-key full-client/operation
separation plus exact lost replies/default changes; requester/independent reviewer
versus policy executor; current-scope/refusal after lock waits; pending and
approved original-anchor lower/raise including expiry before historical decision;
concurrent grant/policy spend and revocation, restart and attachment no-refill;
Up/Down/floor and incompatible-survivor refusal. Reuse the existing
`TestContextAdmissionWithRealServices/access-grant-approval-children-pool-revocation-and-expiry`
regression (parent and subtest verified in source), plus affected purpose/installer
roles. `scripts/test-custody.py --run` is the existing bounded targeted runner;
new policy test selectors are not claimed to exist yet. Run sql-check and affected
Go/race/spec/architecture gates before qualification. No public runtime wiring or
hosted campaign until SQL review and real SQL gates pass.


Public-composition follow-up: a current sponsoring team manager who may attach or
revoke must be able to inspect the attached grant's finite state/expiry after the
original requester leaves. Existing nonrequester Get is approver-only; decide a
minimal current-manager view when composing those controls, without a grant-head
service or broader collection/disclosure authority. This does not block SQL scope.


### SQL draft smoke checkpoint

The schema-102 draft now has conditional workload-grant rows, original full-actor
request keys, accepted-settings storage and atomic lower-period clamping. It adds
immutable explicit attachment receipts and cumulative session/fence/sequence row
shapes, but their accounting/activation composition is not implemented or qualified.
The raw-predicate refusal remains. The targeted first owned PostgreSQL/S3 smoke
checks actual migration syntax, historical ad hoc Up/Down, incompatible-survivor
refusal and the request/settings component under compiled SQL roles; it is not
final schema-102 or public/executor/collector qualification.

No new credentials, Kubernetes permissions, network requests, watchers or timers
are added by these SQL adapters. The existing permission-accept credential gains
settings read/write, root-lock UPDATE(id), five grant metadata SELECT columns and
UPDATE(policy_not_after,expires_at), with the trigger limiting that update to a
monotonic overlay. It cannot inspect review/scope payloads, decide or refill spend.
The existing hub grant duty reads the accepted source/settings under its root lock.
Original observation endpoints are rounded down to PostgreSQL microseconds,
never extended. The compatibility floor is 102; a compatible Down restores 81,
while policy/session/attachment survivors refuse rollback without deletion/refund.
The simple set-based clamp retains the earlier measured complexity decision; no
revision history or new global row ceiling is introduced.


Smoke 1 (`07ad950c`) failed before Go tests during migration: PostgreSQL refused
its generated requester-key expression as non-immutable (42P17). Both owned
containers were removed; unchanged sources and cleanup were independently checked.
No test or role qualification resulted. Report SHA-256
`a8605c8a3575a1ef7a39179ae66f8d2448200f4e3edaf3f6abc6d1259f010fc3`.

The correction uses an ordinary nullable policy-only actor-key column, no legacy
backfill, extension or IMMUTABLE wrapper. The existing INSERT computes its key
from four explicit UTF-8 strings with network-order byte-length prefixes; a
conditional CHECK independently requires that same canonical key. Go computes
the lookup key with the same byte encoding and rechecks the full actor/input.
A multibyte golden is exercised in both languages; boundary/client/kind changes
remain distinct and caller-selected mismatches must refuse. Attachment keys use
an ordinary insertion-checked column too. Actual CHECK behavior remains pending
another coordinated owned SQL run; generation/unit passes alone do not prove it.


Smoke 2 (`fa5d053b`) passed the ordinary key-definition stage, then failed before
Go tests while compiling the new grant trigger (42601): PL/pgSQL parsed an
unparenthesized CASE inside an IF comparison as an incomplete condition. The
correction explicitly groups that CASE; other new IF expressions were reviewed.
No data/check/role proof resulted. Report SHA-256
`7ab5b1df971dcc4ab113791634a5d33ba5c3cd35af87c9c94c5a3f6b0c268961`,
unchanged sources, no cleanup failures, and both owned containers absent.


Smoke 3 (`1a5ee7ee`) passed the actual schema-101→102 Up/compatible Down/reapply
case (2.19 seconds). The catalog confirmed `textsend`/`convert_to` are STABLE,
`int4send`/`sha256` IMMUTABLE. The policy case failed during its existing synthetic
source setup: `policy_source_runtime`'s fixture-only column list omitted the new
`authored_grant_ref` (42501). Production compiled policy-source grants already
include it. The correction adds only that exact fixture INSERT/UPDATE column.
No request/settings data or Unicode/check proof resulted yet; group exit 1,
Go test 3.879 seconds (runner phase 59.802 including race compilation), unchanged
sources, cleanup empty, containers absent. Report SHA-256
`20f4186fb34e8f9ad310f6b53db891d03023e0f3f5a6e24db09abd8c6ee4efdd`.


Smoke 4 (`56e132a4`) passed the selected real PostgreSQL/S3 request/settings
case: `TestPermissionAuthorityPoliciesWithRealServices/policy-grants-original-request-periods-and-client-journal`
(3.32 seconds; Go 5.838 seconds; runner phase 8.926 seconds), exit 0,
unchanged 3,244 source hashes and no cleanup failures. It qualifies conditional
rows, full-client/Unicode journal lookup, original-anchor lower/raise and refusal
of unsafe rollback for that source snapshot, with synthetic protected identities
and authority inputs. It does not qualify attachment or execution accounting.
Report SHA-256
`2e3c1c40fda99e051e7a8d533347ddd6e632bda29cd769b470fd3bb554e396c6`.
The archived report and Go log are under the local build cache's
`approved-workflow/policy102-smoke-4-artifacts/` directory.

The next source batch adds an unwired attachment store on the existing
`policy-automation` SQL duty. Recovery → permission root → source → grant locks
serialize the control against source changes and review/revocation. A fresh
current sponsoring manager is checked for both new control and historical reply;
creator/requester identity is not management authority. The full actor/client/key
and original policy/grant input identify an immutable reply. Replay returns its
old receipt without restoring a cleared source pointer. Accepted authored-grantRef
changes clear that pointer, so A → B → A needs another explicit control; an
unchanged reference preserves it. No acceptance, expiry or spent counter changes.
The existing duty gains full access_grant SELECT, attachment SELECT/INSERT,
grant UPDATE(id) solely for row locking (the immutable trigger refuses ID
changes), and source UPDATE(grant_attachment_id). The full SELECT reuses the
existing locked grant decoder and all conditional immutable-field checks; a
partial reader would introduce a second verification path. The ordinary
hub-runtime role union already has full grant SELECT through its grant duty,
but the standalone policy-automation duty now reads that additional metadata. There are no new credentials, provider requests,
watches, timers or background tasks. The public activate_policy encrypted-intent
acknowledgement/outcome boundary remains unwired; this store is not independently
public execution authority. Real role-bounded attachment/ABA/replay qualification
is pending the next coordinated frozen-source run.


Attachment source gates (not SQL behavior qualification): sql-check passed with
62 generated-query files; targeted race checks passed for domain authorization
1.010s, application authorization 1.031s and PostgreSQL adapter 1.073s. The
integration package compiled and its external cases skipped without fixture opt-in
(1.072s); no real attachment behavior is inferred from that result. spec-check
passed 13,284 assertions, architecture-check 1,326 positive checks and Go
architecture 67 packages/393 imports. The first spec invocation used the system
Python without development dependencies and failed; the retained second run uses
the existing canonical spec virtual environment and passed. Actual role/ABA
cases remain pending a frozen-source PostgreSQL/S3 run.


Attachment smoke 1 (`b17c4c50`) passed the expanded selected real PostgreSQL/S3
case (subtest 3.44s; Go 5.905s; runner phase 8.676s), runner and qualification
exit 0. All 3,247 source hashes matched, sources were unchanged during the run,
cleanup failures were empty, and both exact owned containers were absent.
Report SHA-256
`640ccbc0ed808d2d823b1845f16a97da39d28f1e3b1f86289ad0204d5ce48508`;
report/log archived under
`approved-workflow/policy102-attachment-smoke-1-artifacts/` in the local build
cache. This proves the role-bounded current-manager attachment, full-client
journal/conflict, immutable reply and accepted-source A → B → A clearing cases,
with synthetic protected identity/authority inputs. It does not qualify the
public encrypted-intent boundary, node execution, or cumulative accounting.
The earlier smoke-4 evidence remains bound only to `56e132a4`.


### Occurrence-backed capture accounting batch

Observed gap: current real trigger code spends one accepted execution before
creating a policy_occurrence, but capture admission spends neither grant output
nor accepted output. Every recurring collection uses this typical path; repeated
accepted captures can therefore multiply the finite reviewed output allowance.
This is an accepted product guarantee, not a speculative extra security check.
Reuse that existing occurrence for the charge identity: add an immutable reserved
capture/grant/output tuple, rather than another journal/table or generic budget
service. Existing context_capture idempotent lookup runs before new charging.
Require an actual pending occurrence of the exact current acceptance and real
Pod; its already spent accepted execution is never incremented again. The
admission transaction atomically creates the capture, increments accepted output
and, when attached, grant execution/output, then freezes the original tuple.
All effects roll back together on refusal. Lost commit replies recover the same
capture; restart, attachment/grant replacement and source control/share edits do
not alter old tuples or refund output. Unknown started effects stay reserved.

Budget output by the existing native plan ceiling: 4,096 bytes for pod status or
the frozen recorder's bounded MaxBytes, currently at most 8 MiB. These are retained
native output ceilings, not pre-filter observation bytes. Grant/acceptance original
expiry, current source/delegation/denies/recovery and concrete Pod remain binding.
A policy requiring review needs an explicit exact current attachment; never find
the newest grant or borrow the human requester. Unreviewed context policies still
consume their accepted aggregate output. Ongoing packet/syscall observation
credit/session/fence and all-before-filter accounting are separate pending work.

Numeric cost: zero new services, tables, credentials, remote provider calls or
connections, watches, background tasks or configuration. SQL Query/Exec calls
are database round trips. Each new policy capture adds a source lock, accepted
read and occurrence lock; an attachment adds receipt and grant reads. Existing
clock queries bound those reads. Charging adds one accepted output UPDATE, one
occurrence UPDATE and at most one grant UPDATE. Final exact round-trip counts
will include database-time reads. No per-payload/chunk accounting. Existing root lock
serializes source/control/revocation; lock source then occurrence/optional grant
before storage/evidence locks. Exact counts are reviewed again against the final
code. No global grant/occurrence ceiling is added. Down refuses a reserved tuple
or nonzero accepted output, never deletes rows or refunds to force rollback.
Public activation attachment/audit and ongoing-source integration remain explicit
requirements; SQL admission does not stand in for those workflows.


Composing a changed accepted scope also clears its old attachment in the existing
ActivatePolicyAcceptance UPDATE; unchanged accepted scope retains the pointer.
A newly accepted collection scope cannot inherit an old grant's approval. This
adds the pointer column to the existing acceptor UPDATE privilege and fixture;
it adds no request. The context-admit SQL duty gains reads of the occurrence,
attachment and complete grant metadata, source UPDATE(policy_uid) solely for row
locking, occurrence UPDATE of the three reservation fields, accepted-output
UPDATE and grant execution/output UPDATE. The ordinary installed hub union
already owns those source/grant reads; standalone capture-admit now has that
additional SQL access. Existing immutable/monotonic triggers still constrain
all writes. Explicit current eligibility/recovery/expiry checks remain mandatory.


Independent review found an upgrade refill in the new counters' DEFAULT 0:
legacy trigger executions/occurrences may already have collected or possibly
started work. Up now conservatively fills both pools to the ORIGINAL authored
maxima whenever executions_spent is positive OR any occurrence exists, including
pending/refused/unlinked NULL capture replies. This is unknown conservative
spend, never a measured byte count. Pristine scopes with neither signal remain
zero and usable. Cost is one set-based UPDATE with an acceptance scan and
occurrence membership set, O(acceptances + occurrences), during the existing
migration transaction; no runtime work, parser, provider lookup or new state.
Exact backfill from retained artifacts cannot establish all uncertain effects;
adding historical reconstruction machinery has weaker value than this fence.
Previously spent legacy scopes intentionally cannot start further collection.
Restoring capacity requires explicit reauthorization/renewal under a supported
lifecycle; same-intent recurring renewal is not implemented here, and cosmetic
scope edits are not a reset mechanism. Down refuses these preserved nonzero
pools rather than discard uncertainty. The schema-101 migration test now covers
spent executions, unknown open occurrences and pristine scope with distinct SQL
fixtures; it does not claim recovered exact historical output evidence.


Mode check: ADR-249 items 2 and specs/authorization.md REQ-AUT-006 distinguish
payload-sensitive rawBytePredicate observation from the administrator's optional
recordingApprovalRequired on ordinary sanitized networkHeaders. The latter
requires review but carries no sensitive observationLimits. Reuse the existing
AcceptableRecorder/RecordingForContext gate: any raw predicate with observation
limits stays RecorderUnavailable, and unsupported raw/HTTP/syscall argument
profiles remain unsupported. No new blanket recorder refusal is introduced.
This batch reserves output for the bounded on-trigger packet capture supported
by that existing gate. It does not establish ongoing source arming/session credit;
zero observed-byte authority must not be described as permitting a continuing
source. Genuine ongoing packet/syscall policy support remains planned.

Final accounting SQL cost: the new capture-only lock helper adds five database
round trips without an attached grant (source lock, two database clocks, accepted
read and exact occurrence lock), or eight with one (receipt, grant lock and one
more clock). Charging adds two UPDATEs, or three with grant spend. Final checks
reuse existing database clock results. Each later original-policy effect check
adds three reads/clocks without a grant or five with one. No work occurs per
packet/payload/chunk. Those original grant checks prevent replacing an attachment
from transferring an old possibly started capture to new approval or spend.
The existing api-execution SQL duty gains source/occurrence/grant SELECT and
UPDATE(access_grant.id) for row locking only; no grant counter/decision writes.
The hub union already owns those reads, but standalone purpose grants are
explicitly expanded and their exact-grant test updated.


Accounting source verification before the batched real-service run: integration
package compiles; targeted domain/application authorization, capture and PostgreSQL
race checks pass (1.014s/1.254s/1.186s/1.079s respectively), sql-check passes,
spec-check passes 13,284 assertions, architecture-check 1,326 and Go architecture
67 packages/393 imports. Real SQL regression scope is the revised 101→102
historical uncertainty/pristine migration case, the existing request/settings/
attachment case and actual policy-executor capture admission with a four-capture
attached grant, replay/restart and refused fifth occurrence. These new accounting
cases are pending; no executed RED/GREEN claim is made for them yet.


Accounting smoke 1 (`da522a48`) failed overall (Go 10.063s; runner phase
40.678s; exit 1). Request/settings/attachment passed (3.25s), and the actual
schema-101→102 conservative historical/pristine migration test passed (2.93s),
including the production output-spend query refusal and unsafe Down refusal.
The policy-share/accounting case failed during new synthetic fixture setup:
WritePolicyGrantSettings returned PostgreSQL 42501 under hub-runtime, which
correctly cannot accept its own protected ceilings. Fix the fixture to use the
existing permission-accept purpose for that projection, as the earlier qualified
request/settings fixture already does; no production privilege is broadened.
No accounting admission was exercised. All 3,249 source hashes matched,
unchanged sources, cleanup empty and both exact owned containers absent.
Report SHA-256
`1daaba87f88519326eef98ac935fecba2f093c61b09738a99b29b66deaf5617c`,
archived with actual Go/provider logs under
`approved-workflow/policy102-accounting-smoke-1-artifacts/` in the local build
cache. Preserve the passing unchanged migration/attachment evidence; retry only
the concrete failed policy-share component after fixture correction and gates.


Accounting smoke 2 (`ef5a211d`) failed overall before capture admission:
settings acceptance passed under its separate duty, then the new fixture's grant
scope bytes did not hash to its synthetic accepted authority digest. PostgreSQL
correctly refused access_grant_check; the digest CHECK is unchanged. Go 2.805s,
selected child 2.35s, runner phase 22.048s, exit 1; unchanged 3,249 source hashes,
cleanup empty and both exact owned containers absent. Report SHA-256
`b51ca1afff2ab5018143b0e3866870fbc34d319bef250df8bb404fc34d5267f6`,
archived under `approved-workflow/policy102-accounting-smoke-2-artifacts/`.
The fixture correction builds one synthetic collection-scope document before
acceptance, hashes those exact bytes into authority and passes those same bytes
to the grant. It checks the domain blueprint and review hash before SQL and uses
the real typed caller-input digest. The second accepted fixture version explicitly
changes source collection intent; a sharing-only edit never reauthorizes or resets
collection budgets. These remain synthetic authority inputs to real SQL, not
production compiler/identity qualification. No product check or privilege changes.


Accounting smoke 3 (`be38a13e`) failed overall later in the fixture: it derived
synthetic Pod restart ordinals from per-acceptance execution counts. The second
accepted scope reused ordinal 1 of the same real resolved Pod; PostgreSQL
correctly refused policy_occurrence_root_id_policy_uid_pod_uid_restarts_key
(23505). Actual Tick retains the Pod's monotonic restart counter across accepted
scope changes. The fixture now keeps one monotonic ordinal across acceptances;
the product occurrence key, deduplication and all counters remain unchanged.
The first four captures, replay/restart and refused-fifth assertions were reached
before the later failure, but the selected subtest is still FAIL, not a completed
accounting qualification. Go 4.843s, child 4.39s, runner phase 23.703s, exit 1;
unchanged 3,249 hashes, no cleanup failures and both exact owned containers absent.
Report SHA-256
`31af1fc2ed21e989bfac3eba92bff03eb99b89d12861a07e88db33bacfdcf556`,
archived under `approved-workflow/policy102-accounting-smoke-3-artifacts/`.


Review of the complete sharing scenario also makes acceptance C an explicit
fourth source generation with changed collection intent. Generation 3 stays an
unaccepted control-only edit that stops sharing without changing collection
acceptance B. Both new collection acceptances now have distinct source intent;
stop/revoke/replay control transitions retain the same accepted counter pools.
These fixture corrections add no product behavior or relaxed constraints.


Accounting smoke 4 (`2319c48d`) passed the entire selected real PostgreSQL/S3
policy-share scenario: selected child 31.61s, Go 33.070s, runner phase 52.108s;
runner/qualification exit 0. The actual log records grant executions 4/output
16,384 bytes, accepted executions 5/output 16,384 bytes and no fifth reservation.
The fifth trigger occurrence remains spent but its refused capture contributes
no output/grant charge. Replays/new adapters do not add charge; later collection
scopes have distinct accepted intent and monotonic Pod restart ordinals. Existing
sharing publication after expiry/control changes, stop and revoke-all expectations
also pass. All 3,249 hashes matched; unchanged sources, cleanup empty and exact
owned PostgreSQL/S3 containers absent. Report SHA-256
`e19b5a75f8bf331ebca9e535df5a3d17cc35f101eb93065c1e10414c49f3d41e`,
archived with Go log under
`approved-workflow/policy102-accounting-smoke-4-artifacts/`.

This is role-bounded SQL/S3 component evidence with synthetic current identity,
protected authority and review inputs. It is not installed public policy-grant or
recorder qualification. The unchanged revised migration/attachment positives
remain bound to `da522a48`; failures 1–3 remain archived. Acquisition-gate testing
after attachment replacement/revocation, public activation encrypted audit,
request/review/UI wiring, finite same-intent renewal and genuine ongoing sensitive
observation/session credit are still pending. Static call-site review confirms the
new current-policy/grant gate runs on API work/start checks, never on stored
completion or publication; no later-source control blocks already gathered
artifact finalization through this gate.


### Canonical approved-workflow composition

The branch now composes canonical main `eed8594020645fe6d10f8c6565e69a6235c7507d`
(the merged/qualified approved manual workflow), history 00101 and policy 00102.
Resolve the squash-history conflicts by retaining canonical tri-state recorder
availability, the actual-parent response reserve, fixed endpoint diagnostics and
updated H2 metadata assertions, alongside history's pinned-repeat selection,
encrypted settings/browser flow and policy workload metadata eligibility.
Ad hoc original-client continuation hints remain intact; policy grants gain none.
No grant, occurrence accounting, migration 00102 or SQL query implementation
changed during this composition. Earlier real SQL reports remain bound to their
recorded sources; they are reused, not relabeled as installed composition proof.

Five critical diagnostic/wait files are byte-identical to canonical main:
owner_endpoint.go, cluster_observation_operation_client.go,
owner_endpoint_diagnostic.go, owner_route_diagnostic.go and
context_storage_wait.go. History additions preserve the independent current
request/authority cutoffs. Generated browser validators were regenerated from the
merged contracts. Initial generation failed because this worktree lacked locked
web dependencies; the existing console-install target installed the unchanged
lockfile and generation passed. No package version or dependency changed.

Actual composed gates: pre-push exit 0 (13,287 spec assertions, 62 sqlc files,
67 Go packages/393 imports and 227 console unit tests); full affected race suites
passed authorization 1.343s, capture 11.050s, PostgreSQL 2.557s, mTLS 36.860s,
presentation 74.373s and MCP 50.996s. Console build/browser-check exit 0,
Go 21.492s: actual built React/Go HTTPS with synthetic authority ran 23 browser
journeys/20 accessibility scans and four native-restart boundaries/two scans.
Those browser reports do not qualify real SQL/IdP/collectors or native transfer.
Reports/screenshots are archived in the local build cache; generated test results
were restored after archival. No extra SQL fixture, collector or hosted run was
launched, and no push/publication is implied by these local gates.


### Current-manager metadata and original-grant acquisition batch

Observed defect: after the requester leaves, the exact current sponsoring team
member may attach/revoke the team grant but Get returns not found because it
requires action-approver. The service regression reproduced this (exit 1) before
fixing it. Team continuity is a maintainer requirement; the earlier requester/
approver-only metadata rule was an agent implementation choice, now explicitly
extended for exact current pinned managers. Ordinary readers/unrelated managers,
stale denies and replaced assignment/basis identities still reveal nothing.

Reuse one GrantView and the existing get_grant/list_reviews DTO. Add a closed
adHocCapture/policy discrimination: real workload UID scope, policy UID/executor,
original authority dates and finite ceilings/spend; no fake capture/preview/Pod.
Effective grant expiry stays request-anchored. Manager visibility does not confer
independent review, evidence/history/download rights, personal continuation or a
team-wide inbox. Existing can_revoke comes from current actual control rights,
not requester provenance; Approver remains review authority. Old ad hoc shape
and behavior remain unchanged. The same browser/MCP contract and generated
validators retain parity; the existing React detail displays the finite team
scope and available control, never substitutes a new page/model or endpoint.

Numeric cost: zero new services, providers, credentials, network requests,
background tasks, configuration or durable rows. Get still reads one existing
workload projection; list still reads at most one per distinct workload in its
existing 100-row bound. Derive collection/reviewer/manager flags locally from the
same projection (at most three bounded assignment scans); final identity and
original freshness checks remain. Existing response limits stay unchanged.
The added policy metadata is identifiers, configuration and numeric counters,
not gathered user data, credentials or content authority.

Original-grant acquisition testing reuses the fourth admitted capture as an API
pod-status capture (same recipe), after its existing encrypted intent publisher.
A replacement grant cannot change that capture's immutable charged grant or
spent tuple; revoking the original stops its acquisition read while the unused
replacement remains approved. Completion/publication semantics remain separate.
The standalone api-execution SQL duty additionally needs policy_acceptance SELECT
for its already-existing contextEligibilityIn accepted-authority read. The actual
installed hub union already has that read; no grant/acceptance write is added.
New external qualification waits for root's coordinated free fixture slot.


Manager metadata verification: the old C03 Get reproduced not-found for the
current exact sponsor after requester departure (actual RED exit 1, 0.002s).
After the policy-only fix, the complete authorization suite passes, including
single-projection manager access/revoke without review, lost requester rights,
wrong workload, unavailable/stale denies, ordinary reader/unrelated basis and
replaced assignment/digest cases. Real C03 → canonical presentation tests exercise
correct workload/expiry/spend, refused review, one revocation with unchanged
spend, and no metadata after replacement of the manager assignment. Ad hoc
continuation and requester behavior remain under their existing regressions.

The same public DTO now discriminates adHocCapture/policy in browser/MCP and its
offline runtime bundle. Policy adds real namespace/workload UIDs, policy/executor,
original authority dates, finite grant ceilings/reservations and effective
request-anchored expiry; capture/preview/Pod and personal result-access fields
are forbidden. Policy continuation hints must be false. The React page displays
grant reservations with an explicit reminder that shared team/workload/admission
limits still apply; it never promises that grant remainder is usable capacity.
The existing production grant service now wires its previously unused
WorkloadPermissions port to the same existing accepted SQL permissions adapter.
No collector or public policy-execution path is enabled by this metadata wiring.

Full affected race suites passed authorization 1.359s, presentation 79.936s,
PostgreSQL 3.019s and bootstrap 54.591s. Final pre-push exit 0 includes 229 console
unit tests, canonical generation, SQL generation, specification/architecture and
vet. The first TypeScript check correctly found the newly optional preview ID in
manual continuation code; the handler now explicitly requires the existing ad
hoc mode/preview before using that path. No policy can enter personal continuation.

Actual console build/browser-check passed, Go 21.887s: 24 journeys/21 accessibility
scans plus four native-restart boundaries/two scans. Its new policy-manager
journey uses real built React → HTTPS/cookie/CSRF → canonical Go presentation →
real C03 with synthetic identity/store/projections. It shows original
workload/executor/expiry and 4 of 10 executions/32 of 64 MiB reservations, offers
no review/step-up/personal continuation, and revokes exactly once without changing
spend. No external browser requests or accessibility/CSP/runtime violations.
Browser reports/screenshots were archived before restoring tracked test outputs.
These facts are not SQL, IdP, encrypted-audit, native collector or deployment proof.

The expanded real SQL original-grant replacement/revocation acquisition case is
compiled but not run yet; retain that gap until the coordinated fixture completes.
Shared accepted-policy counters in the existing policy-status route remain a
required next public-composition step, not an optional alternative to grant status.


### Composed installation inventory (history 3673 + policy 102)

Retain history's qualified eviction mutation-count fence and exact two-table
installation correction by merging 3673c264. The complete permanent inventory
is 130 names (history 127 plus policy_grant_settings, policy_grant_attachment,
policy_observation_session); the previous literal 128 rejected this supported
first-install path. The old ordering test reproduced that rejection (exit 1,
0.010s); no installed policy success is inferred from history's schema-101 pass.

Replace only the two table-catalog bounds with the closed compiled inventory:
complete/activation reads admit exactly 130 and fetch at most 131 rows to detect
unknowns; partial replay permits the two exact legacy transient tables, at most
132 known names and one overflow row. Unknown names still reject immediately,
and complete equality, owner, permanence, RLS, pristine-table, original-prefix,
original deadlines and binary floor 102 remain unchanged. The unrelated 128
migration-file/version and filename bounds remain unchanged. Added real-SQL
regressions create unknown names before/after the complete ordered inventory,
require refusal, remove them and require successful exact replay; not yet run.

Cost: zero extra catalog queries/round trips, credentials, services, watches,
background tasks or configuration. Existing catalog reads gain parameterized
LIMITs, replacing one unbounded read and one literal bound. Each existing
pristine scan gains three SELECT EXISTS round trips compared with history 101
(five compared with canonical 100); no per-workload scaling. Initial preparation
and activation each gain SELECT and MAINTAIN on those exact three policy tables:
12 role/privilege tuples total, and six deduplicated grant-option tuples for the
existing setup-manager union. History's two tables account separately for eight
role tuples/four manager tuples. No runtime role or write privilege is added by
this inventory composition. A larger arbitrary constant or omitting tables
would leave the observed exact-inventory failure unresolved.


Composed local verification: initial inventory/role gates pass PostgreSQL 0.078s
and integration compilation 0.015s; full PostgreSQL race suite passes 2.557s.
`make pre-push` actual exit 0 includes all 229 console unit tests, canonical
schema/SQL generation, specification, architecture and vet gates. Logs are
archived as policy102-history-composed-{prepush,postgres-race}.log under the
existing approved-workflow cache. No external service qualification ran during
this composition; both new real-SQL scenarios remain pending.


Composed smoke1 on frozen a3f9c8da: overall runner/Go exit 1 (Go 21.712s,
phase 52.037s); initial-schema parent passes 16.96s. All 13 direct schema
children pass, including unknown-first/last catalog overflow and both nested
activation changed-database/changed-postmaster cases. This is genuine schema-102
first-install/role/prefix/incarnation qualification with synthetic protected root,
not a deployed installer proof. All 3,258 source hashes match, source unchanged,
cleanup empty and exact owned n4fzsg3r PostgreSQL/S3 containers absent. Report
SHA-256 78ee813a274f6fdaeb90e0837733069278423dd509643de129e30019e189a9a7;
report/log/provider evidence archived before removing untracked result copies.

Policy-share reaches the expected 4/16,384 grant and 5/16,384 accepted accounting
checkpoint, then its new acquisition fixture fails before adapter construction:
it incorrectly requests retired installed-purpose api-execution from the public
role renderer. That name remains a shared hub duty; the renderer correctly
refuses it. Correct the fixture to existing compiled hub-runtime union, as other
policy fixtures already do. No production privilege, constraint or role-purpose
change; standalone-duty exact grant tests remain separate source checks. No
acquisition success is claimed and no automatic rerun is authorized.


### Shared accepted-policy budget status composition

Observed gap: get_grant correctly shows only its own reservations, while the
existing get_policy_status exposes accepted executions but omits the shared
accepted native-output/observation pools. Add four required typed fields to the
same browser/MCP status data: collected_bytes_spent, max_collected_bytes,
observed_bytes_spent, max_observed_bytes. The existing SQL acceptance row already
contains both counters, and decodePolicy already provides original authored
ceilings; use these exact values, including conservative legacy saturation.
No subtraction from grants or inferred measured bytes. Preserve the existing
current viewer identity/whole-workload metadata checks, recovery/source state,
original expiry and final freshness; status grants no collection or evidence
access. Browser labels native output as reserved and observation as charged,
explains shared policy scope, and retains the existing explicit Refresh action.

Complexity/cost: zero new SQL queries/round trips, API calls/connections, roles,
privileges, background tasks, timers, watches, dependencies or configuration.
Four bounded integers add under 160 JSON bytes per existing status response.
Existing projection/audit and privacy contracts remain, no new failure state or
public endpoint. A per-grant substitute would hide the actual shared ceiling;
a separate budget service would add cost without improving this workflow.


Review found one adjacent protected-result gap: GrantService.Revoke returned an
already-revoked replay directly before final identity validation. A blocked-store
regression reproduces metadata disclosure after same-principal group loss,
identity expiry and original manager-eligibility expiry (all three RED, exit 1,
0.008s). Fresh/replay now converge on existing finalGrantMetadata and preserve
the original policy management deadline. Fresh retains one final identity read;
replay acquires its missing final identity check. No second workload or grant
read, new freshness interval or mechanism; refused replies do not undo/refund a
previously committed revocation or its counters. Ad hoc uses its existing final
check. Current manager/get and manual regressions remain binding.


Shared status/replay verification: full race suites pass capture 11.116s,
authorization 1.355s, presentation 80.516s and PostgreSQL 2.573s. Tests include
current team-maintainer status after creator departure, refused lost membership
and final identity expiry, canonical distinct accepted counters/ceilings even
after expiry, and all three blocked-replay regressions. Existing canonical status
fixtures with finite zero output/observation budgets validate unchanged.

Actual console-browser check passes (Go 22.598s): 25 journeys/22 accessibility
scans plus four restart boundaries/two scans. The new journey uses built React
through HTTPS/cookie/CSRF/canonical operations into the real policy-status service
with synthetic accepted ledger/source/projection/recovery. It shows accepted
5/100 executions, 16,384/1 GiB native-output reservations and 0/0 pre-filter
observation charges, with explicit refresh; no new polling, external requests,
CSP or runtime errors. Archive:
/home/phil/.cache/asservat-build/approved-workflow/policy102-status-browser-artifacts.
This is not SQL, IdP, audit, collector or installed qualification. First pre-push
caught required-field array ordering drift between browser/MCP; canonical order
was aligned and regeneration/final pre-push exit 0 passes all 230 console unit
tests plus full schema/SQL/specification/architecture/vet checks. Earlier failure
logs remain archived. The corrected original-grant SQL case and actual SQL
accepted-pool status assertion still require the next coordinated focused run.


Focused status/acquisition smoke1 on 87e3f492: runner/Go exit 1, child 5.86s,
Go 6.317s, phase 9.176s; all 3,260 source hashes match, unchanged, cleanup empty,
exact owned ihvcclkp PostgreSQL/S3 absent. Absolute archive:
/home/phil/.cache/asservat-build/approved-workflow/policy102-status-acquisition-smoke-1-artifacts;
report SHA-256 7c401adc163c12eae357e6137966e09a91215aa506d675e4afc1fa3e7c79abce.
The real shared-status assertion and original prepaid API acquisition read pass
before the replacement callback, where the fixture attempts an existing role.
The shared narrowRole helper takes the first 12 UUID characters, constant for
custodyID's monotonic test IDs; invoking the grant helper twice with its same
prefix collided. Scope the helper's two fixture login prefixes by their already
distinct fixed original/replacement request keys. No global helper, production
role or privilege change, and no replacement/revocation success claimed. This
failure is retained; the host slot was released to storage qualification and no
automatic repeat is authorized.


### Public request/review/attachment composition (2026-10-28)

Use request_policy_grant as one typed browser/MCP command over the existing C03
RequestPolicy service; callers select only an exact named policy/UID pin and
finite limits/period, never authority, scope bytes, requester or a Pod/capture.
Reuse existing GrantOperations/get_grant detail and independent decide_review
with real step-up. Keep original actor/client journals and original request
expiry. Use the current get_grant projection for the command result rather than
introducing another policy view model: this adds one existing grant read and one
existing workload metadata projection on a rare approval request; exact SQL
round trips are recorded with the implementation, not called network-free.

Add optional grant_id to existing activate_policy input. The real activation
service resolves the policy and current actor, preserves acceptance/audit, and
calls existing AttachPolicyGrant only when accepted-policy audit is acknowledged.
The outer AuditedOperations already acknowledges encrypted intent before inner
service work and records its outcome. Include all new input fields in existing
normalization/MAC and exact immutable request key; unknown Begin never mutates,
unknown outcome never refunds or fabricates a new attachment. No new audit
worker/table/service or public resume hints. SQL102 extends existing closed
operation_audit_lane/input functions for request_policy_grant; Down restores
previous names and refuses incompatible retained policy state as before.

Production producers already exist: PolicyGrantPlans recompiles the pinned
accepted source with the same recorder/profile/filter compiler and verifies its
exact scope digest; AccessGrants reads current accepted settings and original
request journals. Wire these and WorkloadPermissions, not fixture authority.
Reuse the existing manual filter compiler through typed DTO conversion; no new
compiler dependency or profile approximation. Join the existing settings observer
under the permission-worker's existing lease, using its protected cached identity
reader and permission-accept credential. Incremental bound: at most one source
read/10s (at most three Kubernetes HTTP requests per refresh =0.3 API/s), one SQL
projection transaction/10s, fewer on exact cached observations; no new watcher,
credential, worker workload or table. Source validity is the original 30s; cache
reuse cannot renew it. The existing observer child is joined on lease loss.

Recorder activation/execution currently lacks production composition: the trigger
still only compiles/submits pod-status and must never substitute that for packet
recording. Keep sensitive acquisition without concrete observation/session bounds
unavailable, preserve supported ordinary qualified headers, and compose genuine
recorder submission next. Public metadata/review/attachment alone does not finish
ongoing source arming, all-before-filter credit, native evidence or installed
policy workflow qualification.


Public composition cost refinements: settings are one transaction per fresh
observation, not one SQL query. The normal transaction executes five work SQL
calls (lock, clock, read, write, final clock), plus existing setup Exec and
BEGIN/COMMIT = eight database round trips before driver first-use preparation;
initial/lower maxima add one clamp call = nine. Thus steady accepted observations
at 10s cost about 0.8 DB round trips/s (0.9 on a clamp), in addition to at most
0.3 Kubernetes requests/s; exact unchanged cache hits skip SQL. Existing bounded
transaction retry stays under its original five-second total. One serial joined
observer child/timer runs inside the existing permission-worker workload/lease,
with no new worker deployment, watch, credential or table.

For usable controls status also reports accepted collection_kind (from the
already-read authority actions) and optional attached_grant_id. The latter is
folded into the existing purpose-specific status source read through a bounded
LEFT JOIN to the exact current receipt/root/policy/acceptance/authored reference;
authority digest is checked after accepted-record decode. No additional round
trip, mutable denormalized grantID or lookup by historical control key. Generic
source authority readers remain unchanged. The status role already has receipt
SELECT. Missing/mismatched current pointer fails unavailable; attachment ID never
claims current approval eligibility or recorder readiness. This addresses stale
receipt replay without an extra O(attached policies) query in multi-policy views.


Public request final-authority regression: while composing the command, fresh
RequestPolicy and immutable replay reproduced protected-result disclosure after
same-principal group loss during blocking storage/projection (both RED, actual
exit 1, 0.011s). Both now use existing finalGrantMetadata at the same final read,
with no additional workload/SQL read. The stored original request remains once,
with zero execution spend; refusing the reply cannot erase uncertain history.
This extends the same demonstrated final policy-identity contract as get/revoke,
not a new freshness mechanism.


The source has a 30-second observation interval with a healthy 15-second trigger
poll, so there is no inherent normal-operation freshness gap. After a genuinely
expired source observation (for example a >30s observation outage), the initial
SQL-first plan could fail before reading the restored protected object. The
single canonical request
now binds policy_name plus UID, and its plan reads that protected exact object
once, persists its original observation through existing SourceWriter, then reads
current accepted authority and recompiles those same bytes. No extra Kubernetes
read versus the intended plan, TTL relaxation, watch or SQL locator lookup; one
existing source-observation transaction per fresh request. Immutable request
lookup still happens before all new source/settings interpretation on replay.

There are no deployed production schema-102 policy-grant requests: this branch
has never been published and all recorded requests were disposable owned fixture
data, with exact source snapshots retained. Update this one unpublished canonical
v1 input/digest and fixtures together; do not retain compatibility versions or
fallback ports solely for prototypes. No real receipt is rewritten. The name/UID
pin is validated again against the accepted record and actual protected source.


The source-first ordering regression models an original valid source observation
expired after 31s, then a new actual named protected read. It retains that read's
original 30s deadline and the separately bounded five-second recovery/preflight
result, plus unchanged authority/expiry/pools. Failed observation has no fallback
to SQL authority. Its mutation of current negative/source watermarks occurs only
inside the existing acknowledged outer public operation intent. It is never
acceptance, renewal or permission to collect. The earlier five-versus-15 claim
was a diagnostic error, corrected before qualification or publication.


Review effect-bound cost/qualification: four blocked fresh/replay reviewer cases
(group loss and original eligibility expiry) reproduced RED (exit 1, 0.012s).
The same Store context now retains earliest original identity/reviewer and fresh
approval step-up deadlines, truncated down to microseconds. Its existing UPDATE
also compares database time with the inherited bound (one scalar parameter, zero
new queries/permissions/tables). Replay does not demand a new step-up. This is
original-bound enforcement, not immediate role-change revocation. The compiled
public SQL fixture holds the actual row beyond both narrowed reviewer and step-up
bounds and independently reads decision NULL after release. No actual SQL RED or
GREEN has run yet; do not replace that evidence with a hidden-error assertion.

Public request post-read detail cost: seven work SQL calls in the existing grant
read/workload projection, two transaction setups and BEGIN/COMMIT pairs = about
13 steady round trips before first-use preparation, plus two existing current
identity resolutions. It reuses one existing DTO and actual CanRevoke rather than
duplicating rights or a view model. Source observation costs six work calls plus
setup/BEGIN/COMMIT = nine steady round trips per fresh named request; no additional
protected Kubernetes read. These are per human/service approval request, not
per packet, policy poll or ongoing authority renewal.

Public fixture preflight now uses actual PolicyGrantPlans, typed composition
conversion and the same profile compiler, rather than a synthetic plan/scope.
Its pinned genuine libpcap corpus accepts exactly `tcp dst port 80` and refuses
other expressions; this is not a host libpcap qualification. The accepted scope
hashes the compiled configuration, original delegation/owners and original
64 MiB output ceiling. The public request selects 32 MiB for two executions;
held-row probes select 16 MiB, matching the builtin action ceiling. Protected
Kubernetes source, verified IdP/step-up and initial trust remain synthetic facts.
Source refresh is dispatched only inside the outer acknowledged intent; both
unknown-intent cases independently compare actual source observed_at, in addition
to checking no grant/attachment mutation. A separate external source-observer
simulation performs authored-ref A→B→A. This does not execute a recorder.

Local public composition checks: final canonical source-order races and
pre-push passed (actual exits 0); the final fixture compiler/compilation check
passed in 0.014s. Built React → actual Go HTTPS browser run 5 passed (actual exit
0, Go 23.199s): 25 journeys, 24 accessibility scans, no external requests or CSP/
runtime errors, plus the native-restart checks. Browser reports/screenshots were
archived before restoring tracked results at
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-browser-5-artifacts/`.
This uses synthetic server authority/store and does not qualify SQL audit,
protected Kubernetes producers, installed execution or sensitive observation.
The new actual SQL public/audit/held-row checks are still pending coordination.
Final affected race run also passed, actual exit 0: authorization 1.356s,
capture 11.074s, PostgreSQL 2.596s, bootstrap 54.629s, presentation 87.126s,
audit 1.031s and browser transport 17.805s. Final pre-push exit 0 includes
spec/architecture/design/schema/OpenAPI/SQL generation, console 231 tests and
Go vet/format checks. No external fixture or collector ran for these checks.

Combined public SQL/S3 batch 1 at clean 134080ef terminated exit 1 (Go 47.590s,
harness test phase 68.467s). Actual positive children: policy-share accounting
36.83s, including original-grant acquisition before/after attachment replacement,
original revocation refusal, unchanged tuple/pools and shared status; original
request/attachment 3.13s. Migration's full top-level body passed 2.72s, including
new audit-name Up/Down mapping and legacy conservative spend; the report's
passedTestNames lists children only. The new public audit child failed 3.00s in
fixture configuration replay: refresh recomputed audit-pool ValidUntil while
ExpectedRevision remained zero. The existing immutable configuration replay
correctly refused this. Provision both finite pools once at their original
anchor; do not refresh their deadline, revision or spent counters. No product
permission/constraint change. The public unknown outcome/source and held-row
SQL assertions did not complete and remain pending.

All 3,264 hashes independently matched the frozen snapshot, sourceUnchanged=true,
cleanupFailures=[], exact `asservat-custody-ggze1ry6-postgres`, `-s3` and their
network absent after terminal. Archive before source changes:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-composed-smoke-1-artifacts/`;
report SHA-256 5aff42437209b9273ac028c085086727a92aa6df49474b06a524ad53ce4cffb4.
Reuse these unchanged positive cases; a next run requires reviewed focused
public-fixture selection, not an automatic repeat of the combined batch.

Focused public run 2 at clean 168aec43 terminated exit 1 (Go 5.170s, harness
phase 25.803s). Original unknown-intent/source-no-mutation and unknown-outcome/
one-stored-request assertions were reached; same-key result recovery failed.
No PostgreSQL product permission/constraint error accompanied it. The actual
PolicyGrantPlans producer emits `policyCollection`, while the public grant reason
enum accepted only rawBytePredicate/recordingApprovalRequired. Earlier synthetic
wire/browser fixtures used those old reasons and masked the contract mismatch.
Using the actual producer reason reproduced local canonical-route RED (exit 1,
0.435s); the closed browser/MCP enum now includes policyCollection for request,
detail and list metadata. Sensitive action reason enums remain unchanged. Product
copy describes separate finite recurring approval/budgets without claiming raw
sensitivity or installation-required approval. The same route is GREEN (race,
exit 0, 3.287s). Existing closed FixedStep diagnostics are now logged by the SQL
fixture on failures; no new diagnostic mechanism or production permission.

All 3,264 source hashes independently matched, sourceUnchanged=true, cleanup[],
exact `asservat-custody-egt4vrqk-postgres`, `-s3` and their network absent. Archived
before source edits at
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-focused-2-artifacts/`;
report SHA-256 b82d9259a3db3e1b9acdbf2349ec940e3e2944c97d278c259577410d8cac16c9.
No automatic retry. Complete public attachment/audit recovery and actual held-row
NULL decision assertions remain unqualified until reviewed focused SQL GREEN.
The reason-contract correction passed final pre-push (actual exit 0, including
231 console tests) and actual built-browser run 6 (exit 0, Go 23.097s,
25 journeys/24 accessibility scans plus native-restart). Manager and newly
requested policy detail now exercise policyCollection end-to-end and assert its
finite-budget explanation. Reports/screenshots archived before tracked restore:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-browser-6-artifacts/`.
These browser facts still use synthetic accepted authority/store; SQL public
completion/held-row proof is pending a reviewed focused run.

Focused public run 3 at frozen 8caf2ee4 passed, actual terminal exit 0 (Go9.703s,
public child7.32s, held reviewer1.75s/step-up1.77s; harness49.592s). Both request
and attachment reached audit-begin/object and audit-finish/object uncertainty,
then recovered exact journals. Source-before-Begin assertions passed. One grant,
one immutable attachment, original expiry, zero execution/output spend; six
independently encrypted acknowledged operations and two uncertain outcomes.
Both actual held-row cases independently read decision NULL after releasing the
lock beyond the original bound. This is unit RED / actual SQL GREEN; no actual
SQL RED source variant was run. All3,264 hashes match, sourceUnchanged=true,
cleanup[], exact5z8fx0u4 PG/S3/network absent. Archive:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-public-focused-3-artifacts/`;
report SHA-256334c26892d87e786d3c90ed7766e6148f72e05b45d756474eaddb0e21d5e21df.
Protected source/IdP/initial trust remain synthetic component facts. Reuse the
combined134080 migration/attachment/accounting positives; this does not qualify
installed recorder execution or ongoing observation.

Next producer slice (approved existing S-04 plan): accepted packet policies
currently hit three concrete incompatible branches: trigger compiles only
pod-status and calls its Preview; generic policy capture eligibility requires
kubernetesSnapshot; recording settings look up the internal policy issuer and
approval asks a policy principal to open a human ad hoc review. Reuse the same
recorder compiler and PreviewComposition for the actual triggering Pod, original
occurrence key, ContextSubmission and encrypted capture intent/start. Permit only
the compiled supported packet mode; sensitive raw predicates keep existing
RecorderUnavailable until real observation authority is composed. Atomic
admission checks the actual recorder/snapshot action against accepted actions
before spend, retaining the original grant/recipe/counter/deadline checks.

Complexity/cost: this fixes all otherwise-unusable accepted packet policies,
not a new speculative recovery mode. Zero new watch, worker, listener, credential,
network exposure, table or SQL query/round trip is intended. Pure bounded action
checks occur in existing eligibility/admission. Existing recording settings read
uses accepted settings issuer provenance from the private request-owned policy
identity/cache; it does not reauthenticate the creator or consult personal
membership/account state. No extra acceptance read or second settings fallback.
Same one profile/filter compilation per packet-policy poll plus the existing
actual preview compiler; measure the combined path before claiming CPU cost.
Same 30s source /15s poll and existing finite attempt/deadlines. New absent-private
settings provenance refuses packet preview, with no fallback or new config knob.
No instant role-change revocation or separate machinery is introduced. A smaller
metadata-only change cannot produce an actual recording; installed/native and
ongoing qualification remain required after this source slice.


Producer local defects reproduced before fixes: a valid packet policy failed
existing shared eligibility with OutsideDelegation (unit RED exit1,0.001s), and
its real recorder preview could not use protected settings under the internal
policy issuer (unit RED exit1,0.005s). Current tests preserve the actual team
reader audience and deny sponsoring-team loss; use only accepted settings
provenance, refuse ordinary policy-shaped CurrentIdentity without the private
view, and refuse absent/outage/changed issuer or requirement after preview.
The private view reads only the existing cached accepted snapshot (asserted no
additional acceptance read), never creator credentials/groups. Trigger tests
reach the existing real recorder preview/request with the original occurrence
key/Pod/executor/recipe, refuse a changed compiled scope before Tick, and retain
the raw observation refusal before occurrence spend or personal review.

Actual bounded pure poll compilation with the statically linked libpcap1.11.0
prefix, GOMAXPROCS2 on Ryzen7 5700X3D (three1s samples per case, actual exit0,
Go7.023s): ordinary `tcp dst port 80` full policy/profile/DTO/filter/canonical
compilation117.158–117.512us/op,59,995–60,005B/op,267allocs/op; inert raw filter
119.391–120.877us/op,60,206–60,211B/op,270allocs/op. No capture/device/socket,
protected source/SQL read or recurring worker ran. At200 policies/15s, arithmetic
for this ordinary input is about1.57ms CPU/s (0.157% of one core),0.80MB allocated/s;
at1,000 policies,7.83ms/s (0.783%),4.00MB/s. These are scaled pure local costs,
not measured end-to-end CPU, GC retention, concurrent compilation or maximum
filter complexity. The existing compiler mutex remains; no cache/configuration
was added without demonstrated need. Complete runtime/workflow costs and native
qualification remain pending.
The exact linked compiler version was independently printed by a bounded
single-iteration diagnostic: libpcap1.11.0 (64-bit time_t, TPACKET_V3), actual
exit0/Go0.020s; its cold first ordinary compile was498.572us,165,344B/1,670allocs.
Do not substitute that one-shot sample for the repeated steady measurements.

Producer affected races passed (actual exit0): domain authorization1.478s,
application authorization cached, capture11.262s, PostgreSQL2.579s,
bootstrap54.013s. Pre-push exit0 includes231console tests and repository contract/
architecture/SQL generation/vet/format gates. The new focused SQL fixture compiles
but has not run: actual Tick baseline→higher restart spends one accepted execution;
packet admission/replay must charge8MiB native output and one grant execution
once, while snapshot-only authority/attachment must refuse the actual recorder
with zero output/grant reservation. Each case has one full8MiB storage slot;
negative denial cannot be attributed to a four-kilobyte or exhausted fixture.
Exact generated grant request/scope/digest, finite settings original anchor,
role names, source/permission freshness and independent cleanup are reviewed
before any coordinated external run. This is not a collector/start/publication
or native-recorder execution qualification.

## Local callback meter component (2026-10-28)

This isolated component starts from `867ed8d7`. It does not issue authority,
change public wires, migrate SQL, or enable the raw recorder. Finite onTrigger
with exactly one packet action per real capture is the first composition target;
default ongoing source arming remains separate required work.

Binding requirements before later enablement: (1) retain UNIQUE capture and one
packet action, so actions cannot each receive the aggregate credit; (2) existing
capture/expectation joins prove Pod/action/program but the regional API execution
row does not prove actual node identity; (3) persist actual node UID, boot ID,
collector Pod UID/epoch and accounting-rule digest from authenticated node
resolution, with an under-channel-lock exact tuple comparison at enqueue; (4)
issue only after SQL commit/current checks, renew the original tuple/fence/grant
with monotonic sequence, never a replacement process; (5) terminal rows need
existing custody/backing cleanup after original cutoffs and settled references,
without refund or credit recreation. This local meter implements none of those
issuer/channel/persistence responsibilities.

The gate checks the original engine wire length before Recorder.Add (therefore
before maintained BPF matching), including discarded/malformed/output-full input.
It distinguishes observed input from the existing retained WireBytes. Missing or
invalid length stops without a fabricated debit; engine loss is unknown input,
never zero input or refundable credit. One local mutex serializes debits and
permit updates. The engine receives the meter cancellation context; returning a
callback error alone is insufficient. Lease/session timers also stop an idle
engine, and its synchronous return joins acquisition before capture resources
are released. No buffered packet copy or per-packet network/SQL call is added.

Accounting rule `wire-token-bucket-v1` uses existing integer ObservationMeter at R bytes/s,
with initial/max burst R bytes (one second), an average/token-bucket rate rather than
a strict rolling-one-second cap. Both cumulative prepaid credit and
rate must admit a whole original frame. A frame larger than R is refused;
credit does not wait/refill. The finite rate upper bound includes the burst:
ceil(R * remaining duration) + R, intersected with reviewed cap/remaining pools.
This is a conservative reservation bound, not measured input. Exact duplicate
permit updates do not recreate rate tokens or credit. General ongoing prepayment
quantum and trusted renewer remain undecided by this component.

Complexity gate (estimates before code):
1. Missing pre-predicate debit is established in Recorder.Add, so enabling raw
   predicates now would fail the accepted all-input accounting contract; frequency
   under enabled sensitive capture is every delivered frame (currently refused).
2. No: maintainer has not accepted unbounded sensitive observation.
3. Required finite sensitive recorder path; existing sanitized path unchanged.
4. Published Gadget supplies packet_size; established local token bucket reuses
   the existing byte-nanosecond ObservationMeter. No custom gadget, BPF or packet parser.
5. Zero privileges, credentials, endpoints or dependencies added.
6. Two states, running/terminal, with closed terminal reasons; no fallback.
7. Zero new knobs. Fixed burst is part of the accounting version.
8. Existing pinned Gadget callback/source length and BPF evaluator only.
9. O(1) state/session, one callback-owner mutex plus one gate mutex per callback, one lease
   timer/session and one engine-cancellation callback; zero per-packet SQL/API/network,
   zero periodic renewer/watch. CPU/allocations must be benchmarked, not guessed.
10. No wire/schema change; deleting this unused component restores base behavior.
11. Keeping raw refusal is sufficient today; this component is the smallest
    testable next step toward accepted finite enforcement, not rollout proof.

Local component evidence (synthetic inputs, no Gadget execution): removing the
pre-Add Consume call makes zero-match regression fail in 1.00s with actual exit 1
because the engine is never canceled; restored gate passes. The tests exercise
real packetInput -> Recorder.Add -> maintained BPF/decoder/output limit, with
fake engine delivery and no authority/store. Credit/rate/length refusal, cancelled
parent, idle original/renewed lease, original session expiry, conflicting/lower
sequence, cumulative-credit preservation, changed boot/action/scope/epoch and
unknown engine loss are covered. Synchronous engine return is asserted after
cancellation, including a queued post-cancel callback; no collector was run.

Final affected `go test -race` passed: collector 1.006s, packets 1.027s,
bootstrap 54.302s. Canonical `make pre-push` exited 0 (230 console tests,
13288 specification assertions, 1326 architecture checks); Go architecture
passed with 67 packages/393 internal edges. The existing pure domain meter and
its tests are unchanged. The lifecycle wrapper belongs to node bootstrap;
no domain context dependency or architecture exemption was added.

AMD Ryzen 7 5700X3D, GOMAXPROCS=2, three runs of 100000 callbacks each:
median baseline -> metered zero-match 13.63 -> 74.84 ns/frame; malformed
32.93 -> 96.48 ns/frame; output-full 64.69 -> 129.10 ns/frame. Incremental
cost is 61.21–64.41 ns/frame. Zero-match/output-full stay 0 B/op, 0 allocs/op;
malformed remains the decoder's 16 B/op, 1 alloc/op on both paths. These are
shared-host synthetic microbenchmarks using fixed 64-byte wire lengths, not
native Gadget throughput or end-to-end overhead percentages. Per-source setup
allocation/CPU and combined installed cost remain unmeasured. The new gate and
callback helper total 278 implementation lines, with 512 test/benchmark lines
before this evidence note; no packet bytes are copied by the gate.

The local timer/control cost is exactly one lease timer, one derived cancellation
context and one engine-cancellation AfterFunc per metered source, plus the runner's
joined engine call; there is no periodic goroutine or renewal loop. Existing
ObservationLease's <=60s current-lease limit and <=1h original-session limit remain.
REQ-AUT-006 and action-lifecycle require rate ceilings but do not define a strict
rolling-second algorithm; this component pins the existing one-second-burst
integer implementation explicitly. Eventual review/SQL permit must bind that
accounting identity before enabling sensitive predicates. Prefix access soundness,
authenticated actual-node resolution/enqueue binding, issuer/session SQL, terminal
row cleanup and default ongoing source arming are still required. Upstream events
that never reach the node frame callback are not measured here; loss remains
unknown and reserved spend is never refunded.

Duplicate permit comparison uses timestamp instant equality, so private-wire UTC
normalization/loss of Go monotonic metadata cannot turn an exact replay into a
conflict. The replay regression also proves that rate tokens remain spent.

Independent review correction: an already-dispatched old AfterFunc can wait for
Update's mutex, survive Reset, then wrongly stop the renewed source. The expiry
callback now compares the current lease while holding that same mutex. A regression
joins the obsolete callback while renewal wins the mutex; restoring unconditional
Stop reproduces failure (0.20s, actual exit 1). All observation race tests pass on
the correction (5.202s, actual exit 0). The full-suite/pre-push/benchmark numbers
above describe checkpoint `632746cf`; the packet debit/recorder benchmark path is
unchanged by this timer-only fix. No additional timer, worker, service or authority.

The clean producer checkpoint is 3dd5f544. Only the independently reviewed local
meter commits were then composed: 632746cf as 480b22af and ba585360 as f120b6ea.
The plan's append conflict retained both public/producer and meter sections.
No stale branch merge, SQL/node authority issuer or raw-path enablement occurred.
At composed f120b6ea, one affected race run passed (actual exit 0): bootstrap
54.634s, packets 1.028s; unchanged collector/capture/authorization/PostgreSQL
packages reused Go's test cache. One composed pre-push also exited 0, including
231 console tests and the repository contract/architecture/SQL generation/vet/
format gates. Logs are `policy102-producer-meter-composed-{race,prepush}.log`
under the existing approved-workflow archive root. No external fixture ran for
this composition. The next reviewed SQL selection is only the new recorder
team/action case plus existing policy-share/accounting original-grant positives;
reuse public focused-3 and unchanged inventory/migration evidence. Complete
SQL/node binding/channel/pre-filter/native and ongoing qualification remain open.

Composed SQL batch at frozen f94be53c terminated exit 1 (Go 44.905 s, harness
67.628 s). Existing policy-share/accounting passed 36.81 s, including the original
grant acquisition/replacement/revocation/status assertions with unchanged pools.
Both new recorder cases reached actual Tick but stopped before admission at
retention resolution (4.03 s / 3.60 s). The baseline covers packet evidence;
the fixture captured its validation time before the existing blocking retention
helper observed a newer protected snapshot. Freshness correctly refused that
older time. Validate retention after the read returns, retaining the original
identity, capability/target/storage, grant/policy and plan deadline. No production
guard, policy, permission or interval changes. The other captured times were
reviewed: permission/source observations precede their consumers; original
acceptance/submission anchors remain fixed; admission obtains fresh recovery
after retention/compilation and the current accepted read; none renew an original
execution bound. The focused fixture compiles locally after this correction.

All 3,271 hashes independently matched, sourceUnchanged=true, cleanup [], exact
`asservat-custody-v4hl9ge_-postgres`, `-s3` and their network absent. Archive before
source edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-producer-meter-smoke-1-artifacts/`;
report SHA-256 8bc01759ee8ea9284d3f1861bc22e78c527262c503480b820d847258004144d9.
Reuse the existing positive; next qualification requires reviewed focused new
recorder child only. Real recorder admission/replay/action-pool assertions remain
pending; Tick and local source passes are not their substitute.

Recorder focused run 2 at frozen 37dfe108 terminated exit 1 (Go 7.957 s,
harness 27.405 s). Retention resolution passed; both recorder cases stopped at
the adapter's pre-transaction structural guard. The fixture called unreviewed
AdmitContext with an approvedAcceptance-marked RequireApproval plan; that guard
requires a preview ID. Production ContextSubmission already uses the reviewed
entrypoint. Correct the fixture by persisting its exact compiled passive preview
and calling AdmitReviewedContext with ContextRequestDigest of that preview for
both initial admission and exact replay. Do not set RequireApproval false or
weaken/export the production validator.

A shared offline/SQL fixture assembler now builds that marked plan, full preview
and original request digest once. Its local preflight reports all failed
predicates together: frozen plan; registration/8 MiB bound; storage root, target,
allocation and freshness; retained anchor/expiry/deletion/write deadline;
eligible principal/target/identity and permission revisions; original recovery;
case/occurrence IDs; exact preview canonical scope and reviewed timing marker.
The offline assembled fixture passes. The actual fixture runs the same checks
before preview persistence/SQL admission, keeping protected observations and
original deadlines. These are test-only checks, no production port or validator.

The failed run's 3,271 hashes independently matched; sourceUnchanged=true,
cleanup [], exact `asservat-custody-m53hggn3-postgres`, `-s3` and network absent.
Archive before source edits:
`/home/phil/.cache/asservat-build/approved-workflow/policy102-recorder-focused-2-artifacts/`;
report SHA-256 48cab9576f7c548b763057e0d1158f9c97414231b04f489fbb2c1d40b9476b3f.
No actual recorder admission or negative action-pool result is claimed. Reuse
prior policy-share positives and require a reviewed focused rerun only.
