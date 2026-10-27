# ADR-259: Team-policy grants and prepaid sensitive observation

Status: accepted design; implementation and qualification in progress.

## Decision

Implement S-04 increment 12b end to end under REQ-AUT-003/004/006. A policy
AccessGrant binds a real policy UID, workload scope, resolved execution digest,
policyExecutor, accepted policyAuthority and finite budgets. The authenticated
requester and independent signed step-up reviewer are separate audit actors.
Policy grants have no capture/preview/Pod placeholders or personal resultAccess.
A current manager explicitly attaches an approved grant using optional grant_id
on activate_policy. An authored grantRef must match exactly; absent grantRef permits
an explicit runtime attachment. A changed authored reference stops old-pointer
reuse until explicitly reconciled. The attachment preserves the original acceptance,
issue/expiry and spend. Its immutable SQL control receipt is semantic/idempotency
state, not durable object audit. The existing audited activate_policy transport
must acknowledge encrypted intent before changing the pointer and retain its
outcome/replay behavior; automatic collections keep separately audited admission.
No new audit worker or credential is introduced. Creator departure and
requester token expiry do not revoke independently accepted team execution.
Current delegation, sponsors, source, grant, recovery and capacity remain required.

The original grant issuance timestamp anchors expiry. Defaults are seven days,
maximum thirty days and renewal notice one day; protected configuration can set
finite values up to 365 days. Persist every accepted lower maximum so older grants
clamp even when unused during that accepted setting period. A later increase does
not extend them. Settings changes mean protected accepted projections under the
existing bounded observation semantics, not unobserved raw ConfigMap history.
Reuse existing projection identity/epoch/audit; no new watch/history service and
no blanket revocation for benign resourceVersion changes.

Observation input is separate from retained output. Reserve conservative byte
credit before dispatch and charge original wire bytes before a sensitive predicate,
including discarded packets. Piggyback cumulative credit extension on the
current-authority renewal required for sensitive observation over the existing
private node channel, preserving original session/fence, idempotent sequence
and one outstanding RPC. Preserve unconsumed existing credit when the parent pool
has no new credit. Unknown possibly-started credit stays spent. No independent
quota renewal stream, two-slice machinery, per-packet network or refund protocol.
Derive credit from reviewed rate times measured bounded authority horizon; compare
full-session prepayment and tail waste before fixing the quantum.

Use only the pinned published Gadget and maintained compiler/decoder libraries.
Verify actual published snaplen limits and compiler assumptions before lifting
raw-predicate refusal. Distinguish an existing metadata capture buffer from input
entering a sensitive predicate; do not invent a blanket restriction on ordinary
metadata. Keep unsupported capabilities unavailable with an explicit reason.

The first recorder policy path is explicit finite onTrigger/before-zero. Ongoing
source/ring arming in S-04 increment 6 remains an active dependency for that mode,
not a specification waiver. Complete request/review/attach, admission, executor,
UI and installed native proof before claiming this increment qualified.

## Complexity and validation

The [implementation plan](../reviews/s04-policy-grants-plan-2026-10-27.md) records
all eleven complexity questions. No new watch, listener, collector credential or
kernel/parser dependency. Metadata recording currently has no per-capture authority renewal. At an assumed
five-second sensitive-authority interval, 200 active sources add 40 renewals/s; a separate 64 MiB stream at 16 MiB/s would increase the
combined count to about 90/s and is rejected. Actual intervals and channel/SQL
costs must be measured. Per-packet local meter cost needs ns/alloc benchmarks.

Tests must prove requester/executor separation, independent review, original-time
clamping, no refill on grant replacement/restart, atomic quota/grant admission,
current revocation races and original wire-byte charging with zero retained output.
Migration 00102 follows packet funding 00100 and history 00101 and requires role/Down/Up qualification.
No collector runs locally; installed/native qualification uses agreed frozen
candidates on disposable runners, each run at most twenty minutes.

Accepted lower maxima use an indexed set-based monotonic clamp, in the same
transaction that publishes the accepted protected settings projection. Include
pending and approved grants, clamp from immutable RequestedAt, and never extend
on a later raise. No revision-history/read-time/pruning mechanism is added.
The synthetic PostgreSQL comparison in the implementation plan measured median
18.917 ms for 3,200 rows and 786.484 ms for 100,000 rows (maximum observed
1,885.476 ms), versus 50 and 1,563 committed 64-row pages. No global row cap
exists; one settings change/day and the scenario row counts are assumptions.
The benchmark is not qualification of the final SQL schema or deployed load.


One joined settings observer reuses the permission worker and its protected cached
client at a ten-second cadence. Its source/SQL failures are local to policy-grant
availability and cannot terminate permission/browser loops. Maximum additional
source proof traffic is 0.3 GET/s per installation, independent of workload count;
acceptance uses one SQL call per newly cached observation plus the lower-change
clamp above. Original source expiry, request cancellation and joined shutdown bind.

Request replay reads the existing immutable journal by full actor/client/key and
canonical original input choices before consulting current defaults or plans.
Zero lifetime remains the original default choice. Store the original approval
maximum with the settings revision and resolved recipe digest in reviewed scope,
distinct from later lower
deadline overlays; no historical settings lookup is required. Recovery returns only the frozen
result under current workload rights/final identity and accepted lower deadlines;
it never issues authority or refills budgets. Changed inputs conflict. This adds
one indexed point read and no new table, credential or worker.


Policy requester metadata requires current collection rights on the exact reviewed
workload, plus current identity and original observation bounds after reads.
Former requester provenance cannot reveal grant detail or requested-list rows.
Ad hoc metadata and independent current approver views remain unchanged. Service
requester identity includes client and kind. This uses one existing workload read
per Get or distinct workload in the bounded list and the existing final identity
read; no observer or extra credential is added.

Recorder scope projects collection fields only. Sharing and grantRef controls do
not change collection authority, original issue/expiry or spend. Activation replay
keeps the accepted sharing instruction until a separate authorized sharing control
applies; it does not silently apply newly authored recipients or limits.


## SQL accounting composition and upgrade

Migration 00102 extends the existing grant/request journal with conditional real
policy/workload scope, original request-anchored deadlines and cumulative pools.
Explicit attachment uses an immutable control receipt and never reattaches on a
historical reply. Accepted authored-grantRef changes clear the source pointer;
new collection acceptance clears an old scope's attachment. Neither changes old
expiry/spend or supplies encrypted audit authority.

Reuse the existing policy_occurrence for each capture's immutable original
capture/grant/output tuple. Tick has already spent the accepted execution;
admission does not spend it twice. The capture, accepted output and optional
grant execution/output are committed atomically. New acquisition checks retain
the original charged grant after replacement. Stored completion and publication
use their separate retained-authority/custody contracts; current source controls
are not a new finalization fence. All-before-filter sensitive observation pools
remain distinct from this native-output reservation.

Legacy schema-101 executions/occurrences cannot establish exact past output or
uncertain starts. On Up, conservatively fill original accepted output/observation
pools to their ORIGINAL authored maxima whenever any execution was spent or any
occurrence exists, including pending/refused/unlinked replies. This is uncertain
spend, not measured bytes. Pristine acceptances with neither signal remain zero.
One set-based migration UPDATE avoids a historical parser/journal or runtime
provider lookup. Previously spent legacy scopes intentionally cannot start more
collection; same-intent reauthorization/renewal is an unfinished lifecycle and
cosmetic edits must not become a budget reset. Down refuses preserved nonzero
pools or charged tuples rather than discard uncertainty.

Separate-role PostgreSQL/S3 component tests now pass original request/settings,
attachment ABA/replay, conservative legacy markers/pristine Up and unsafe Down,
and actual capture admission with four reservations, lost-reply/restart and a
refused fifth trigger. Exact source-bound reports and failed fixture runs are in
the implementation plan. The identity/review/control inputs remain synthetic;
public audit/request/review/UI/runtime composition, original-grant revocation
races and installed recorder/session qualification are still pending.


Current pinned sponsoring managers may directly inspect the existing grant's
policy/workload scope, original/effective dates and grant reservations after the
requester leaves. The earlier requester/approver-only engineering restriction
would make already-authorized attachment/revocation unusable; it is explicitly
revised. Reuse get_grant's existing mode-discriminated DTO and canonical browser/
MCP schema, never fake a Pod or create a second view model. Review authority stays
separate. Existing can_revoke reflects current real control rights, not immutable
requester provenance. One current workload projection supports all local checks;
there is no extra provider/SQL read, broader list visibility or evidence access.
Shared accepted-policy pools remain independently binding and must be visible in
the existing policy-status workflow; grant counters alone are not available
collection capacity.
