# ADR-263: Ordinary ongoing source active leases

Status: accepted engineering contract (2026-10-29); local source components implemented; full workflow and qualification pending.

## Decision and scope

Select a fixed active leaf of at most thirty seconds for a **new private typed
ordinary sanitized ongoing packet source-purpose commitment**. This interval is
an agent engineering choice under the maintainer's proportionality instructions,
not a maintainer-required interval or the download timing clarification.
Existing PolicyArm result.ValidUntil, ADR-261 finite sensitive observation,
manual capture, browser and download permits remain unchanged. No raw predicate,
HTTP-content or syscall argument authority is added. No production caller is enabled.

New admission and every renewal require exact current accepted policy,
delegation/permission, complete deny, recovery, retention, target and local
process facts under their original at-most-five-second issuance bounds. Recheck
after blocking work, before commit/sign/dispatch. Do not replace these checks
with a thirty-second precommit permission cache or renew an observation timestamp.
Source admission must consume a protected source-resource projection of administrator ceilings;
see [resource projection](262-protected-ongoing-resource-projection.md). No new default
resource limits are selected here.

Atomic issuance fixes:

`leafUntil = min(issuedAt + 30s, all applicable original fixed hard ends)`

Hard ends include accepted policy/binding, required review/grant, source session,
local process and administrator/privacy ends. Each leaf also fits the currently
proved certificate expiry and same-identity capacity pool/allocation/control-account
coverage. Renewing those current observations does not replace the immutable
source session, funding identity, counters or ring. Their old transient coverage
cutoffs are not fixed session ends, but no leaf may exceed currently proved
coverage. Transient check expiry
is distinct from these immutable bounds. A receipt or attach cannot restart
issuedAt. Each renewal has a **new original five-second issuance operation**;
this is distinct from the initial source start cutoff. A delayed initial start
cannot acquire a fresh window through renewal or replay.

Per-segment content expiry remains acquisition-based: the first packet expiring
does not stop the continuing source. Erase expired segments on their original
schedule; snapshots inherit the earliest expiry of their included segments.
No source leaf extends content retention or snapshot processing.

## Continuity, credit and control

Renew the same source identity/fence, accepted action and actual Pod/node/boot/
collector binding with monotonically later absolute IssuedAt. Preserve original
StartedAt,
session/hard end, counters, rate tokens and ring. Exact duplicate content is
passive replay; earlier or conflicting issuance and changed bindings refuse. An
ended incarnation cannot be revived. Extending accepted policyAuthority itself
still requires fresh acceptance/applicable review.

Credit is cumulative: `newCredit = oldCredit + additionalCredit`. Quiet renewal
may retain the same positive credit with additionalCredit=0 while prepaid credit
remains, including when no unallocated parent credit remains. It still needs
fresh current facts and locked current source/terminal reads, with no source-state
UPDATE or additional debit for a quiet renewal. Only positive credit increments
use a durable expected-credit CAS. Row locks may themselves generate WAL; this
is not a WAL-free or unlimited-backing claim. Any positive increase prepays exactly
its positive delta; never refund, refill, reset or blindly debit rate×30 each
fifteen seconds. Charge original wire length before filtering, including discarded
records. Keep measured local input distinct from conservative reserved spend;
unknown input cannot invent zero or release charges. Ordinary accepted input
allowance must be positive; zero forbids acquisition. A required ordinary review
grant with Observation=nil does not create a sensitive raw input pool.

Use the existing fifteen-second policy scheduling loop for due maintenance,
independently of incident busy/cooldown and incident maxPods. Arm all authorized
replicas within source ceilings, without fake captures/executions. A tick is not
a completion guarantee: missed renewal stops at the previous leaf. Hold source
count/ring/rate/burst reservations once, not once per renewal.

Keep the engine/ring context bounded by its ORIGINAL hard session/policy end.
The owner separately enforces the current leaf with one bounded expiry timer
and serialized callback checks. A queued obsolete timer callback must compare
the current issuance/deadline under the existing owner lock before stopping.
No fast loop, watch, new cadence knob or source replacement is introduced.
Cancel acquisition on expiry/received negative; join before releasing resources,
never from inside a packet callback. This local owner lifecycle has component
tests; actual native source and whole-workflow qualification remain pending.

An authoritative negative blocks new admission/renewal; a received exact-source
negative stops via connected control/lifecycle. No new notification watch or
instant partition-proof stop is promised. Unknown/disconnected authority ends
at the original leaf, at most thirty seconds after issuance. Time from a physical
external change also includes separately qualified observation/propagation lag.

Leaf expiry, revocation and exhausted authority override REQ-LIF-006 stopped
source grace. Existing natural-stop grace remains separately bounded, not a new
lease grace. Already admitted copied snapshots may finish only within their
original processing/storage/privacy bounds. Quiet expiry must stop and erase
unsaved live bytes; never fabricate a sourceStoppedAt timestamp from cancellation.

## Journal and custody

Reuse acknowledged accepted-policy audit and existing audited public activation/
review mutations. The source journal is **bounded current state per source**,
not an append-only event row per tick. It records the original binding, cumulative credit and
terminal state; it is not current authority. Quiet IssuedAt/leaf changes are
node-owned live state and do not rewrite a durable source row. The SQL logical
slot stays occupied until an explicit terminal fence plus conservative in-flight
leaf/join/reference settlement, or its immutable hard end; an old stored leaf
never proves current expiry. Initial source creation consumes one existing
ordinary full/replay metadata-record unit, not a fictitious capture. The four-slot
reference workload consequently has room for one source and three incident
records. Smaller allocations require measured whole-graph qualification.
No mandatory encrypted intent/outcome object pair per ordinary source Pod is added.
Commit prepaid/source state before purpose-specific signing and authenticated
exact-node delivery. An unknown receipt retains spend and the same identity.
Saved incidents retain their separate output/storage/custody/audit sequence.
Unsaved sanitized source rings are local bounded RAM, with no evidence registration,
UI/MCP projection, processing artifact ID or processing-budget counter. Arming
still checks current retention, recovery and team permission. Every Save separately
checks current processing, placement, lineage, deletion, custody and output
requirements. No source arm creates a processing service or permits plaintext PVCs.

## Complexity and qualification

1. Benefit: required ongoing acquisition; no installed defect is attributed here.
2. Accepted risk: bounded rechecks/proportionality, not this specific interval.
3. Applies to ordinary ongoing sources; sensitive/manual/download stay separate.
4. Reuse cumulative prepaid meters and existing policy scheduling, no new journal framework.
5. New credentials, key provider and deployment dependencies: zero. The existing policy-automation SQL duty gains purpose-specific source table/current-resource reads and accepted-input counter writes; exact privileges and real SQL qualification remain required.
6. Live, stopped/expired and unavailable outcomes; replay adds no fallback authority.
7. New tuning-only configuration: zero.
8. Depends on current producers, authenticated control and engine cancellation/join.
9. At 64 sources/15 seconds: about 4.27 logical renewal checks/s before batching, not measured throughput. One timer/source; no packet API/SQL or second ring. Quiet renewal has zero source-state UPDATE and additional input debit but still current locked reads. Content-free cumulative source status uses the existing fifteen-second node report, with a bounded row per owned source, not a second cadence. A matched older quiet-leaf status remains accounting feedback; it is not a current permit or attach ACK. The purpose-specific node status bound is 512 KiB for at most 1,088 owned-source/replay rows; enrollment/poll request bounds remain 64 KiB. Actual transaction/API/WAL, report CPU and aggregate fleet costs remain to measure.
10. No rollout/disable/runtime qualification is claimed; strict old-node refusal must qualify.
11. Reuse the fifteen-second loop with thirty-second leaves instead of a fast loop or repeated full-rate prepay. Naive twenty-Pod cold-arm 160 GET/180–260 SQL is not an accepted performance promise; reuse/batch original same-request facts and locks before enabling.

Required controls: fresh issuance versus expired/future/changed facts and lock/
sign/dispatch cutoff; all earlier hard ends; quiet delta-zero renewal and exact
positive debit; duplicate/conflicting/restarted binding; delayed initial arm after an earlier
received stop (node enqueue sequence alone is insufficient); queued stale timer,
quiet expiry and joined resource release; received negative versus partition;
all replicas versus incident cap; unchanged original pre/post windows and known
gaps/clock uncertainty. Ledger, producer, typed wire and local owner now have
component implementations. Save composition and installed source/whole-workflow
qualification remain next work. No global event-time watermark,
new service, kernel mechanism or acquisition authority is created by this ADR.

## Local composition and measured boundaries

The private typed `packetSource` work binds the original accepted policy,
source/fence, exact Pod/node/boot/collector epoch, resolved filter/ring plan and
protected resource lowerings. `SourceWork` uses the existing installation work
key and current trust with a separate ordinary-source JWS purpose and frame.
The signed payload encodes the existing little-endian eight-byte BPF instructions
as bounded base64 bytes, verifies their program digest and reconstructs the typed
program before node delivery. It retains the real signers' 16 KiB input limit;
source payload/signed-frame caps are 11/16 KiB. A controlled maximum-program,
legal-name and escaped-key-ID test used the actual Transit adapter against an
owned TLS stub: 10,742-byte signing input, 10,829-byte signed work, one HTTP sign.
That is codec/adapter evidence, not live-provider or packet-engine qualification.
Its short regional exchange only queues work; a queue result is not an attach
ACK or coverage proof. The node poll loop passes the process context to the
owner, not the five-second issuance request. Same-process reconnect/renewal
keeps its owner and ring.

The node reserves aggregate source count, physical ring, input rate and burst
once before allocation. Initial admission intersects configured ceilings with
current source-resource lowerings against already held node resources; a quiet
renewal does not reserve again or stop an existing source solely because an
unrelated later admission changed aggregate usage. A changed protected resource
binding cannot silently renew. Copied windows keep independent frozen capacity
and their original processing deadlines after live-source shutdown.

Source status uses the existing fifteen-second report, with cumulative credit,
observed wire bytes, exact source/fence/issuance and distinct natural Stopped,
Closed and unknown-input facts. Its timestamp is sampled at the original source
set snapshot before later blocking metadata; a newer query or receipt timestamp
cannot prove an older empty snapshot happened after an arm cutoff. A matched
older quiet leaf remains accounting feedback, not current acquisition authority.
Unknown/missing status is never measured zero. Initial credit is at most one
active leaf plus the existing one-second burst and a fair share of the actual
complete candidate cohort; SQL clamps it to remaining accepted input. Later
positive increments use the matched measured remaining credit, not an automatic
full-rate debit on every tick. Current effective content expiry minus its original
anchor must cover the selected ring age; the requested retention alone is not
proof of that effective age. A complete report predating the
original start cutoff cannot prove that a still-startable source was absent.

Required metadata observation batches share one original five-second regional
peer/source proof, retaining input order and per-item refusal. Per-Pod Kubernetes
reads remain unchanged. Sixteen maximum legal-name/full-state replies measured
45,985 bytes, exceeding the existing 31,744-byte body budget. The fixed batch
limit is eight; no frame limit increase or truncation was selected. This reduces
regional round trips, not a demonstrated API/SQL/signing or full-workflow cost.

A controlled node regression reproduced Stop being enqueued before a paused,
already-committed initial Arm: node Work.Sequence correctly ordered enqueue but
the later-sequence Arm still started. A bounded exact-source stop tombstone
through the original maximum five-second initial-start interval closes that
race; expired renewals cannot construct replacement engines. This is local
current-state fencing, not another durable event journal or restart protocol.

The SQL/producer, current custody of saved incidents, installed all-replica
continuity and packet-engine/resource qualification remain separate evidence.
Public compilation stays finite-only until the ongoing source and Save workflow
is qualified. These local components do not enable public ongoing collection.
