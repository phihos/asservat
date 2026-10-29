# ADR-263: Ordinary ongoing source active leases

Status: accepted engineering contract (2026-10-29); runtime implementation and qualification pending.

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
local process/certificate and administrator/privacy ends. Transient check expiry
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
collector binding with a monotonic sequence. Preserve original StartedAt,
session/hard end, counters, rate tokens and ring. Exact duplicate content is
passive replay; lower/conflicting sequences and changed bindings refuse. An
ended incarnation cannot be revived. Extending accepted policyAuthority itself
still requires fresh acceptance/applicable review.

Credit is cumulative: `newCredit = oldCredit + additionalCredit`. Quiet renewal
may retain the same positive credit with additionalCredit=0 while prepaid credit
remains, including when no unallocated parent credit remains. It still needs
fresh current facts and a source-state CAS. Any positive increase prepays exactly
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
the current sequence/deadline under the existing owner lock before stopping.
No fast loop, watch, new cadence knob or source replacement is introduced.
Cancel acquisition on expiry/received negative; join before releasing resources,
never from inside a packet callback. This lifecycle is required future runtime,
not an implemented promise.

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
review mutations. The source journal is **bounded current state with CAS per
source**, not an append-only event row per tick. It records the original binding,
sequence, cumulative credit and terminal state; it is not current authority.
No mandatory encrypted intent/outcome object pair per ordinary source Pod is added.
Commit prepaid/source state before purpose-specific signing and authenticated
exact-node delivery. An unknown receipt retains spend and the same identity.
Saved incidents retain their separate output/storage/custody/audit sequence.

## Complexity and qualification

1. Benefit: required ongoing acquisition; no installed defect is attributed here.
2. Accepted risk: bounded rechecks/proportionality, not this specific interval.
3. Applies to ordinary ongoing sources; sensitive/manual/download stay separate.
4. Reuse cumulative prepaid meters and existing policy scheduling, no new journal framework.
5. New credentials/privileges/provider calls selected by this contract: zero; purpose-specific SQL/wire still requires review.
6. Live, stopped/expired and unavailable outcomes; replay adds no fallback authority.
7. New tuning-only configuration: zero.
8. Depends on current producers, authenticated control and engine cancellation/join.
9. At 64 sources/15 seconds: about 4.27 logical renewal-row operations/s before batching, not measured throughput. One timer/source; no packet API/SQL or second ring. Quiet renewal has zero additional input debit but still current checks/CAS. Full transaction/API/WAL costs remain to measure.
10. No rollout/disable/runtime qualification is claimed; strict old-node refusal must qualify.
11. Reuse the fifteen-second loop with thirty-second leaves instead of a fast loop or repeated full-rate prepay. Naive twenty-Pod cold-arm 160 GET/180–260 SQL is not an accepted performance promise; reuse/batch original same-request facts and locks before enabling.

Required controls: fresh issuance versus expired/future/changed facts and lock/
sign/dispatch cutoff; all earlier hard ends; quiet delta-zero renewal and exact
positive debit; duplicate/conflicting/restarted binding; queued stale timer,
quiet expiry and joined resource release; received negative versus partition;
all replicas versus incident cap; unchanged original pre/post windows and known
gaps/clock uncertainty. Ledger, producer composition, typed wire, owner lifecycle,
Save and installed qualification remain next work. No global event-time watermark,
new service, kernel mechanism or acquisition authority is created by this ADR.
