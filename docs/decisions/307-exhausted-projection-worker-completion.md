# ADR-307 — Natural completion of exhausted projection workers

Date: 2026-11-05. Status: implemented with named local and installed-test qualification
under standing engineering delegation. Requirements: REQ-MCP-002, REQ-EVD-005/008,
REQ-AUT-006; TASK-02/08/11.

## Observed problem

Native42044789919 completes five fixed single-batch projection results, but the
worker loop reconnects after every joined conversation until its original
RunUntil. Once the only admitted batch has been consumed, that process cannot
perform another useful read. Its live process and conservative physical slot
remain occupied. The installed worker declaration is384MiB/500m and its query
lifetime60s; these are ceilings, not measured memory or CPU usage.

The five fixed views take148.24s including15.86s of HTTP calls and roughly
115–120s of deliberate fixture polling waits. Those observations do not prove
that four immediate polls would find a cold worker ready, so the finite poll
budget and schedule remain. The120s accepted-review expiry proof also remains.
Natural completion addresses exhausted product work, rather than changing
these qualification checks. Any suite-time saving still requires measurement.

## Decision

An authenticated projection conversation may report process-local exhaustion
only after its exact final joined acknowledgement has been validated and its
reader, buffers and stream have joined successfully. Its trusted decoded scope
must allow exactly one read batch and the completed generation must be one.
The bootstrap loop may then return successful completion and cancel/join the
credential child before the process exits.

The private credential callback has the production supervisor's error-origin
contract: `context.Canceled` is returned only from its supplied context, not
forwarded from an independently cancelled enrollment/provider operation. The
sole runtime composition uses `WorkerCredentialSupervisor.Run` with
`waitWorker`; enrollment failures are normalized before reaching the pair.
A cache-only audit substituting an arbitrary callback that independently returns
`context.Canceled` reproduced false success in 46 of 50 concurrent cases. That
callback is outside this contract: the error value alone cannot prove its origin.
Keep the actual-supervisor regression and this limitation when changing the
composition; no generic cancellation-origin mechanism is added.

The exhaustion disposition is private process information, never a field of a
wire message, public result, signed authority, SQL row or caller instruction.
A remote message cannot supply it. Premature credential completion, cancelled
work, failed close, missing/wrong/lost final acknowledgement and uncertain
outcomes do not become successful completion. Existing multi-batch projections
and native download conversations retain their current behavior.

Keep original RunUntil, query/source/permission dates, worker limits and all
nonrefundable spend unchanged. A result or process-local flag is not a SQL
termination or retirement proof. Product cleanup must independently
observe the exact admitted Job/Pod termination and record positive retirement
before capacity can be reused. Missing objects alone remain insufficient.

The existing bounded cleanup selector may additionally return an unexpired,
bound, claimed single-batch query only when existing SQL proves generation one,
no active or uncertain read, and an exact closed/native-closed batch associated
with that query, worker binding, claim and native-operation reference. Recheck
the same predicate under the existing worker lock before confirming early
termination. The existing runtime SQL role gains EXECUTE on the already-defined
`context_query_read_batches(jsonb)` helper, so selection shares its canonical
classifier. This SQL IMMUTABLE function has a fixed `pg_catalog,pg_temp` search
path, reads no tables and is not SECURITY DEFINER; it derives only an integer
from supplied metadata. No new role, schema or effect authority is introduced.
The Go scope check remains independent. No future timestamp may be substituted
for the current clock.
Unbound, multi-batch, still-running and uncertain cases keep the existing path.
The Kubernetes adapter delegates a bound worker to its existing exact positive
termination observer; the original expiry restriction still protects unbound
abandonment. Keep the order: persist termination, UID-bound deletion and observed
absence, persist retirement, then reuse physical capacity. Logical read/key/byte
spend is never replenished by this physical cleanup.

Qualification may observe actual single-batch termination before RunUntil;
RunUntil is an upper bound, not a minimum process residence. The exact identities,
controller ownership, container termination, timestamps and SQL readbacks remain
mandatory. Multi-batch/download fixtures retain their original bounded waits.

## Complexity assessment

| Question | Answer |
| --- | --- |
| Frequency/harm | Five fixed queries in the observed run; every successful exhausted single-batch projection follows the same reconnect loop. Live-slot occupancy is concrete; deployment frequency is unmeasured. |
| Accepted risk | No maintainer requirement for a minimum worker residence was identified. Original maximum dates and conservative cleanup remain. |
| Typical benefit | Yes: releases exhausted worker processes through normal completion. |
| Precedent | Uses the existing joined native conversation and credential-child shutdown mechanisms; no new supervisor or protocol. |
| Added privileges/network | Zero new credentials, roles, API kinds or network destinations. One existing pure batch-count helper gains EXECUTE in the compiled runtime profile; no table or effect authority is added. Newly eligible foreground cleanup can add an existing exact Job/Pod observation walk. |
| Added failure/fallback states | Zero fallback modes; only an explicit successful exhausted-work disposition. |
| Added configuration | Zero. |
| External dependencies | No new component or behavior. Existing Job/Pod terminal observation remains mandatory. |
| Aggregate cost | One process-local boolean and branch; existing16-row cleanup bound and foreground demand only, no background polling/watch. Early candidates can add existing API attempts; the current walk permits at most44 resource REST calls plus unchanged input guards, within the existing caller/5s bounds. They remain charged when not terminal. Idle reconnects can end earlier. Savings are unmeasured. |
| Rollback | Original wire and SQL schema remain compatible; existing selector/recheck queries gain the strict early predicate. The prior worker retains its previous lifetime behavior. No stored authority or budget migration. Existing compiled-role reconciliation must apply/remove the helper grant on upgrade/rollback; installed operational qualification remains separate. |
| Smaller alternative | Fixture-only faster polling cannot prove readiness or eliminate exhausted product occupancy. Shorter deadlines, weaker retirement proof and dropped expiry/view/Stop checks are rejected. |

## Verification boundary

Require regressions for final-ACK/close/join before exhaustion, single-batch
natural success, two-batch/download retention, cancellation, premature credential
exit, serialization exclusion and joined credential shutdown. Retain actual
Job/Pod and positive SQL retirement assertions in fresh installed qualification.
Local lifecycle tests are not installed cleanup or a full20-minute workflow pass.

The installed test on signed51344180 (PR171) observes exact positive Job/Pod
termination and SQL retirement with original RunUntil retained; raw two-batch
queries retain their behavior. Go/harness finish0 with complete cleanup and
source verification. The outer job is cancelled after a GitHub upload-finalization
failure crosses its20-minute limit; this is not a green hosted workflow or a
universal performance claim. [Original report](../../test/results/saved-syscall-query-native-42065554713/README.md).
