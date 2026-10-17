# ADR-162 — Read-only finalization of original owner projection effects

Date: 2026-10-14. Status: implemented; qualification pending. Requirements: REQ-DEP-003 and REQ-FED-001; existing
SC-DEP-003 / SC-FED-001 and TASK-03 / TASK-11 remain the traceability owners.

## Problem

The SQL59 separation qualifies unchanged fleet renewal alongside semantic SHARE
locks, but original installed-owner run 11 still fails after a projection effect
in its final native graph. The same SQL call records a live-context source-client
limiter refusal. This does not identify an individual failed HTTP request or
justify increasing deadlines, QPS or burst. The current operation combines
provider inspection, complete native admission, claim/current checks, one effect
and another complete native graph within the same original five seconds.

## Decision

For `OwnerProviderInstalledLayout`, select only bounded execution and mandatory
read-only finalization for its six projection and two launch transitions. Older
fresh-provider mutating entry points must refuse or use that same strict protocol;
they cannot retain a combined execution bypass. The actual `OwnerInstalledLayout`
legacy path and other owner role operations remain unchanged. This changes
installer orchestration, not a public interface,
SQL schema, Kubernetes permission or Helm enablement.

Execution retains original provider inspection, ADR159 split native admission,
public claim CAS, recovery/activation and role/advisory locks, actual postclaim
current checks, exact four-role SQL verification and its single fixed effect.
After the effect, recheck current SQL and the original deadline, close and join
all admitted work and transactions. Its output is only a spent **unverified**
transition. It cannot report acknowledged/complete or authorize another effect.
Every original claim/child/launch date, effect end and uncertain-attempt charge
is unchanged. Expiry can make a completed external effect unverified; it cannot
undo it or grant a replacement attempt.

One opaque process-local pending record binds the same live root/controller,
original installation/activation and immutable source/guard/provider identities,
resource/role-root UIDs, public layout/projection digest, fixed transition and
claim IDs/dates, exact before/expected journal state including siblings, known
child UID/resource-version pins, and dispatch/result disposition. Later execution
must compare those known child pins before any dependent receipt or effect; a
finalizer rejection after persisting a replacement receipt is too late. It contains
no credential bytes, token or private-payload hash. One pending transition
blocks every later Advance/Launch, including direct callers bypassing the driver.
Copies, foreign roots, consumed handles and reconstructed controllers cannot
recover authority from matching serialized fields or reset attempt accounting.

The first execution requires the original live role-root creation lineage and
completed independent verification from that same root. Merely opening an
already-persisted private role journal in a reconstructed root is insufficient.
An inert controller may be constructed before role creation, but no execution
may precede it. A new controller cannot adopt existing projection/launch progress;
every later execution requires its retained, successfully finalized predecessor.
Enforce these conditions at the serialized operation boundary, including calls
that passed an earlier entry check before waiting. The selection is process-local
and has no restart/resume producer or new durable global ownership record. It
does not turn historical receipts into reconstructed continuation authority.

Finalization receives a new at-most-five-second **observation** interval within
the still-live original caller/root/setup lifetime. It may inspect an effect
whose original write interval has ended; it never reopens that interval or the
closed execution handle. All newly learned bounds only narrow its own interval.
Fresh current provider/administrator/source/recovery facts must match the
original pending semantic identities; an elapsed effect proof is historical,
not relabeled fresh authority.

Execution also pins SQL59 `semantic_version` through its existing locked SQL
authority read. The pending record retains that exact value; finalization compares
it under the same authority locks. A suspend/resume or semantic A → B → A change
cannot become an unchanged root merely because current visible values match.
Positive observation renewal leaves the version unchanged and may support the
new read-only proof without extending the original effect. This is a narrow
additional scalar read, not a change to the nine-column `fleet_current_trust`
view or schema. No later version may replace the execution pin.

The finalizer performs only fixed GETs, identity reviews, existing dry-run denial
probes and SQL reads/locks. No object CREATE, persistent PUT/PATCH/DELETE, journal
CAS, role DDL, signing, receipt persistence, compensation or generic callback is
reachable. Its fixed sequence is:

1. Observe the provider and start the existing incomplete native prefix.
2. Acquire recovery/activation and role/advisory locks through a purpose-specific
   original-root admission handle before completing the prefix or reading the
   private role journal. An incomplete prefix is not an admitted role snapshot.
3. Complete native admission and independent accepted-owner SQL checks, then
   reconstruct private material and compare the exact pending identities/state.
4. Read the known child results and independently verify all four SQL roles.
5. Run actual complete current comparisons after those blocking reads; reread
   immutable children with the same known UIDs/resource versions. Launch keeps
   its original Deployment UID/spec/marker and existing status-update semantics.
6. Check current SQL and all original caller/finalizer bounds through commit and
   output; close/join before returning a local verified result.

One complete enforcement bracket plus post-read current comparisons suffices
only for this fixed read-only finalizer. Do not add a skip-final-check flag or
reuse it for mutating effects. The next distinct execution must establish its
own fresh authority; the verified result is not a reusable execution permit.

## Known identity, uncertainty and receipt consumers

A positively returned CREATE identity may supply a candidate UID/resource version
only after validating that exact API response. It is not independent verification.
A retained original receipt is another known pin. A lost CREATE reply with neither
pin remains unverified: matching name, bytes or an operation annotation cannot
establish that a replacement never existed. Neither finalization nor the older
inspection fallback may adopt a new UID or allow the next transition in that case.

An uncertain journal CAS has an already-known resource-root UID and exact expected
replacement. Read-only confirmation may recognize that exact committed result
only if execution already retained the locked SQL semantic-version pin. An
unknown initial claim CAS before that pin remains unverified; finalization cannot
invent the missing earlier authority. It cannot retry an absent/uncertain CAS,
change siblings or reset process-local
receipt-attempt spend. The narrow protocol permits no automatic restart/resume
of an unreceipted transition after its original live controller has been lost.
Existing committed receipts can still be independently inspected under the
existing current-authority requirements; they cannot mint a new pending record.

Persisted receipts remain immutable historical provenance. Their consumers must
keep their independent current verification: `InstalledOwnerIdentityReader`
checks native protection, online Pod token/controller identity, mounted objects
and exact receipts before SQL credentials; runtime then checks current accepted
configuration/recovery/roles/registration. `ReadCapacityLocalOwner` checks the
original journal, configuration/Deployment/account/Service objects and current
source before returning public provenance. Shape validation alone grants no
authority. Neither consumer relies on an unverified local execution return.

A launch can already start the Pod before installer finalization succeeds.
Independent runtime admission remains mandatory; failed installer finalization
is not rollback, Pod termination or proof that no effect occurred. There is no
promise of uninterrupted historical guard protection across the gap: the result
is current verification of a known original effect, never retrospective renewal.

The finite driver schedules eight explicit finalizations in addition to the
existing eighteen normal calls. Count them separately from its single permitted
unknown-result inspection. No sleeps, polling, silent retry, replacement ID,
limiter reset or longer parent deadline is introduced. Failed/cancelled/expired
finalization retains spend and stops; shutdown joins owners before release.
The driver's `Complete` summarizes historical completion of its fixed invocation;
it carries no observation lease and grants no current runtime/effect authority.
Its enclosing ownership and cancellation callbacks must join before return, and
original caller cancellation or component closure during cleanup must suppress
success. Independent current checks remain necessary for every later consumer.

## Qualification and limits

Source-derived normal graphs predict at most 56 source-client requests per
execution or finalization, versus at most 87 within a previous combined phase;
total work increases and the sixteen provider GETs occur in each phase. These
are planning counts, not measured latency or an availability guarantee. All
original six clients retain their 20-QPS/burst-20 buckets across phases.

Required checks cover exact graph counts; zero finalizer persistent writes;
known/unknown CREATE identity; exact committed/uncommitted CAS outcomes; mutation,
replacement and source/incarnation changes; unchanged renewal versus repeated
SQL fencing, suspend/resume and semantic ABA; original effect expiry versus fresh
read-only verification; original caller/root cancellation; copied/foreign/reused
handles; alternate legacy entry points, reconstructed roots/controllers and
calls queued before split selection; one inspection and eight scheduled
finalizations; private reads after all locks; and joined cleanup. Test receipt
consumers independently of the finalizer. Then qualify the actual SQL seam,
unchanged original native installation and full affected regression gates.
No component count or source review establishes installed availability. Results
belong in [implementation progress](../implementation-progress.md).
