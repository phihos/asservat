# ADR-323 — Finite share metadata and public audit retirement

Date: 2026-11-11. Status: candidate implemented; bounded wide100 cost sampler passes, installed qualification pending.
Requirements REQ-PRV-008, REQ-PRV-004 and REQ-SHR-001 through REQ-SHR-008.
Scenario SC-PRV-015 binds the finite share and audit-retirement workflow.

## Observed gap and scope

Share expiry denies access, but `protect_evidence_share` rejects every DELETE.
The 32-active-share limit does not bound revoked/expired rows. Public normal and
resolution audits have a retirement implementation but no installed retirement
runner. The capture cleanup component and projection builder also need actual
installer provisioning; they are not evidence of an installed consumer.

Complete one workflow: create and use a share, end its access, retire its
identifying row with its original audit obligation, verify managed audit-object
absence and retain the charge through the original residual-history interval.
Cover manual, capture-time and recurring concrete shares through the same SQL
dependency. Recipient copies in capture instructions, policy acceptances and
broader control records remain separate obligations; deleting one table cannot
certify their erasure.

## Implementation direction

Use existing finite normal/capture operation slots instead of a new lifetime
share quota. Measure the additional share/index/TOAST and complete mutation WAL
before changing their qualified layout or enabling the new admission path.

Manual creation carries its private server operation ID through the internal
sharing input. Capture publication uses the existing `intent_operation_id`.
Persist one immutable creating-operation reference per share. A unique binding
and an existing-transaction effect check prevent one paid operation from creating
multiple shares or repeating a mutation. Later transfer/revoke operations pay
their own bounded effect cost; revoke-all already affects at most 100 concrete
shares. Preserve the existing 32-active and recurring-100 limits.

The share inherits original accepted live-removal and hard-retirement bounds;
neither publication, mutation, backing renewal nor replay moves them. Its access
must fit no later than `original_purge_at`, the earliest original cleanup path,
rather than the later certificate cutoff. Refuse incompatible backing
before creation with an explicit remedy; do not silently extend an audit or
shorten an acknowledged share. Do not invent creating-operation links for old
unqualified rows. Retained-state upgrade and rollback must either preserve the
proved layout or refuse clearly without deleting/adopting data.

Delete the dependent share inside existing operation finalization, before the
operation row. Keep direct DELETE denied and retain the existing private
finalization marker. Original objects, terminal verification and actual
SQL-retirement-plus-H cooling remain the release conditions. Failed or unknown
cleanup retains the original charge. No share-specific cleanup state or worker
is needed.

Serialize insertion against finalization by locking the original creating audit
before inserting the share. The finalizer keeps recovery → pool → account →
operation → lifecycle → share order and acquires no artifact, permission or
storage lock afterward. Mutation must not lock the parent audit after the share.
Missing/retiring capture backing yields SharingUnavailable; publication may
still succeed, but it cannot rematerialize a retired or revoked child.

## Replay contract

The stable business key differs from each invocation's fresh audit operation ID.
Within the original retained replay window, a currently authorized retry returns
the original share and deadlines; changed input conflicts. The private operation
reference must not become a new equality requirement for legitimate retries.

After identifying replay metadata retires, recognition of its old opaque key is
not promised. A fresh, fully authorized manual decision may use a previously
used key string in a new window. The public API already requires an absolute
expiry, so an expired original request cannot acquire a fresh default lifetime.
This is an explicit finite contract replacing incidental lifelong deduplication,
not a new maintainer requirement. No permanent tombstone or extra preflight is
introduced. Capture publication retains its stricter original-instruction rule.

## Installed composition

Extend the existing cleanup component to the closed capture/normal/resolution
lane set. Share its three existing facet pools and provider clients across
one scoped adapter, with one total page of at most 16 operations and a global
UUID cursor that wraps after its final page. Do not add concurrent per-lane loops or a separate share
cleaner. The installer must actually provision the protected projection and
credential material and the supervisor must own and join its task.

Current writers use the owner audit provider, but historical equality is not
implied. Pin the accepted store/key/signing associations and deduplicate only
proved identical scopes. Never try alternative keys or infer an old binding
from today's configuration. Preserve cleanup/verifier storage separation and
the exact SQL facet grant union. Keep identity/processing lanes, source
acceptance and evidence-key authority outside this expansion.

The four closed provider purposes reuse the native worker login/lifetime
machinery. First use needs four login/lookup-self pairs (eight HTTP requests);
healthy reuse adds no provider refresh request. Renewal needs two requests for
each due slot, only during later cleanup work. This operation count is covered
by component regressions; combined installed latency is pending. The existing
audit-wrap role also retains its exact selected signing-key path when that
optional key is selected. This is the same worker/key scope as cleanup-sign,
with no additional role, token, key or separate signer-selection flag.

## Complexity and qualification

| Question | Answer before implementation |
| --- | --- |
| Observed benefit | At `2a2bc0f1`, 65 shares remained while only 32 were active. The sequence grew relations by 1,114,112 bytes and whole-instance WAL by 1,085,704 bytes in 1,160 ms. These observations are not maximum-footprint qualification. |
| Accepted risk | No maintainer acceptance of indefinite identifying share history. |
| Typical deployments | All three concrete sharing producers and normal public audit apply. |
| Precedent | Reuse C-08 retirement. Argo uses finite completed-control retention; PostgreSQL supplies the row-lock conflict used for the proposed transaction. Neither proves backup erasure. |
| Added exposure | Activate 3 already-provisioned SQL logins, 2 operator-supplied S3 credentials and 4 closed provider purposes (wrap, open, independent verify-open, sign): 9 active bindings, 0 new SQL role identities. The provider roles reuse native proof-bound login/lifetimes. No collectors or evidence keys. |
| States | Zero new lifecycle/fallback states; existing healthy, overdue and unavailable behavior remains. |
| Configuration | Zero new lifetime quotas or cleanup-tuning knobs. Existing qualified retention/backing must cover the effects. |
| Dependencies | Existing PostgreSQL, audit storage/provider and qualified residual-history inputs. |
| Aggregate cost | Three cold pools (MinConns 0, MaxConns 1) activate at most +3 connections per worker, +6 across two retained workers. These are already included in the separate 20-pool worker compartment and compiled 114-connection installation requirement. API hub 32 is unchanged. Existing supervisor task; 0 new deployments, watches or child goroutines. Measure provider work, sustained normal-read retirement and capture progress; pool bounds do not prove throughput. |
| Upgrade/disable | Qualify original layouts and empty rollback; unknown retained links or provider scopes cannot be adopted. Disabling work cannot certify timely erasure. |
| Smaller fix | Raw scheduled DELETE omits paid history, late publication and residual reuse. Coupled existing finalization avoids another cleanup protocol. |

The current count-maximal eight-manager/eight-recipient baseline used compiled
hub grants and an actually published artifact. At `2a2bc0f1` its owned service
run passed in 8.170 s. All 4,546 source hashes matched; source stayed frozen,
cleanup failures were empty and owned PostgreSQL/S3/KMS containers were absent.
Whole-instance
WAL deltas and real tuple/index growth are observations, not universal maxima.
The 100-share transaction and the integrated additional layout still need their
own measurement. Do not label a fixture-gated compile run as service execution.

The first width experiment found that simultaneous individual field maxima
(2,048-byte issuer, eight sponsors/managers/recipients and 256-byte identifiers)
produce a domain-valid 73,469-byte immutable acceptance, beyond the existing
65,536-byte encoded-record cap. Preserve that cap and its refusal before
collection. A separately labelled wide sample uses a 1,536-byte issuer with
the same counts/identifier widths; its pure fixture record is 59,133 bytes.
Actual admission/publication and 100-share costs still require service results.
Neither the narrower sample nor the structural rejection is universal maximum
footprint qualification.

### Measured mutation cost and smaller correction

At `dac2d40d`, all 100 wide captures/shares, explicit rollback, paid revoke-all
and fresh-operation replay completed their semantic assertions. The final
funding assertion refused the result: paid revoke-all produced 6,731,960 bytes
of whole-instance WAL and rollback 7,703,136 bytes, beyond the original synthetic
2 MiB transition bound (and the 256 KiB installer example). Each mutation also
grew indexes by about 1.7 MB and TOAST storage by about 1.66 MB. These include
page images/background effects, not universal per-statement maxima.

First remove whole-row JSON serialization from the immutable-field trigger and
keep recipient GIN entries only for unrevoked shares. The proposed exact tuple
comparison preserves all 21 immutable columns and branch-specific restrictions;
both recipient-key queries already require `revoked_at IS NULL`. This adds
zero rows, role identities, permissions, background tasks, configuration or
lifecycle states; it replaces one index predicate and its empty rollback.
Ordinary revocation benefits too, while avoiding a blanket increase in every
normal-read reservation. The existing artifact-index predicate still changes,
so this does not promise HOT updates or TOAST reuse. Rerun the same sampler
before accepting a smaller cost bound. A separate narrow mutable-state row is
deferred unless these measured simplifications are insufficient.

Mechanism references checked 2026-11-11: [PostgreSQL HOT](https://www.postgresql.org/docs/current/storage-hot.html)
and [partial indexes](https://www.postgresql.org/docs/current/indexes-partial.html).
They explain update/index behavior; they do not qualify this candidate.

The small patch at `a3ca495f` preserved all 100-share semantics and the paid
revocation/management-mutation refusal. Paid WAL fell to 1,949,488 bytes
(71% lower), rollback to 2,957,808 bytes (62% lower), and paid TOAST growth to
zero. Schema upgrade/rollback passed with both index forms. Rollback still
exceeds the original 2 MiB fixture transition value; the run remains a failure.

Fund that bounded business effect once per normal-v4 slot, separately from the
existing per-transition audit-protocol allowance: add a fixed 8 MiB business-WAL
allowance inside each of the same two residual generations and WAL-copy count.
Keep the 24 baseline transitions and finite purge-lease costs. This applies
only to normal/resolution-v4 layouts; it never promotes or changes old layouts.
The source compiler and SQL validators must calculate the same amount before
admission, and the 100-share test must compare its complete paid/aborted effect
to this separately prepaid allowance. The per-transition field continues to
qualify the audit protocol; it is not redefined as an average.

Eight MiB is a conservative engineering allowance above the observed 2.96 MB
aborted effect, not a universal physical-layout proof. With 256 KiB transitions,
four purge leases and three WAL copies, normal-v4 reserves 102 MiB per slot
including both generations, versus 54 MiB before this allowance. Raising every
transition to 8 MiB would reserve 1,728 MiB instead. This is zero new rows,
state, configuration, reads, roles or workers: one versioned arithmetic term,
reusing current prepaid slots and release. It avoids a new mutable-state table
and its joins/locks while preserving conservative unknown-effect accounting.

Then qualify actual upgrade/rollback, all three producers, original cutoffs,
replay, late publication, mutation/finalization concurrency, recovery refusal,
unknown effects, direct-DELETE denial, provider scope rejection, managed-object
absence and original cooling. Run focused loops while editing, broad checks once
integrated, then fresh installed share retirement on frozen sources. Record
actual source hashes, exits, cleanup and throughput; no generated result files.

References checked 2026-11-11: [PostgreSQL row locks](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS)
and [Argo completed-resource retention](https://argo-workflows.readthedocs.io/en/latest/cost-optimisation/#limit-the-total-number-of-workflows-and-pods).
These references support mechanism/precedent, not Asservat qualification.

## Combined provider recipe envelope

The fresh integrated installer at `4192e6bd` refuses its owner-provider outbox
before public startup. A complete pure production reproduction with genuine
installation-derived names encodes65,845 bytes, beyond the existing64KiB bound.
The7,950-byte `federation` description repeats role/ACL/PKI/transit bodies
already present in the exact flat `apply` requests. The operator CLI consumes
that description only as a presence indication; current provider verification
recomputes expected recipes from protected deployment inputs.

Replace that duplicate description with `federation: true` when selected and
omit it otherwise. Preserve every flat action/body, inspection path, separate
`federationAuditStorage` requirement and unique owner authentication/reviewer
prerequisite. Keep the64KiB bound. This changes one public setup-artifact field,
not evidence, credentials, current provider authority or SQL protocols. It adds
no role, API call, process, fallback, state or configuration. Existing protected
input/image pins and unsupported-development-state refusal remain in force;
no permanent compatibility mechanism is introduced. Focused tests and fresh
installed qualification must establish the correction before it is delivered.

## Cold cleanup scheduling correction

The `1d1451f8` installed worker opened its three SQL facets but could not obtain
its first cleanup provider credentials. `RefreshCleanup` uses the existing
cleanup admission ticket and awaits a fresh fleet scheduling notice; the
notice's closed purpose list omitted cleanup and refused it before provider
login. Admit that one intended maintenance purpose. The original notice end
still bounds the context, and cancellation, one-use scheduling, native/recovery
proofs and the four exact provider/key purposes remain unchanged. A notice is
not effect or owner/authority-audit authority. This is a correction of the
component composition, with no new role, cache, timeout, API call or task.
Cold regressions must cover the actual cleanup ticket and unseeded credential
slots; healthy cached-token tests alone cannot establish cold startup.

## Independent projection completion during startup

The installed `8ab7b9ae` worker rejects capacity startup when cleanup publishes
a valid sibling claim/receipt between capacity's two native reads. The cleanup
producer guarantees all other journal fields stay unchanged. A focused
reproduction fails for both legitimate sibling updates. Capacity completion
therefore compares journal copies without only the sibling `CleanupProjection`
field. Both complete states are still validated, and every core/selected
capacity field, Secret, worker identity, guard, token and original time bound
remains required. Cleanup and every other purpose retain their existing
comparison. This removes an unrelated-entity coupling, with no new request,
retry, state, deadline or fallback and no weakened process-identity test.


## Installed proof-window counter refusal

At `d851782f`, public MCP manual and capture-time sharing pass and the original
worker stays running, but normal identifying rows remain at their original
`live_retire_by`. PostgreSQL reports SQLSTATE23514: the cleanup role's nested
`record_operation_proof_window_missed` update is rejected by the backing guard.
Permit only its exact bounded counter increment under that existing compiled
cleanup identity and nested trigger context; every other pool field must remain
identical. Do not grant direct pool writes, move a deadline or turn a missed
healthy proof into a healthy result. Exercise the actual compiled role and
reject nested counter reset/jump and unrelated pool mutations.

Cleanup diagnostics retain only application-selected fixed stages and existing
error identities. They add no provider request, retry, state or authority. The
installed observer also reports safe DB-relative timing and boolean state on
failure without changing its strict live-row, atomicity or charge assertions.
Cold sequential credential acquisition and the original short proof windows
still require measured installed qualification; the available sparse logs do
not establish cold-start duration or a successful certificate acknowledgement.


## Schedule only the next due effect

The worker's original-purge-only selector repeatedly admits already acknowledged
certificates while they wait for their original terminal cutoff. Each selected
waiting row pays the full existing native Begin/Finish (23 reads and three probes
in the focused contract), two lifecycle reads and a refused terminal-lease
transaction, about44 SQL statements including transaction control. The installed
log shows two serial waiting-row refusals1.358s apart. Multiplying that observed
rate by16 suggests21.7s per full page; it is an inference, not a measured full-page
maximum. Both concrete shares in the B10 run retired with cooling, but neither
proved healthy certification. The row timing diagnostics were insufficient to
attribute that outcome solely to scheduling or cold provider acquisition.

Skip an acknowledged certificate until its existing certificate-purge cutoff;
keep terminal-acknowledged rows eligible for finalization. Apply this scheduling
predicate to the existing worker and capture selectors. No new state, grant,
query, watch, task, fallback or effect authority is added. Existing transactions
continue to reject early effects. Test acknowledged absence before the original
cutoff, eligibility at the cutoff and finalization readiness with real SQL.

The next fresh installed cohort uses an original30-second cleanup budget rather
than the unqualified10-second fixture value. The trial's public profile already
uses60 seconds. Keep H2/P10 and the same240/300s retention. Existing arithmetic
moves original purge60s earlier and the identifying-row live cutoff20s earlier,
reserving time for actual serial native/provider work without extending evidence
retention or changing an in-flight deadline. This is qualification of B30 only;
it does not declare the failed B10 healthy path fixed. Cold-refresh cost remains unmeasured; exact original certificate states are
recorded on the next run, with every success,
original deadline and charge assertion retained.


## One original native proof for the bounded history page

The B30 run verifies the normal share's certificate with22.2s left in its
original write window, but fails its original live-row cutoff. Normal live
rows are4 while history retains14 records; these are record counts, not proof
of14 simultaneously due keys. The effect log has roughly1.26s per successful
serial operation. Due-history selection already requires eligibility no earlier
than original release, so repeated successful pre-release no-ops are not the
cause. The existing worker pays a complete native bracket for every history key
before it returns to lifecycle selection. Up to16 keys cost416 native API calls;
at the observed effect rate this suggests20.2s, not a measured full-page bound.

Use one request-owned native cleanup bracket for the existing page of at most16
SQL-only history keys. Its claim binds the worker/installation/purpose and
credential projection rather than an individual key. Each key retains the same
SQL recovery, incarnation, account, original eligibility and exact-history fences.
Do not batch lifecycle effects with variable S3/crypto work in this change.
Preserve progress after an isolated release failure and conservative unknown
accounting. Do not advance or replace the original keys or deadlines.

Bound SQL work by a child deadline at the original proof end minus one second,
then finish under the unchanged original five-second context. Unattempted keys
remain in SQL for the next independently admitted sweep; this is not a renewed
permit. A slow or changed final proof still refuses. One second is a fixed
engineering reserve for the existing final native pass, not a guarantee against
API latency. This reduces a full history page from416 to26 native requests
(93.75%) and its native-operation time envelope from up to16 original brackets
to one. It adds no role, grant, credential, process, watch, background task,
configuration or effect authority. The only added child context shortens work.

Numeric completed-sweep diagnostics separate selected lifecycle/history counts
and durations without IDs, provider inputs or dependency text. Component tests
must preserve cancellation, the original parent deadline, the final-check tail,
per-key error continuation and exact native request counts. Real compiled-role
SQL and fresh installed qualification remain required; the timing inference and
passing certificate alone do not establish timely erasure.


## Pair lifecycle IDs under the same original request

At `ba0128c4`, nine history releases take1.549s, proving the bounded history-page
composition runs. The workflow still fails its normal original live cutoff:
a sixteen-ID lifecycle page takes19.827s. Its certificate is acknowledged with
4.3s left before the original write cutoff, so neither dropping verification nor
another retention/budget increase addresses the observed serial native cost.

Group at most two lifecycle IDs under one original cleanup proof. Keep provider
refresh before native admission, each ID's current SQL/store/key checks and
complete existing lifecycle protocol, one original five-second context, the
same one-second final-check reserve and one Finish. Continue a second ID after
an isolated error only while that original child remains live. Report each
closed per-ID error. A partial group advances the UUID cursor only through its
attempted prefix; zero progress ends the page rather than spinning, and only a
fully attempted short page resets the cursor. Unattempted IDs stay in SQL.

A full16-ID page needs eight proofs rather than sixteen (208 vs416 native
requests); with one16-key history page,32 effects need234 rather than832 native
requests, a71.875% arithmetic reduction. This is not a latency guarantee. It adds
no state, configuration, role, grant, provider scope, goroutine or background task.
Variable S3/crypto work remains bounded by the unchanged original child; unknown
outcomes remain charged. The B30 cohort and all success/deletion assertions stay
unchanged. Test paired exact IDs, cancellation, partial progress, first-error
continuation and original-tail bounds, then measure the fresh installed outcome.
