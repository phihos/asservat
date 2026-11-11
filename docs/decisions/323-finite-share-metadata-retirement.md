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
