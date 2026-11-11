# ADR-323 — Finite share metadata and public audit retirement

Date: 2026-11-11. Status: implementation plan; cost and runtime qualification pending.
Requirements REQ-PRV-008, REQ-PRV-004 and REQ-SHR-001 through REQ-SHR-008.

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
must fit before identifying metadata can retire. Refuse incompatible backing
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
lane-specific adapters, with one total page of at most 16 operations and bounded
round-robin progress. Do not add concurrent per-lane loops or a separate share
cleaner. The installer must actually provision the protected projection and
credential material and the supervisor must own and join its task.

Current writers use the owner audit provider, but historical equality is not
implied. Pin the accepted store/key/signing associations and deduplicate only
proved identical scopes. Never try alternative keys or infer an old binding
from today's configuration. Preserve cleanup/verifier storage separation and
the exact SQL facet grant union. Keep identity/processing lanes, source
acceptance and evidence-key authority outside this expansion.

## Complexity and qualification

| Question | Answer before implementation |
| --- | --- |
| Observed benefit | Source rejects all share deletion; the retained-count/cost reproduction is pending. |
| Accepted risk | No maintainer acceptance of indefinite identifying share history. |
| Typical deployments | All three concrete sharing producers and normal public audit apply. |
| Precedent | Reuse C-08 retirement. Argo uses finite completed-control retention; PostgreSQL supplies the row-lock conflict used for the proposed transaction. Neither proves backup erasure. |
| Added exposure | Activate the existing cleanup component's three SQL facets and scoped provider/storage credentials. Exact installed connection/credential delta must be recorded before wiring. No collectors or evidence keys. |
| States | Zero new lifecycle/fallback states; existing healthy, overdue and unavailable behavior remains. |
| Configuration | Zero new lifetime quotas or cleanup-tuning knobs. Existing qualified retention/backing must cover the effects. |
| Dependencies | Existing PostgreSQL, audit storage/provider and qualified residual-history inputs. |
| Aggregate cost | One existing component loop with a total 16-operation page. Measure provider work, sustained normal-read retirement and capture progress; three cold pools bound connections, not throughput. |
| Upgrade/disable | Qualify original layouts and empty rollback; unknown retained links or provider scopes cannot be adopted. Disabling work cannot certify timely erasure. |
| Smaller fix | Raw scheduled DELETE omits paid history, late publication and residual reuse. Coupled existing finalization avoids another cleanup protocol. |

First measure current count-maximal eight-manager/eight-recipient share effects
using compiled hub grants and an actually published artifact. Whole-instance
WAL deltas and real tuple/index growth are observations, not universal maxima.
The 100-share transaction and the integrated additional layout still need their
own measurement. Do not label a fixture-gated compile run as service execution.

Then qualify actual upgrade/rollback, all three producers, original cutoffs,
replay, late publication, mutation/finalization concurrency, recovery refusal,
unknown effects, direct-DELETE denial, provider scope rejection, managed-object
absence and original cooling. Run focused loops while editing, broad checks once
integrated, then fresh installed share retirement on frozen sources. Record
actual source hashes, exits, cleanup and throughput; no generated result files.

References checked 2026-11-11: [PostgreSQL row locks](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS)
and [Argo completed-resource retention](https://argo-workflows.readthedocs.io/en/latest/cost-optimisation/#limit-the-total-number-of-workflows-and-pods).
These references support mechanism/precedent, not Asservat qualification.
