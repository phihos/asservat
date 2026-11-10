# ADR-318 — Processing operator rule inventory and release

Date: 2026-11-10. Status: implementation candidate; qualification pending.
Requirements: REQ-PRV-006, REQ-CAP-005, SC-PRV-010; TASK-07, TASK-11.

## Problem and authority

The accepted privacy workflow already requires durable restrictions and exact,
independently audited release (ADR-127/146/210). The installed browser route
initializes/restricts processing, but release always returns unavailable. There
is no console rule inventory, so an operator cannot rediscover a restriction
after losing its last receipt. These are concrete product gaps. The maintainer
has authorized complete workflows; the HTTP/console composition below is an
implementation choice, not an additional maintainer security requirement.

## Decision

Reuse the existing reserved processing audit lane and its private release-history
qualification. The accepted profile projection includes its actual policy and
retention alongside normal/resolution. Release uses the processing retention;
normal traffic cannot spend that reserve. Existing intents retain their original
policy through Finish. Read lane locks in normal/processing/resolution order;
read the processing root under existing permission-root serialization.

The same-origin console adds explicit inventory, initialization, restriction and
release. GET `/api/v1/processing/rules` is an on-demand operator-only page,
default 50/max 100 rows, with an optional UUID position. It returns control scope,
state, revision, deadlines and observation time, without evidence content,
audit actors or credentials. Pages are observations, not a cross-page snapshot
or authority. Release always checks the actual current exact revision in SQL.
No MCP processing tool is added; configured operator client restrictions remain.

The existing POST changes route uses a canonical lowerCamel scope DTO. The
immutable domain/SQL scope JSON is unchanged. A new artifact restriction may
supply only the selected public artifact ID. Resolve its immutable location
under the same original operation authority before canonical hashing/audit;
never ask the operator to find an internal attempt ID. Release uses the exact
persisted scope returned by inventory and the expected restrictive revision.
Go comparisons use interval instants, so a non-hour timezone survives the
durable JSON round trip; serialized scope and request/audit digests are unchanged.
Known conflicts return 409; uncertain effects remain unavailable and retry
only the original request ID. Reload reads durable rules, not browser storage.

The inventory and artifact resolver reuse `ProcessingDecisions.transaction`,
its compiled processing duty, existing SELECT grants and two bounded sqlc
queries. Two initially proposed SECURITY DEFINER inventory functions were
removed because they duplicated those fences without reducing privileges.

Current caller/operator policy/recovery precedes metadata SQL. Reuse one complete
operation observation and its original deadline; final checks are local/current
request identity checks, not another complete policy/recovery observation.
The change service's previous three complete observations are reduced to one,
as already required by ADR-311. Its persisted five-second SQL request bound
remains; current identity loss/expiry after audit or SQL still refuses receipts.
Existing SQL source, recovery and backing checks remain. Processing changes do
not alter ADR-312: a started native response continues its original decision;
new responses still authorize current processing state.

Migration 149 changes the existing audit-profile function and declares the
existing schema compatibility floor as 149, without table or retained-row changes.
The prior binary's strict two-lane decoder cannot consume this response. This is
a fresh supported development baseline: the existing release coordinator refuses
`installer-upgrade` from 148 before migration, and image-only rollback to 148 is
unavailable. No existing installation is adopted or erased. Supported additive
upgrades starting at 149 retain the existing upgrade/rollback mechanism. A direct
owned-fixture Down restores the exact prior function and floor 102; it is not a
supported installed downgrade or a permanent development-layout compatibility layer.

## Complexity and cost review

1. Frequency/harm: every public release currently fails; restrictions cannot be
   rediscovered through the console. No hypothetical incident is required.
2. Accepted risk: retain the maintainer's started-download decision; add no
   interruption/recheck mechanism.
3. Benefit: privacy operations are occasional, but this is a specified user
   outcome. No background work is imposed on evidence sources.
4. Precedent: reuse this repository's session, operator, audit and bounded
   list/control patterns; no new policy engine or service.
5. Added privilege/credentials/network services: zero.
6. Added fallback mechanisms: zero; reserved/restricted/released already exist.
7. Machinery-only configuration: zero; page bounds are fixed.
8. New external dependency: zero.
9. Profiles read one existing reserve pool and processing root in their existing
   SQL query. Inventory/resolution add one bounded SQL SELECT per explicit use.
   No new connection pool, watch, poll or per-workload task; pages max 100 rows.
10. Migration Up/Down/Up is required, with retained data unchanged and actual
    profile expression execution under compiled roles; installation history and
    fresh installed console qualification remain required.
11. The discarded partial wiring cannot expose a current reserve or support
    reload/release. Documentation alone would leave the accepted workflow absent.

## Verification boundary

Focused unit/race and compiled-browser checks are component evidence. The fresh
installed workflow must select an existing artifact, restrict it, observe new
ordinary case/download refusal, reload inventory, release its exact revision,
and recover the same original evidence without additional replay audit spend.
This is a bounded portion of REQ-PRV-006; erasure, complete rights-request search,
reporting, backup lifetime and the full first release remain separate work.
