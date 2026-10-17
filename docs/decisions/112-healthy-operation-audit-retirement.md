# ADR-112: Healthy operation audit retirement and backed history

- Status: accepted for staged implementation; runtime remains disabled
- Date: 2026-10-11
- Requirements: REQ-AUT-005, REQ-PRV-004; S-02
- Owner: C-08 Audit

## Decision

Opt new public-operation audit into a fixed, explicit healthy-writer protocol.
Only the actual one-use producer can record completion after a successful
conditional PUT, exact GET/cryptographic verification and joined closure.
An existing object, HTTP 412, unknown response or later lookup cannot produce
completion. Historical schema-40 operations keep their original bytes, behavior
and charges; no migration fabricates proof for them.

Retain each operation's original two-object/128-KiB charge while both originals
are purged and independently verified. A signed, encrypted deletion certificate
then occupies one freed slot. Verify and acknowledge that exact certificate
with a separate role, retain it through its frozen proof cutoff, purge it and
require a separate fresh absence acknowledgement. A dedicated SQL finalizer
atomically removes operation identity and its fixed lifecycle child. No third
simultaneous object or recursive deletion-audit object is introduced.

For supported backup/WAL/replica history, transfer the same charged record to a
finite principal-HMAC cooling aggregate. This removes operation/trace/case
identity but remains privacy-relevant. It is not a second unbacked queue.
Release only that aggregate's exact count after its frozen history interval,
then remove the empty principal account when no other live, unknown or cooling
obligation remains. Unknown writes and legacy records keep their charges. The existing pool keeps a
root-only protected profile/deadline through the final residual generation;
empty-account state cannot justify premature backing shrink or profile change.

Freeze the hard metadata deadline D, supported logically recoverable history H,
cleanup allowance B and certificate proof window P at admission. SQL identity
retires by D−2H−B; cooling becomes eligible at D−H−B, is deleted by D−H, and the
last H covers its supported recoverable history. The two prior cleanup budgets
and P must fit before SQL retirement and after the original write interval.
Reject an infeasible request instead of truncating its proof window. Late
retirement preserves the original dates, records Overdue and delays capacity
reuse until at least actual retirement+H. That safety floor does not extend
permitted retention, revive authority or report compliance with the missed date.

## Reasons and limits

Immediate quota refunds after SQL DELETE would allow arbitrary residual backup
history while apparently free slots are repeatedly reused. Existing charged
slots plus finite aggregate cooling avoid that availability/privacy defect.
Qualification must pin concrete layout, footprint, transaction-WAL, copy-count
and finite attempt bounds; arbitrary positive byte reservations are insufficient.
No account-key replacement may reset old charges.

All durable transitions preserve current recovery, issuer and PostgreSQL
incarnation, original post-lock deadlines and distinct source/producer/cleanup/
acknowledgement/finalizer roles. Transaction markers are private, consumed in
the same transaction and protected by deferred constraints. No runtime role can
create a marker, delete a row or decrement a counter directly.

This implements the healthy subset only. Protected policy/qualification
producers, operational supervision, uncertain-writer reconciliation and the
required qualified restart/restore bridge remain unfinished. The current
incarnation fence intentionally denies historical cleanup after a database
restart; supporting ordinary restart safely is required before enablement.
The policy does not assert physical media sanitization or make unmanaged
operator backups disappear. See [the implementation contract](../architecture/operation-audit-lifecycle.md).
