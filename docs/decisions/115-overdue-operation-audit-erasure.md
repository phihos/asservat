# ADR-115: Overdue original operation-audit erasure

Status: accepted for the bounded component implementation; runtime remains disabled.

[ADR-112](112-healthy-operation-audit-retirement.md) cannot create a deletion
certificate after its original schedule no longer leaves the minimum proof
window. An outage before first cleanup therefore strands even positively closed
original writers. Extending the certificate dates would hide a missed obligation;
creating and immediately deleting a certificate would not provide that window.

New records may contain the immutable protected policy capability
`OverdueTerminal: overdue-original/v1`. Its omitted representation preserves all
older bytes and behavior. It is installation composition, never a public option.
H>0 admission additionally requires the new `operation-audit-history/v2` qualified
layout and backing for the extra fixed transitions. Neither migration nor source
renewal upgrades old records. Existing-record adoption requires separate reviewed
reconciliation, including compatibility with all outstanding pool profiles.

After the original certificate cutoff minus its full proof window, a private
cleanup transaction may select an irreversible overdue mode only when both
original writer completions and receipts exist and no certificate PUT has ever
been claimed. The transition shares the certificate claim's lock, cannot reset
lease budgets, and permanently forbids certificate creation. The current bounded
purge may then erase the original objects even though all original dates are past.

A separate read-only backend verifier checks current complete absence and
acknowledges the exact bounded purge under the original lease. Only then may the
existing finalizer retire identifying rows and transfer or release their original
charge. This explicit terminal checkpoint reports a missed proof window; it does
not claim that a retained certificate existed or that deletion was timely. No
late or recursive audit object is created. Failed verification keeps charges
without requiring deleted objects to reappear.

A fixed root/lane saturating `proof_window_missed` counter is incremented in the
same transaction as first mode selection. It remains after identifying rows
retire, without per-operation labels or an indefinite identifying tombstone.
Original dates remain unchanged; the existing actual-retirement-plus-H cooling
floor and residual backup protection still govern safe reuse.

Unknown/failed writers, legacy40 records, old41 records without the capability,
claimed-but-unclosed certificates and exhausted cleanup budgets remain excluded.
Database restart/restore still requires the independently accepted historical
ledger reconciliation bridge; a fresh source observation cannot invent it.

See [the implementation contract](../architecture/operation-audit-overdue.md)
for states, roles, bounds, qualification and remaining work.
