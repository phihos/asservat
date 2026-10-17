# ADR-124: Retire prepaid Stop obligations with positive writer proof

Status: Accepted design; component implementation and qualification tracked in
[the architecture contract](../architecture/download-stop-lifecycle.md).

## Context

[ADR-119](119-public-context-download-and-prepaid-stop.md) reserves each download's
Stop record, encrypted decision and bounded recovery attempts before acquisition.
Restriction remains possible when normal audit capacity or evidence-read rights
are unavailable. Retaining those reservations forever would eventually prevent
new downloads; releasing them at expiry would forget uncertain writes and managed
backup copies.

## Decision

New, explicitly configured reservations bind `closed-download-stop/v1` before
any Stop provider operation. A successful conditional PUT, exact verified GET
and joined synchronous producer yield a positive completion. Existing receipts,
Find, HTTP 412 and elapsed time cannot produce one. Historical reservations are
not upgraded.

Cleanup permanently closes the original claim under the same Stop row lock. It
distinguishes a reservation never used, a decision whose write was never claimed,
and a positively completed and independently acknowledged write. The unclaimed
decision is a missed audit, not a recorded one. Any issued writer without exact
positive completion remains charged.

Purge the original before using its reserved slot for a signed, encrypted typed
retirement certificate. Independent verification has only read/open/public-key
capabilities. The JWS purpose is specific to Stop retirement; an existing lifecycle
signing key may cover it only when protected installation acceptance explicitly
authorizes that purpose. Encryption alone cannot replace asymmetric provenance.
The certificate's actual writer closure and an independent complete inventory
acknowledgement precede SQL retirement. A missed certificate window irreversibly
forbids certificate creation before an overdue absence path; no proof interval is
fabricated or moved.

Freeze original object, identifying SQL, cooling and final backup/WAL dates at
admission. Preserve the two-generation history arithmetic from ADR-112 and prepaid
per-slot ciphertext/key/SQL/WAL backing. Retiring a Stop moves its charge to
allocation-level cooling until safe reuse; it never releases parent download,
native-read, output, response or worker charges. Unknown or late work remains
visible as an unresolved obligation or retention breach.

Use current independently accepted recovery in each transaction. Original issuer
epoch still binds the obligation; ordinary source refresh cannot approve restore
or reconcile unknown effects. An independently approved current incarnation is
not rejected solely because the historical admission used another postmaster.

The bounded pending reconciler attempts independent eligible records after a
per-record error. Expired unclaimed writes, exhausted lookups and lifecycle-closed
rows do not consume its sixteen active selection slots. It neither retries a row
within the pass nor extends the pass's original five-second deadline.

## Consequences

Healthy and provably unstarted obligations gain finite retirement. Unknown writes
still require independently qualified reconciliation; deletion is never inferred
from time alone. Backend inventory/IAM, lifecycle signing-purpose acceptance and
SQL/backup/WAL history qualification remain deployment prerequisites. No public
runtime is enabled by these components.

Certificate verification spends one of two fixed SQL attempts before the independent
provider read/open. A lost verification/acknowledgement reply cannot refill those
attempts. The twelve-operation key reservation includes both verifier attempts;
provider success is still not an acknowledgement.
