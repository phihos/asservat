# ADR-321 — Exact early erasure

Date: 2026-11-11. Status: exact-artifact installed qualification passed.
Requirements: REQ-PRV-006, SC-PRV-012.

A current privacy operator selects an exact published artifact from the
Processing console and explicitly confirms early erasure. The request names
the existing artifact and uses a stable request ID. The closed action uses
the normal audit lane with the exact selected artifact reference. It reuses
the existing processing decision transaction and leaves the reversible
restriction and release reserve available for their own actions.

The SQL transaction validates retained publication, the exact positively
closed writer and current authority. It binds the original retained attempt
and effective dates before audit, then applies that exact decision after the
independent normal audit pair is acknowledged. It closes the retained
readable interval at its acquisition anchor and preserves the existing
effective hard deletion deadline. The receipt time records when the action
was applied. Concurrent changes to the prepared custody facts require a
fresh review. Acknowledged replays reuse the decision and audit spend.

The same transaction appends a canonical lifecycle decision. Its signed
source revision uses `erasure:<request UUID>`, generation 1 and the digest
of the exact prepared processing decision. The stored policy lists remain
actual retained policy references. The existing hub worker signs and
acknowledges this record using the installed lifecycle publisher. This
retains the existing record wire shape so the preceding publisher can sign
the same cutoff and provenance. The narrow trigger writes the existing
retention overlay and uses its existing immutability and monotonicity guard.

The deletion worker processes the now-due attempt and verifies the managed
copies through its existing inventory, audit and finalization path. An
accepted request and signed lifecycle acknowledgement are separate from
verified deletion. An audited exact-request status read shows the applied
cutoff, the hard deadline at acceptance, the current deadline and the
deletion state through the original control retirement. It remains available
after the artifact leaves discovery. Failed or uncertain cleanup remains
pending or overdue with original charges held.

## Complexity review

1. A privacy operator previously had to wait for ordinary expiry.
2. Existing operator authority, immutable lineage and deletion proof still apply.
3. The first path supports exact published attempts with qualified closed writers.
4. It reuses the processing decision, retention journal and deletion reconciler.
5. New SQL credentials, grants, service listeners and privileged workers are
   zero. The browser adds one audited metadata status operation.
6. Request acceptance, pending signature and deletion progress use existing
   acknowledgement and custody states.
7. New administrator settings are zero.
8. The configured audit and evidence providers perform the existing bounded work.
9. One irreversible decision and lifecycle row per accepted artifact, funded
   through existing processing transition backing. No per-artifact watch or poll.
10. Existing mutation and lifecycle wire shapes retain compatibility. Test the
    previous publisher against the new records and refuse schema Down with
    retained erasure decisions.
11. The signed cutoff plus existing cleanup supplies exact early erasure
    with the current role layout.

Complete incident and workload selections, derived and cached copy
propagation, access/correction, reviewed preservation and inventory reporting
remain under REQ-PRV-006. The exact request covers its selected managed artifact
and copies inventoried by the qualified deletion worker.
