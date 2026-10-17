# ADR-164 — Passive convergence of the original owner launch receipt

Date: 2026-10-14. Status: accepted; implementation staged, qualification pending.
Requirements: REQ-DEP-003 and REQ-FED-001; existing SC-DEP-003 / SC-FED-001
and TASK-03 / TASK-11 retain traceability ownership.

## Problem and evidence

The installed owner may begin executing immediately after the original guarded
Deployment's single zero-to-one transition. Its installer records the launch
receipt in a separate later bounded operation. The runtime reader previously
classified a valid original launch awaiting that receipt as changed and exited.
ADR-162 explicitly allows the launched process to exist before read-only
finalization; finalization is not a process-start barrier.

The exact before regression, `owner-launch-receipt-before-1`, runs the actual
provider projection producer against the runtime journal reader using the
existing synthetic API/SQL/provider fixture. The pending child fails with the
old changed classification; the acknowledged-original-launch control passes.
Native13 failed at initial-journal/journal-state after all eight execution and
finalization pairs passed. The unit evidence proves a legal failing interleaving;
it does not uniquely identify which compound predicate native13 encountered.

## Decision

The observation-mode startup loader may passively await only the receipt of its
fully validated original launch. The private pending classification follows
complete original journal shape, provider selection, resource UID, child and
role-root validation. It yields no identity proof or authority.

Pin the entire first pending public journal state in process memory. Read only
the original journal, at most once per 250 ms, with each read bounded by five
seconds and the unchanged original thirty-second startup caller/resource-root
end. The only permitted change is the original launch receipt becoming present.
Reject changed claims, siblings, roots, dates and any malformed/unavailable read.
No CREATE, CAS, launch retry, SQL credential use, key/provider action, activation
or serving is performed while waiting. No private credential bytes are retained
in pending state.

After the receipt appears, perform the complete existing native verification
under a new at-most-five-second proof bounded by that same startup caller:
current native protection, original Pod-bound token, exact mounted immutable
projections, original Deployment/account/Pod chain, and before/after journal and
guard checks. Pin the complete first observed positive receipt and state across this full
proof; it cannot adopt another valid receipt for the same operation. Only
that complete current proof allows subsequent SQL credential verification.

The passive waiting interval and fresh authority observation are separate.
Neither alters any installation claim, effect cutoff, spend, original UID or
resource version. Original runtime Verify remains a non-waiting single proof.
No persistent recovery journal or restart producer is introduced. Failure or
cancellation preserves the nonzero startup exit and joined loader cleanup.

## Validation boundary

Preserve the before failure and positive completed control. Corrected tests must
cover actual producer/reader compatibility; pending-to-receipt convergence;
unchanged whole-state pins; substitution before the final authority read; guard
or token loss after passive convergence; repeated pending observations; read and
caller expiry; failed fresh authority; and no positive result from pending alone.
The installed original owner fixture must still pass all original setup,
projection, launch and identity outcomes with unchanged rates, attempt bounds
and fixture ceilings before deployed availability is claimed. Helm/public
collection remains disabled until its separate slice requirements pass.
