# Processing coverage at context admission

[ADR-146](../decisions/146-processing-coverage-before-collection.md) adds a
pre-collection processing check to C-09 and the C-21 admission transaction.
It implements REQ-CAP-005 and REQ-EXE-002 for the pod-status slice.

## Check

`ContextProcessingCoverageReader` (concrete `postgres.ProcessingReads`) takes
the proposed artifact location, exact target, acquisition anchor and resolved
deletion date. It reads the processing root and the active rules matching that
target, and reports whether a restrictive rule covers the proposed artifact.
Matching restrictive rules keep their original horizon. The check never
shortens or chooses retention; retention comes from the stored deadlines
described in [retention](retention-lifecycle.md).

Preview runs the check before returning its plan. It is advisory: a positive
preview does not reserve the lineage slot, and the published `captures`
counter excludes pending captures. Submission with an existing operation ID
returns the existing outcome; a new submission runs the check again inside
admission.

## Admission transaction

Admission runs in one transaction under the hub process's single SQL login:

1. `SELECT … FOR SHARE` on the processing root.
2. Read the matching rules and evaluate coverage.
3. Update the per-workload counters with conditional updates that lock only
   the affected workload row (ADR-330 D7).
4. Insert the custody registration, capture row and audit row, keyed by the
   operation ID.

Processing writers (configuration acceptance, decisions, release and catalog
publication) take the root `FOR UPDATE`, so admission and those writers
serialize on that one row. There is no second root read and no writer-specific
lock order. Root and rule rows are never deleted.

A retry with the same operation ID returns the stored outcome. An unknown
outcome is resolved by looking up the operation ID; a charge is released
once the outcome is known.

Insufficient coverage returns a shared browser/MCP message distinct from a
transient unavailable read.

## Operator inventory and release

[ADR-318](../decisions/318-processing-operator-rule-inventory-and-release.md)
adds same-origin console controls for processing operators. Inventory uses
bounded queries under the processing duty and grants no ordinary evidence
inspection. Artifact selection resolves one immutable location; release
names the persisted scope and exact revision and writes its audit row in the
release transaction.
