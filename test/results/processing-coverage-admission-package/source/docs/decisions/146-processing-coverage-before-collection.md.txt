# ADR-146: Check prepaid processing coverage before collection

Status: accepted for implementation; qualification pending.

## Context

The actual SQL54 fixture accepted a capture and its encrypted intent, then the
unchanged SQL50 publication guard refused its original deletion deadline because
it exceeded prepaid processing history. A shorter synthetic fixture policy
subsequently qualified the full path. A product request must detect known
insufficient coverage before acquisition without shortening selected retention
or assuming that a future renewal will succeed.

## Decision

C-09 observes the existing accepted processing root and bounded rule inventory
through C-21 `ProcessingReads` with the existing purpose15 credential. Preview
and a new request check the exact proposed artifact/target/acquisition anchor and
resolved deletion deadline. The read retains the original caller/recovery and
at most five-second interval through SQL reads and commit. It validates the
complete backing and rule shapes and compares the root before/after the read.
This observation is neither a lineage row, a slot reservation nor an execution
permit. It remains outside canonical approval bytes and persisted intent.

For SQL54-managed accounts, the existing admission transaction repeats the
coverage check against actual SQL while holding recovery then permission locks,
before any custody/capture/control/intent charges. It uses SELECT on
`processing_root` and `processing_rule`, added only to purpose40. Supported
processing configuration, decision, publication and capacity-renewal writers
acquire the same permission lock before their processing writes. Admission adds
no processing row lock after its existing storage/audit locks. Final post-lock
checks retain all original deadlines. Unmanaged component accounts keep their
existing behavior and are not promoted into the installed profile.

The entire active-rule inventory must validate before a known limitation is
reported. An applicable retained restriction imposes its original per-rule
administrative horizon even after that horizon expires. A released rule does
not impose that restriction. Exact deletion-date equality is allowed, matching
publication. A full published-lineage counter reports capacity unavailable.
Pending captures do not reserve a lineage slot through this observation; the
existing charged admission budgets and final publication guard remain separate.
No later change, release, renewal or successful preview guarantees publication.

Accepted same-key replay is resolved before new acquisition checks. An unknown
lookup does not become a new admission. Shared browser/MCP presentation reports
`ProcessingCoverageUnavailable` for known insufficient coverage, while failed,
malformed or expired reads remain unavailable. Request copy preserves the
possibility that an earlier same-key attempt was accepted; it never claims that
nothing happened or silently chooses shorter retention.

## Consequences and validation

There is no migration, new queue, history table, credential or policy source.
Role40's fixed layout changes by two SELECT grants; protected role provisioning
must issue the matching original layout rather than adopt an older role.
The installed public graph must supply the already scoped role15 reader.
Publication and its independent exact lineage/rule checks remain unchanged.

Staged checks cover root and rule boundaries, malformed complete reads,
cancellation/expiry, preview/new-request denial, passive replay and shared error
presentation. The actual SQL54 fixture will exercise purpose15 and purpose40,
require the specific coverage failure, and compare custody, control, capture,
audit and lineage charges before/after a denied long-retention request. It then
uses the independently selected short request through actual publication.
These additional tests have not yet run. Prior SQL54 positive qualification
alone does not qualify this change, sustainable history replenishment, or the
installed public workflow.
