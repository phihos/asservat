# ADR-322 — Processing inventory export

Date: 2026-11-11. Status: implemented; named installed workflow qualified.
Requirements REQ-PRV-006, SC-PRV-014, TASK-07 and TASK-11.

Privacy operators need an inventory covering retained artifacts, recipients,
retention and deletion progress. Discovery currently omits deleted artifacts
and does not export recipient history. Technical regions identify placement,
while processor organization names require explicit operator declarations.

## Report and authority

The browser uses one normal-lane audited `get_processing_report` operation.
Each page checks the current privacy operator once, reuses the existing
processing transaction and preserves the original caller, policy, recovery
and metadata retirement bounds. Intent is acknowledged before reading, and
the prepared response is acknowledged before delivery. Ordinary evidence
read permission alone does not authorize the report.

Seven ordered sections cover artifacts, share recipients, native sessions,
operation responses, processing rules, current technical paths and processor
declarations. Records contain selected typed metadata. Shares and operation
artifact references are flat records with explicit ordinal continuations.
Deleted artifact records remain visible only within their original control
retirement. Missing outcomes and unknown client receipt remain explicit.
Session emitted bytes describe recorded server accounting.

Each page returns at most three records within the existing 24 KiB response
budget. The cursor carries the original creation ceiling and policy digest.
Continuation advances within a section or to the next section. Only the end
of processor declarations completes the export. Report operations are excluded
from their own operation history. Each page is a current observation of the
retained records selected within that creation ceiling. It carries its source
revision and observation time.

The console downloads JSON parts containing up to 32 acknowledged response
pages and at most 1 MiB. A remaining continuation exposes an explicit next-part
action. The final part records completion. Principal changes and cancellation
clear unfinished in-memory output. Exported local copies remain outside managed
deletion. This creates no managed evidence artifact or persistent report cache.

## Declarations and original lifetimes

The existing protected download-environment document gains optional
`processors` metadata. Each of at most 16 declarations has an opaque ID, an
organization name, finite activity labels and region labels. Missing
declarations and an explicitly empty declared list remain distinct. The
installer, Helm input, cluster join rewrite and policy cache preserve both
states and deep-copy nested lists.

These are operator declarations. They grant no permissions and identify no
credentials or endpoints. The complete document retains its existing policy
revision behavior, so declaration edits can invalidate a pending observation
through the existing source-change handling. Started native responses retain
ADR-312's original bounds.

Artifact and rule metadata use their immutable individual retirement dates.
Share history inherits its artifact's original control visibility horizon;
share expiry and revocation describe its access state. Native session history
also consumes the original per-session `capacity_backing.Native.RetireBy`
snapshot. A renewed shared backing cannot extend that timestamp. A missing
original snapshot supplies no qualified native-history visibility. Audit
history uses the original audit lifecycle retirement and retained-record bound.
Current source or backing observations cannot renew these original dates.

Migration 152 admits the new normal operation with the existing
`context-input/v1` format and adds three query indexes. It preserves compatibility
floor 149. Empty Down restores the preceding audit guards and refuses retained
report audit rows. Exact qualification and prior-source behavior are recorded
in implementation progress.

## Complexity review

1. The accepted inventory export has no current public implementation.
2. Existing operator authority, metadata lifetimes and unknown receipts apply.
3. The workflow covers retained installation metadata across supported evidence.
4. It reuses existing keyset pages, policy configuration and audited operations.
5. Added credentials, privileges, network listeners and collectors are zero.
6. Existing unavailable and source-change handling cover refusal. Original
   unknown history stays explicit.
7. Added runtime tuning settings are zero. Processor declarations are product
   metadata.
8. Existing SQL, configuration and audit providers supply the data.
9. One bounded response and existing audit pair are charged per requested page.
   Three B-tree indexes add one entry to the corresponding session, audit or
   processing-decision record. Source scans retain the original SQL deadline.
   Returned rows are bounded; source work still depends on retained history.
10. Additive schema and optional declarations preserve earlier source bytes when
    absent. Upgrade, empty rollback and current-role execution require real SQL.
11. Exporting discovery would omit retained deletions and recipients. The
    existing records support the required inventory without a global content index.

The report records known purposes, types and potential user-data classification.
It does not infer which people appear in evidence. Recorded lineage and retained
history have explicit coverage. Retained-derivative production and propagation,
reviewed personal-data extracts, correction and preservation remain separate
requirements under the accepted specification.
