# Grouped existing-recording Save accounting

Status: accepted maintainer decision (2026-10-30); two-source packet SQL/storage
components and sixteen-source central admission qualified; installed and
sixteen-source native workflow qualification pending.

A Save may select 1–16 existing sources under [REQ-SAV-002/003](../../specs/recording-saves.md).
The maintainer explicitly selected one policy-authority `maxExecutions` debit per
Save, preserving incident accounting. Grant budgets continue to charge each
applicable source snapshot start and the sum of bounded output bytes. Source
observation spend is unchanged. Exact replay does not charge either counter again.

Use one public capture identity, one protected grouped preview, one atomic
admission and one database acceptance time for all selected windows. Retain a
real parent operation and independently funded child capture/custody attempts;
do not emulate a group with separate public requests or a fabricated artifact.
After acceptance child outcomes, publication and joined cancellation remain
independent, with stored evidence winning a cancellation race.

The [implementation proposal](../research/recording-save-groups.md) records the
existing singular assumptions, compact preview constraint, shared transaction,
parent projections and eleven complexity checks. It is not runtime qualification.
Existing single-source records retain their original identities and accounting.
No runtime collection gate is enabled by this decision.

The compact private preview measured 58,360 bytes with 16 maximum-field members;
its full canonical selection was 15,419 bytes, within the unchanged 128 KiB
journal and 16 KiB per-artifact selection limits. Expanded public assessments
include each member's retention-policy digests: the measured maximum response
was 112,917 bytes, and the official MCP SDK's text plus structured reply was
231,462 bytes. Only `preview_recording_save` uses bounded 128 KiB raw and 256 KiB
framed replies; other operations retain 24 KiB raw and 64 KiB framed limits.
These are serialized-size measurements, not production latency or overhead.

Atomic admission covers the selected central authority, accounting and custody
reservations. Configured node ceilings remain binding, and each node still
reserves local resources before copy/encryption through the existing protocol.
A later local capacity race produces an explicit child outcome. No distributed
pre-acceptance freeze lease, extra collector probe or new reservation service is
introduced. Existing source metadata charges remain separate; N sources plus
one new parent and N children require 2N+1 existing metadata-record units.

Policy and grant counter units require an explicit conversion. For a newly
reviewed opted-in recorder grant, the trusted compiler derives starts per Save
from the accepted full scope: the current one-action recorder contributes at
most `min(incidentPodCap,16)` starts. The finite grant-start ceiling is
`min(10000, policySaveLimit * startsPerSave)`; byte and observation ceilings are
unchanged. A private optional grant-scope field records that reviewed unit.
Legacy grants omit it and retain their original validation; no grant is enlarged
or migrated silently. Request and SQL-read paths verify the full accepted scope
hash and compiler facts. A transient exact-scope witness keeps later mutation
invalid without adding persistence, privileges, expiry or key authority. It
retains at most one 64 KiB scope copy while the grant value is used.

The status response may expose `max_grant_starts` as read-only guidance after
recompiling the already-read accepted source with its exact scope digest. This
adds no observer write or configuration read. The UI requests and labels actual
action starts separately from the policy Save counter; it does not multiply an
unverified client-side cap or automatically request a larger grant.
