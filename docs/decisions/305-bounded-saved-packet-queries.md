# ADR-305 — Bounded queries over saved packets

Date: 2026-11-05. Status: implemented; named local component, browser, service
and resource checks pass. Installed qualification, CI and publication pending.
Requirements: REQ-MCP-002/003/005, SC-MCP-003, REQ-EVD-005/008, REQ-INV-001–003
and REQ-AUT-003/004/006. Plan: [saved-packet query implementation](../reviews/s05-packet-query-implementation-2026-11-05.md).

## Decision and authority

Complete S-05's saved-packet query workflow for metadata and raw PCAPNG through
the existing regional Go worker. Reuse the pinned hub libpcap compiler and
`packets.Filter` Go VM; do not introduce another expression parser. The public
field becomes `packet_filter`, with the documented language and UI label
**tcpdump/libpcap packet filter**. The unimplemented `display_filter` field is
removed; no runtime caller or retained query needs a compatibility alias. This
does not accept Wireshark display-filter expressions. Typed time bounds and TCP
flag mask/value selection preserve those outcomes without protocol-offset
expressions.

This is an implementation choice under the maintainer's standing complexity
delegation, following S-05 simplification S6. It is not a newly stated explicit
maintainer requirement. S6 conflicted with the former normative “display-filter
grammar” in REQ-MCP-003. The requirement, scenario, schemas and UI wording were
explicitly revised before behavior changes. The bounded query,
numeric/time/address selection and closed field outcomes remain required.
Native download does not substitute for this workflow.

Keep the public filter limit at 512 bytes and the existing compiler's token,
instruction, no-name-resolution and Go-VM compatibility checks. Empty/omitted
filter means no packet-filter restriction. The initial subset also rejects the
existing `RawBytePredicate` bracket-expression class before compilation/spend.
This explicit first-release choice prevents payload-literal predicates from
being copied into control state; it is not full libpcap compatibility or a user
requirement. TCP flags remain projectable and filterable by bounded typed
mask/value. No payload strings, regex, arbitrary functions, paths or commands.

## Selection, scan and result

One existing case/artifact is selected. A closed ordered field catalog covers
packet time, captured/wire lengths, addresses/ports/protocol, TCP
flags/sequence/ acknowledgement/window and ICMP type/code. A raw source may
additionally project a hex prefix of saved packet bytes selected by bounded
numeric offset/length. Offsets address the captured frame, without inferring a
payload start or padding missing bytes. Specify exact names, units and prefix
limits in the implementation contract before code; there is no
evidence-selected field expression. Missing/truncated data is null or
explicitly unavailable, never inferred from omitted bytes.

Typed optional UTC packet-time bounds use a half-open interval; typed TCP flag
selection uses `(flags & mask) == value`, with value bits contained by mask.
Their final schema names and numeric limits must be identical in browser/MCP,
canonical selection, native command and worker validation. Packet timestamps
describe saved records, not clock accuracy or network-wide coverage.

Return one transient page: at most 100 rows, at most 32 selected fields and the
existing 24 KiB encoded result bound. No stored derivative, new capture, live
source, capture-history entry or reusable approval is created. Capture Repeat
continues to mean fresh acquisition; polling a query never repeats it.

`max_scan_bytes` limits logical scan work: sum captured frame lengths visited
in original saved-record order, including records rejected by filters/time. Do
not visit a record that would cross the cap. `scanned_bytes` reports that same
sum; separately report visited records and whether row/scan limits ended
logical scanning. A timestamp/predicate match never refunds work. Stop logical
scanning at the selected row or scan limit, but drain and authenticate the full
original/canonical stream before publishing any result.
Full-read/authentication bytes are not mislabeled `scanned_bytes`; total input
and drain work remain independently bounded. Cancellation/source/authentication
failure returns no page, with the existing joined owner/worker cleanup.

Today's published packet sources and qualified raw-summary shapes are bounded
at 8 MiB. The schema's 1 GiB maximum scan value is an API ceiling, not evidence
of 1 GiB sources, resources or completion. Preserve that distinction; qualify
larger advertised source/work bounds separately. Query CPU, units and worker
memory must be measured for the new evaluator/output combination; summary
measurements are reusable dependencies, not qualification of the query.

## Exact authority and disclosure accounting

Metadata sources with metadata fields use ordinary current/retained rights.
Every query over a raw original needs an exact `pcap_query` grant even if only
header fields are requested. A metadata original cannot expose a raw field it
never retained. `grant_id` is conditional on authorized source/selection, not
unconditionally required or chosen to bypass current source checks. Shares and
the raw-summary aggregate right do not replace a raw-query grant.

Extend both standalone existing-artifact raw review and the same human's
selected-client combined `resultAccess`; reuse a covering grant. Omitted
request `clientIDs` resolves once to the authenticated requesting client before
review/digest creation. Explicit selections remain exact; the resolved scope is
shown to the reviewer and never changes on retry. This lets the browser select
its current client without exposing identity-provider settings or asking users
to type client identifiers. Preserve exact artifact digest, original
human/client, current parent decision/expiry/revocation, underlying entitlement
and one shared disclosure pool. No future-artifact grant or acquisition-grant
inheritance is invented.

For query-only scopes, `maxBytes` funds returned disclosure, not the whole
source size: retain verified native sizes as source facts but remove their
whole-file coverage requirement for this operation. Keep the existing
query-only 1 GiB request ceiling. If `download_artifact` is also selected,
retain its verified whole-file coverage requirement and existing download
ceiling. Downloads and queries spend the same selected parent pool, never
separate copied allowances. Each actual raw read batch reserves one operation
and 24 KiB of worst-case encoded output in the existing grant-use journal,
atomically with batch creation. Use identity is the batch ID. Replaying that
batch validates its original use; a new paid batch after known closure pays
again. No page is charged merely for initial pending admission. No refund or
replay renewal follows failure/uncertainty. Scan/capacity budgets remain
separate from disclosure bytes.

The initial query resource candidate reserves four query units for up to two
full 8 MiB read batches. Existing fixed packet summaries keep their two units
and one batch. These are declared conservative allowances, not measured CPU or
memory. Qualification must cover the combined evaluator, transport and crypto.

Existing `access_grant_use` is reusable but previously download-only; its
replay comparison must include operation as well as parent/child/bytes/count.
Bind each use to the exact admitted query/paid batch. Initial C3 authorization
reuses the existing idempotent child materialization before constructing the
immutable query; registration remains charged if later admission fails. The
query pins that known parent and child. The existing query ledger also lacks
the declared public `pcap_query.idempotency_key` lookup: add bounded immutable
key/request-digest association there, not a second lifecycle journal. Resolve
same-key replay before a new compilation/admission/debit, preserve the original
program/grant/handle/deadlines, and reject changed selection or grant. A
repeated initial call returns only the same pending handle, without another
read or debit; the existing paid poll performs any later page read. A lost
reply cannot allocate a successor worker or move spend to a newer grant.

Each new audited Begin repeat registers its exact request in the existing
query-call journal before the strict current permit check. This costs one
bounded control-row insert, under the existing query control ceiling. The
repeat must match the original normalized input MAC, format/version, principal
and keyed query; current audit, source and grant checks remain mandatory.
Re-registering the same call is exact-content idempotent. It is a nonpoll call:
poll count, query allocations, worker identity, batches and disclosure spend do
not advance. No separate journal or replay lifecycle state is added.

Store normalized bounded control selection/program and keyed invocation
identity, not output rows/payload, original arbitrary filter text, credentials
or evidence in SQL/audit/logs. Numeric addresses remain user data under finite
control-copy retention. Current identity/audience/client/retention/recovery
checks, final post-blocking checks, three one-use key roles and original
deadlines remain.

## Complexity and qualification

Required normal workflow, not a hypothetical attack mechanism. Added services,
RBAC/permission names, watches, network destinations, PVCs and acquisition: 0.
Extra Jobs beyond the existing one query worker: 0; scoped key roles/source: 3;
stored evidence artifacts: 0; new expression parsers/dependencies: 0. Reuse
existing query states and conservative uncertain retirement. Grant/read/lock
counts and query units remain to be measured at the composed seam, not reported
as zero. At concurrency N, reserve N qualified worker profiles; no new
pool/watch engine.

Meaningful failing tests must precede implementation: grammar before effects,
metadata ordinary versus raw exact grant, operation/client/digest mismatch,
query-only pool smaller than native, mixed-download coverage, idempotent lost
reply, changed-input conflict, full-tail authentication, truncation and hostile
maximum shapes. Prove cancellation/join and no refill/late result. Then run
real managed SQL/key composition, upgrade/rollback fences, both built React/MCP
consumers and one installed same-original native/tshark comparison. ADR-286's
bounded-Go boundary applies; no native subprocess or credential-bearing parser
plugin is introduced. The local checkpoint below does not replace installed
qualification.

## Local checkpoint and remaining qualification

Candidate `360ba3f60d71c500dff6e5c6512ce38a71421f0d` implements the complete
metadata/raw source, authority, grant-use, query, worker codec and React/MCP
composition. [Local originals](../../test/results/saved-packet-query-local/README.md) retain meaningful failures and focused races. The built
React/Go TLS gate at `bb936966` passed in 107.539 seconds, including limited
nested output and zero/null/prefix checks. Its source reuse is explicit; later
SQL/fixture corrections have separate proof. The canonical/runtime
limited-result mismatch was fixed with a fixed inner narrowing hint and null
outer hint, without raising 24 KiB or trimming rows. The parser reserves 4096 B
for wrapping; a 20,424 B primitive page fits direct 21,254 B and nested 21,955
B audited replies.

[Managed services](../../test/results/saved-packet-query-services-local/README.md) passed separately for metadata 13.764 seconds (`5722a38e`) and raw
15.639 seconds (`b2759438`), each with 4,194 exact source hashes and clean
cleanup. The actual compiled-role path covers two batches/six key roles and raw
per-batch 24 KiB/one-operation uses, current child/parent decisions, atomic
rollback and unchanged acquisition spend. Job/Pod/issuer/join inputs are
controlled component facts. Upgrade 139 at `360ba3f6` passed 401 tests, exact
138 restoration/helper absence and unchanged trust. The four-unit account guard
and source-specific 48 KiB control-binding CHECK are SQL implementation bounds,
not new authorization or returned-data allowances.

[Resource runs](../../test/results/saved-packet-query-resource-local/README.md) at `b2759438` cover two exact 8 MiB originals, 256 instructions, 16
currently distinct fields/64 B raw prefixes and 233,011 tiny records/cache
overflow, plus cancel/error joins. All 1,812 dependency hashes matched and four
consumers/probes/cleanup passed. Complete cgroup memory peaks 94,838,784
B/134,688,768 B stayed below 256 MiB; zero swap and 500m quota were observed.
CPU enforcement or sustained 500m throughput is not proved by these short
samples. The local provider allocations share the consumer process; hub
compilation, public SQL/native command/bootstrap and installed maximum input
are outside this measurement.

Eligible CI, PR/merge and one installed same-original MCP/React/native-tshark
workflow remain pending. No complete S-05, all-maxima, sustained-load,
second-cluster or release claim follows from this local checkpoint.
