# S-05 saved-packet query implementation plan

Date: 2026-11-05. Status: implemented and locally qualified at the source
scopes below; installed query qualification, eligible CI, PR publication and
merge are pending. Current candidate:
`360ba3f60d71c500dff6e5c6512ce38a71421f0d`. [ADR-305](../decisions/305-bounded-saved-packet-queries.md) records the selected
implementation choices. Raw-summary PR167 is merged with its named installed
qualification; it does not qualify this query.

## Complete user outcome

From an existing metadata or raw packet artifact, select a tcpdump/libpcap
filter, optional typed time/flag bounds and closed fields, run one bounded
query and read the same authorized page in React/MCP. Raw source/prefix use an
existing covering `pcap_query` grant or the normal independent review,
including combined capture result access. No recollection, mandatory download,
derivative or new approval for ordinary metadata. Finish both source paths; a
schema-only or metadata-only handoff does not finish the outcome.

## Contract choices before behavior

- Explicitly amend REQ-MCP-003/SC-MCP-003's display-filter wording to named
  tcpdump/libpcap syntax, preserving numeric/address/field outcomes and separate
  typed packet-time/flag selectors. This resolves S-05 S6/F4; it is an engineering
  choice under delegated proportionality, not explicit new user approval. Rename
  the unimplemented public field to `packet_filter`; retain no misleading legacy
  alias when no runtime caller or stored query uses it.
- Keep 512 B public filter cap, existing screened compiler/Go-VM checks, no DNS and
  no bracket predicates (`RawBytePredicate`) in this initial subset. Add no new
  expression parser. Publish the exact finite field enum, timestamp units and
  raw saved-frame prefix offset/length maximum, missing-field nulls and response
  cap flags. Offsets address actual captured bytes, never fabricated padding or
  an inferred payload start in an incomplete header.
- Keep 100 rows/32 fields/24 KiB encoded page. Scan counts captured bytes of every
  logically visited saved record, even nonmatches; no partial record crosses
  the byte cap. Full original authentication/canonical EOF still follows a
  logical cap. Report logical work and its limit reason separately from EOF.
- Make grant_id conditional after exact source authorization. Query-only pools
  fund output rather than require native-file-size coverage; combined download
  retains whole-file coverage. Preserve query-only 1 GiB grant ceiling and one
  shared pool. Scan ceiling 1 GiB is distinct from today's 8 MiB sources and named
  qualified resource shapes; do not advertise unmeasured support.

## Actual reusable seams and gaps

| Owner/surface | Work and existing seam |
| --- | --- |
| Common C3/C18 owner | New typed selection/result/source version, exact ordinary/raw route and output class; `application/analysis/{context_query,packet_summary}.go`, `application/authorization/{raw_query,grants}.go`, `domain/authorization/{raw_query,grant}.go`, native projection codec/bootstrap. Fixed raw-summary authority must not authorize packet rows. Bind canonical normalized input/program to OperationMAC and actual native command. |
| Parser/worker owner | Reuse `adapters/packets/filter.go` (pinned compiled program, original wire-length semantics) and the bounded saved-PCAPNG decoder. Decode only requested closed fields/prefix from saved bytes. Reuse `evidence/packet_summary.go`, `objectstore/packet_summary_read.go` patterns for authenticated full tail, deadline and joined failure; add a distinct query callback, not a broader summary output. Resource maxima must cover filter VM caches, decoder, crypto, output and transport together. |
| SQL/grants owner | Extend download-only operation checks in `domain/authorization`, application grants, PG adapters and effective SQL. Existing immutable grant-use journal can retain operation/idempotent debit; replay must compare operation too. Extend the existing context query ledger with exact caller/client key+normalized request digest and raw-use association before effects. No caller purpose flag or new separate journal. Lock order/current grant/deadline and rollback/downgrade fences remain. |
| Public/UI/integration owner | Canonical MCP/OpenAPI/browser/native schemas and generated parity; actual pcap_query route (absent from `presentation/operation_query.go: 10` and compiled tool list), audited normalization, conditional review/remedy, rows/limits/handling UI, get_query_result typed union and exact source binding. Existing saved summary/native/Repeat controls stay unchanged. Own installed continuation-manual-raw extension. |

Assign concrete files and freeze shared type APIs before writers edit. The
table is a handoff boundary, not permission for overlapping ownership or a new
framework. Requirement owners remain existing MCP/evidence/grant components.

The grant gaps are real: `RawQueryScope.Valid`, `ResultAccess.Valid`,
`normalizeRawQueryRequest`, `RawQueryCandidates`, `ReserveRawResult` and
`ReserveGrantUse` permit download only. The latter's replay currently omits an
operation comparison because only one operation is possible. Current pcap_query
schema requires an idempotency key but no runnable producer or query-key lookup
exists. Query admission, one raw use and paid batch must remain durably
associated before a worker/key read; retries find that exact association, not
another grant. Prefer the existing admission transaction if its current lock
order permits; do not claim atomicity from a sequence of independent calls. If
separate existing transactions are necessary, uncertain spend remains charged
and the existing query/use records must settle exact replay without another
execution.

The preview exposes a bounded advisory list of exact raw output action IDs and
current supported operations, derived from the compiled plan with no extra
reads. Omitted request `clientIDs` resolves to the authenticated current client
before review/digest creation; explicit selected clients remain exact. Browser
submissions preserve the selected access snapshot and original expiry through
uncertain replies and approval retries. No identity-provider configuration is
exposed and no manual client identifier is needed for the current-client flow.

The selected seam is the existing `BeginReadBatch` transaction: reserve one 24
KiB/one-operation use with use ID equal to batch ID before inserting that
batch. Admission pins a stable child from existing C3 materialization, without
a page debit. A new batch pays again; initial same-key replay returns only the
original pending handle. The new query candidate uses four units/two batches;
fixed summaries retain two/one. Original installed fixture funding must cover
both existing summary reads (four units) and both new query reads (eight
units): plan 16 backed root/principal/workload units before installation, not a
later top-up. Measure and qualify this declared candidate before advertising
it.

## Ordered implementation and evidence

1. **Contract + RED.** Review ADR choices; update relevant normative prose,
   schemas, source/selection/grant unions and scope/version design. Retain failing
   real compiler/evaluator tests for 512 B/hostile/bracket input before effects,
   time/flag boundaries, metadata no-grant and raw grant-required. Retain failing
   SQL tests for query-only output allowance below native size, mixed-download
   coverage and operation-specific replay. Compile filter once at initial Begin;
   replay retains the originally pinned compiler/program.
2. **One complete path.** Wire source-aware current ordinary/raw access, exact
   grant/pool use and immutable query identity through actual receiver/reader,
   decoder, result validator and browser/MCP. Query-only callers need appropriate
   evidence/raw query scope, not an incidental download permission. Apply current
   source/client/share rules and same-human selected-client parent inheritance;
   no generic raw approved-read expansion or implicit share fallback.
3. **Focused verification.** Actual encrypted raw/metadata originals; full EOF
   corruption after logical row/scan stop; saved truncation and null fields;
   numeric prefix/native-byte parity; no payload in control/audit/logs. Deny wrong
   operation/client/digest/revoked/expired/exhausted grants, changed selector/key
   replay and early cleanup; preserve original request/source cutoffs after
   blocking reads. Prove one batch/debit/worker despite a lost response. Exercise
   max filter instructions/wire-length cache, requested fields/output and raw
   shapes under the declared worker resources, cancel/source-error/join; measure
   units/CPU/memory instead of inheriting summary 2 units/256 MiB as qualification.
4. **Integrated + installed.** Freeze all writers; run repository, contract,
   affected races, built React actual-driver tests and pristine real managed
   SQL/key/upgrade fixtures. Extend the existing manual-raw native suite with
   metadata no-grant and raw query after review, exact output/native/tshark parity,
   accounting/current-grant denial and cleanup. Dispatch one final frozen source
   only after local failures are resolved and independent reviews finish. Native
   policy/refusal/download and raw-summary evidence keep their own source scopes.

## Verified local checkpoint

[Local evidence](../../test/results/saved-packet-query-local/README.md), [managed services](../../test/results/saved-packet-query-services-local/README.md) and [resources](../../test/results/saved-packet-query-resource-local/README.md) retain original failures, exact source
scopes and readback. The implemented path includes screened pinned compilation,
exact ordinary/raw source authority, standalone/combined query grants,
current-client default, original-key pending replay, atomic per-batch
disclosure use, complete authenticated drain and shared primitive public/native
cells. Four query units cover at most two batches; metadata has no raw debit,
while each actual raw batch reserves 24 KiB/one operation.

The built React/Go TLS gate at `bb936966` passed in 107.539 seconds with
metadata, raw zero/null/prefix and limited nested cases; old browser cases/28
journeys and 27 accessibility scans passed. The limited-response failure was a
runtime/browser contract mismatch, fixed by retaining the inner hint and
resetting outer limit metadata. A 4096 B reserve keeps the maximal admitted
20,424 B primitive page inside 24 KiB after direct 21,254 B or nested 21,955 B
wrapping.

Separate pristine managed metadata 13.764 seconds (`5722a38e`) and raw 15.639
seconds (`b2759438`) campaigns passed with 4,194 exact source hashes each,
unchanged source and clean cleanup. Actual compiled roles, encrypted audit, two
batches/six key roles, current-grant denial, quota/use rollback and
retained-history refusal are covered; Job/Pod/issuer/join remain synthetic.
Upgrade 139 at `360ba3f6` passed 401 tests with 4,194 exact hashes/unchanged
source/clean cleanup, strict actual 138 restoration and all four new helpers
absent after Down.

Four fresh resource consumers at `b2759438` passed with 1,812 exact dependency
hashes: two 8 MiB shapes/256 instructions, 16 distinct fields/64 B prefix
output, 233,011 tiny records/cache overflow, cancellation and source error.
Complete memory peaks 94,838,784 B/134,688,768 B stayed below the observed 256
MiB maximum; zero swap and three roles/read were checked, and all containers
were removed. 500m is verified quota configuration, not demonstrated CPU
enforcement or sustained throughput. This component excludes hub
compilation/public SQL/native command/bootstrap and installed maxima. Full
go-check passed at its recorded source scope; pre-push at `b2759438` passed 529
console tests. Later migration and fixture changes retain separate checks
rather than a fabricated single frozen run.

The failed account-delta, key-binding 16 KiB, premature admin-pool close and
preparatory-ordinal snapshot runs remain archived. The fixes add four-unit
admission and a closed packet-query 48 KiB control bound, preserve cleanup and
compare the actual 139 round trip exactly. No installed query pass is claimed;
finish the same-original MCP/React/native-tshark workflow next.

## Cost and decision checks

No new service/watch/RBAC/permission name/network
destination/dependency/parser, PVC, acquisition or stored artifact. One
existing worker/query, three one-use key roles/source and one ≤24 KiB page; no
extra persistent lifecycle states. At concurrency N, cost is N qualified worker
reservations plus existing query/grant transactions. The four-unit/two-batch
accounting bounds are configured and verified locally; the named component
runtimes above are observations. Broader load, CPU enforcement and installed
SQL/latency costs remain pending. Numeric/address filter controls remain finite
user data; no new encrypted-control service is justified for the
payload-literal-free subset. Disable removes new admissions; rollback must
refuse retained new scope/grant operations rather than reinterpret them. Native
download remains useful but does not discharge the promised query outcome.

Read-only audit inputs: cache `raw-packet-query-next-s05-plan.md` (current
b6e), `raw-packet-query-control-privacy-547.md` (historical source), S-05
S4/S6/F3/F4, specs/mcp.md, packets.md, investigation-approval.md,
artifact-downloads.md and privacy.md. ADR-286 governs bounded Go analyzer
isolation. The local checkpoint above records executed checks; the remaining
installed acceptance is not passed by this plan.
