# ADR-291 — Bounded profile summary authority and query composition

Date: 2026-11-03. Status: implemented; named installed CPU/heap summaries pass; maximum-input containment remains pending.
Requirements: REQ-PRF-003/005, REQ-EVD-005, REQ-MCP-003/005.
Depends on [ADR-286](286-bounded-go-analyzer-isolation.md).

## Decision

Reuse the existing approved projection query, its regional worker, original
request owner, prepaid ledger, one-use key slots and joined retirement. Add one
closed `pprof` source and `get_profile_summary` selection: exact case/artifact,
sample type and top-N (default 20, maximum 100). The source remains **raw** with
evidence type **profile**. Its manifest has no invented projection digest; the
query binds the existing verified ciphertext-copy version, original native
format and fixed `approved-pprof-summary/v1` display definition. Go traces, cores,
raw packets and caller-supplied source definitions are not this source.

C-03 uses a separate `ReadProfileSummary` operation for this closed aggregate.
It requires current `evidence:read`, ordinary target roles, complete denies,
the original retained audience, retention, processing and recovery. The raw
source must be exactly pprof; the ordinary `ReadApproved` and `DownloadApproved`
evaluators continue to refuse raw evidence. Every post-read recheck uses the same
summary operation and original deadlines. A summary grants no native download,
raw query, collection or permission to emit labels, paths, addresses or samples.
Raw native download keeps its independent reviewed result-access child.

The existing projection-policy port now receives the closed source native type.
It selects client permissions for the result's class and source evidence type:
metadata/context for pod status, extract/packetCapture for HTTP headers, and
extract/profile for a profile summary. It preserves the actual raw profile
classification supplied to processing and retention. Metadata/context client
permission is not a substitute for extract/profile permission. Unknown source
kinds fail closed. The complete original policy observation remains bounded.

Shares remain the existing metadata-only feature. A raw profile summary does
not consult its share fallback, even when ordinary target or retained-audience
eligibility refuses. Broader profile sharing remains a separate S-06 boundary;
this increment neither reclassifies the original nor creates a stored derivative.

The internal service admits only an exact acknowledged `get_profile_summary`
invocation and immutable selection. It uses the existing routing port, then the
current authority and query-plan ports. A successful query owns one read batch.
The result union admits only the selected closed summary and validates its
selected sample type. The coordinator bounds its JSON to 24 KiB independently
of analyzer validation.
Copies own all hotspot/name/fraction pointers; closure clears retained output.
Migration 127 admits this exact closed source through the existing SQL ledger.
The protected runtime installs the optional presentation facet only with its
complete typed route and an accepted worker of at least 256 MiB. Per-query
backing independently requires the matching transient declaration before
admission. This is candidate activation for qualification; it does not establish
an installed S-05 exit. The facet embeds the closed schema, binds audited input
and serializes pending/ready results; ordinary query construction without the
typed source route does not install it. The regional worker now
connects the existing native reader to the bounded analyzer through one delivery
chunk buffer (256 KiB), retaining no whole compressed profile. The authenticated
whole-file check and exact EOF must finish before a result is accepted. The
source's authored native limit remains binding up to the format maximum; a
16 MiB source does not become a 64 MiB source. Native transport carries the bare
closed summary within 24 KiB and refuses oversized output without trimming. The public response must additionally fit its complete
existing 24 KiB envelope budget. An oversized selected result refuses and asks
for fewer hotspots; it never silently trims the selection.

## Browser and public timing

Initial pending and ready summary data carry `query_observed_at` and
`query_expires_at`, matching the existing saved-status tool. A resolved poll
retains exactly the outer query times and request ID. These are the original
query dates, not a new observation or renewed authority. The browser counts
network delay in its monotonic cutoff, keeps the earliest cutoff, and clears
results on close, source/version change, session loss or expiry. Its request
transport ceiling is the existing server's 20-second evidence-read window;
shorter server/request deadlines still win. It accepts at most the existing
24 KiB envelope and refuses integers JavaScript cannot represent exactly.

The authorized case row optionally exposes its verified `native_format`; this
adds no lookup, native bytes, filename or plaintext checksum. The browser offers
an explicit saved summary only for ordinary-access raw pprof rows. Go traces and
metadata-only shares have no summary action. One transient controller owns each
artifact/version; mounting starts no work. Sample type and top-N are explicit,
function names are text, nullable percentages stay unavailable, and there is no
background polling, external symbol lookup or browser persistence.

## Funding and resource boundary

The S-05 plan's earlier two-query-unit estimate is not evidence for a 64 MiB
profile. A conservative existing profile-window read plus metadata costs more
than 72 MiB and fits ten existing 8 MiB query units. Migration 127 charges ten units atomically to the original root, workload and
principal accounts. This conservative read-work reservation is not a measured
physical memory bound.
Stream verified native chunks into the analyzer rather than retaining another
64 MiB compressed buffer. Parsing still owns the bounded decompressed input and
its object graph. Neither post-parse counts nor a per-query Go memory setting
provide a hard heap bound. Physical worker resources, pre-parse shape controls,
all allocation dimensions and provider work must be measured and funded before
admission is enabled for the intended workload. The legacy summary compatibility
floor remains 256 MiB for both physical and declared transient capacity. The
current shared installer declares 384 MiB for both under ADR-295, replacing the
earlier 256 MiB installed declaration and insufficient 8 MiB transient value.
The named CPU/heap runs qualify their actual inputs at 384 MiB; maximum-shape
composed worker cost remains pending. Summary admission still requires the
legacy floor; older configurations below it serve their existing tools and
fail summary compatibility. No new
reacceptance state, worker template, credential or physical reservation is added. Preserve the original 20-second projection operation bound
unless actual qualified measurements justify a separate change.

Migration 127 extends the existing closed scope/tool/audit functions, exact
selection, ten-unit account increments and query charge, retaining migration 126's
preview window. Downgrade refuses retained summary queries or invocation audit;
on an empty history it restores the exact prior definitions.
No new table, credential, network destination, worker kind or lifecycle state is
required by this design. The owned PostgreSQL/S3/OpenBao fixture proves actual approved profile
admission, API execution completion, independent publication, current C-03
read authority and SQL query accounting. Native target/process observations and
worker ownership remain synthetic. Those fixture results alone do not qualify installed SQL/key/worker composition,
cgroup lifecycle or public MCP output. Named installed CPU/heap focuses provide
separate scoped evidence in the current implementation ledger. Browser component and built-browser fixtures use
explicitly synthetic summary responses; they do not substitute for that run.

## Complexity gate

| Question | Answer for this internal checkpoint |
| --- | --- |
| 1. Observed benefit | First-release profile summaries are required; no frequency or performance percentage claimed. |
| 2. Accepted risk | ADR-286 authorizes bounded Go interpretation with shared worker credentials, not arbitrary raw disclosure. |
| 3. Typical use | Yes: ordinary investigation of retained Go profiles. |
| 4. Precedent | Existing HTTP-header query ledger and regional approved-result transport; no new analyzer service. |
| 5. Added exposure | Zero credentials, privileges or network destinations; one closed source/operation. |
| 6. Added states | Zero persistent lifecycle states; existing pending/refused/uncertain closure. |
| 7. Machinery configuration | None; operator resource limits still need qualification. |
| 8. Dependencies | Existing google/pprof parser and worker process/cgroup lifecycle. |
| 9. Aggregate cost | One worker and one read batch per summary; ten read-work units, zero extra Jobs/PVCs/watches; current installed declaration 384 MiB matches the physical worker. Named CPU/heap inputs pass; maximum-input containment remains pending. |
| 10. Rollback | Migration 127 changes functions only; no new tables. Empty-history downgrade restores old definitions; retained summaries refuse atomically. Removing the optional route disables new summary requests. |
| 11. Smaller fix | A tool-name-only addition would bypass source, classification and funding checks. Reuse existing ports; qualify the complete optional runtime before release. |

## Verification boundary

The internal component tests cover exact source/version/display/selection,
ordinary audience and permission/deny checks before protected lookup, expiry and
cancellation after blocking reads, refusal of raw cores/traces and other
operations, source-specific client policy, unchanged metadata-share limits,
original acknowledged invocation and result ownership. They provide no installed
qualification or proof that the current worker can process every permitted shape.


## Heap selection and qualification continuation

The saved acquisition's requested type suggests an editable browser selection:
heap starts with `inuse_space`, CPU/unknown with the existing `cpu`. Suggestions
establish neither native semantics nor units. Case/artifact/version-scoped form
state preserves edits across metadata refreshes and resets on source changes;
opening a view starts no query. The existing authorized result establishes the
selected native unit and nullable duration.

The focused installed heap fixture reuses the immutable namespace profile and
existing regional query/approval/native-download path. It selects snapshot,
16MiB/5s and forced GC false, completes a read-only `inuse_space` summary before
native preparation, then checks the separately authorized original's exact unit,
signed total, nullable duration and target. The same fixture's CPU route retains
its expiry, refusals and Stop proofs. Existing384MiB resources and funded query
units remain unchanged. Local component/built-console checks pass. Native41818585176 on `80593f93`
also passed this namespace heap MCP workflow: 531 native bytes, two samples,
4,326,741 signed `inuse_space` bytes and null duration, followed by fresh repeat
preview without another capture. All 4,117 source hashes match the frozen head;
Go exited 0 in 580.027s, cleanup was empty and scratch was removed. Installed
heap React interaction and maximum-input containment remain open. PR160 merged
as `5b765322` after eligible `pull_request` CI41821140504 passed, with the entire
merge tree equal to qualified `80593f93`. Originals and scope are in [implementation progress](../implementation-progress.md).
