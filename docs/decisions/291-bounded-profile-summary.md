# ADR-291 — Bounded profile summary authority and query composition

Date: 2026-11-03. Status: accepted internal contract; production composition and qualification pending.
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
Public routing and SQL admission remain disabled. The regional worker now
connects the existing native reader to the bounded analyzer through one delivery
chunk buffer (256 KiB), retaining no whole compressed profile. The authenticated
whole-file check and exact EOF must finish before a result is accepted. The
source's authored native limit remains binding up to the format maximum; a
16 MiB source does not become a 64 MiB source. Native transport carries the bare
closed summary within 24 KiB and refuses oversized output without trimming. The public response must additionally fit its complete
existing envelope budget before activation.

## Funding and resource boundary

The S-05 plan's earlier two-query-unit estimate is not evidence for a 64 MiB
profile. A conservative existing profile-window read plus metadata costs more
than 72 MiB and fits ten existing 8 MiB query units. This is a proposed read-work
reservation, not an implemented SQL charge or a complete memory qualification.
Stream verified native chunks into the analyzer rather than retaining another
64 MiB compressed buffer. Parsing still owns the bounded decompressed input and
its object graph. Neither post-parse counts nor a per-query Go memory setting
provide a hard heap bound. Physical worker resources, pre-parse shape controls,
all allocation dimensions and provider work must be measured and funded before
admission is enabled. No worker template or accepted capacity profile changes in
this checkpoint. Preserve the original 20-second projection operation bound
unless actual qualified measurements justify a separate change.

SQL follow-up extends the existing closed scope/tool/audit functions, exact
selection and query-unit charge, retaining migration 126's preview window.
No new table, credential, network destination, worker kind or lifecycle state is
required by this design. Resource/read bounds, actual SQL/key/worker composition,
OOM and unjoined cleanup, and installed MCP/browser output remain unqualified.

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
| 9. Aggregate cost | One worker and one read batch per summary; proposed ten read-work units, zero extra Jobs/PVCs/watches. Physical memory unresolved. |
| 10. Rollback | No schema/layout changes here; zero fields omitted preserve existing scopes. New production route remains absent. SQL rollback follows in the funded increment. |
| 11. Smaller fix | A tool-name-only addition would bypass source, classification and funding checks. Reuse existing ports and keep activation closed. |

## Verification boundary

The internal component tests cover exact source/version/display/selection,
ordinary audience and permission/deny checks before protected lookup, expiry and
cancellation after blocking reads, refusal of raw cores/traces and other
operations, source-specific client policy, unchanged metadata-share limits,
original acknowledged invocation and result ownership. They provide no installed
qualification or proof that the current worker can process every permitted shape.
