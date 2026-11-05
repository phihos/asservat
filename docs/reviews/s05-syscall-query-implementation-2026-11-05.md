# Saved syscall argument query implementation plan

Date: 2026-11-05. Current base: `afc54889f20399bfdcd792c3a8b33d2482d118c8`.
Status: typed interfaces implemented; named component/service/resource checks
pass. Installed workflow implementation is prepared; its qualification is pending.

Implementation checkpoint: raw domain/decoder/receiver, encrypted object reader,
authorization, migration140, audited C20 delivery and console controls exist in
the isolated working branch. The selected bounds are four units/two batches,
24 KiB/one operation per actual raw batch and 20 KiB private pages. C20's
maximal structured page test passes at 20,349/21,223/21,890 bytes for private,
direct and nested outputs, preserving whole events and cursor. The real console
workspace/HTTP-client approval-to-query unit journey passes with synthetic
responses, as do 35 focused UI tests and TypeScript checking. Initial test-only
fixture URL and detached-button mistakes are retained in their failed logs;
they are not product regressions. The built React/GoTLS fixture also passes two subcases with race detection in
11.927s, including reviewed access, original pending clocks, a fresh-key next
page and whole recorded values; its authority and query responses are synthetic.
The real SQL lifecycle and pristine upgrade140 now pass9/497 tests with exact
source/cleanup evidence. Twenty PostgreSQL JSONB sizes fit existing bounds;
the maximum full binding is35,750B under48KiB. Separate actual encrypted-reader
resource cases pass two near8MiB sources plus cancel/error, with a57,393,152B
peak under256MiB; CPU500m remains configuration-only. The SQL paid loops use
synthetic crypto/join proofs; their scope is distinct from parser/decrypt work.
Installed MCP/React/native parity remains unrun. No whole S-05 or project
completion is asserted. [ADR-306](../decisions/306-bounded-saved-syscall-queries.md)
records the implementation contract. Packet PR169 is separately qualified by
native42023214158 and merged, with proof closure in PR170.

The installed argument fixture now retains all five fixed views, Repeat and
Stop and adds two raw queries against the same native JSONL. All seven queries
are prepaid from the beginning (18 units). A test-only rolling two-slot queue
preserves each original worker end, immediate live SQL/key checks and final
joins; the advancing-clock model is not a measured hosted speedup. The actual
console scope producer regression reproduced missing `evidence:raw` for
arguments; the corrected fixture and control foci pass. Original request,
capture, worker, authority and20-minute workflow limits are unchanged.

## User outcome and reusable boundaries

From one saved raw argument recording, request independent `syscall_query`
access for the current client, approve it through the existing inbox/step-up
flow, select names/errors and inspect exact recorded arguments in React/MCP.
Reuse a covering standalone or same-human combined result-access grant. Native
download is independent; no recollection, new derivative or history entry.

Required scope comes from REQ-SYS-003 / SC-SYS-003, REQ-MCP-002/003/005,
REQ-EVD-005/008 and REQ-AUT-003/004/006. Existing `syscall_query` schema already
specifies names/errors, cursor, 100-event maximum and raw output. This next-step
ordering and regional Go implementation are engineering choices under standing
delegation. File/log/process/network diagnostics and eBPF profiling remain
required S-05 work, not substitutes or implied completions.

| Existing boundary | Reuse and missing work |
| --- | --- |
| `domain/artifact/argument_records.go`, `adapters/syscalls/arguments_check.go` | Reuse raw event DTO, closed argument definitions and canonical full-file validator. Add a distinct typed raw visitor; keep its metadata visitor unchanged. |
| `application/analysis/syscall_queries.go`, `domain/analysis/syscall_selection.go` | Current summary/events views cannot return arguments. Add source-aware raw selection/result/delivery, preserving old serialized scopes and cursors. |
| C3 source-aware projection and packet-query authorization | Dedicated raw purpose, current exact original source/client and grant; no generic `ReadApproved` widening. Initial materialization, current exact-child lookup and missing-approval remedy reuse existing seams. |
| Existing packet-query invocation and paid-batch ledgers | Reuse exact caller/client key+request digest, stable pending replay, batch-ID atomic raw use, one shared pool and conservative charges. Add the closed syscall operation through every producer/consumer. |
| C14/objectstore/native command | Distinct typed callback and source/display selection through actual receiver, native codec, outer encrypted reader and worker bootstrap. Three one-use key roles per actual read; full EOF before disclosure. |
| C20/contracts/React | Existing syscall schema is aspirational: runtime operation selector supports only summary/events. Wire the new operation through the same audited route, canonical/browser schemas, raw review UI, result union and exact-source controller. |

## Typed agreement before behavior

Keep public names `case_id`, `artifact_id`, `grant_id`, `syscall_names`,
`errors_only`, `cursor`, `limit`. Propose required `idempotency_key` with the
same syntax as `pcap_query`; this is a deliberate canonical contract extension
to the previously unimplemented tool. No argument expressions or predicates.
The coordinated proposal is `SyscallQueryView = "raw"`, display version
`approved-syscall-query/v1`, the existing comparable `SyscallWindow`, and a new
`RawSyscallQueryRequest{CaseID, ArtifactID, GrantID, IdempotencyKey, Selection}`.
Add `SyscallArgumentPage` and a distinct result-union branch; do not repurpose
the current metadata `SyscallQueryRequest` or `SyscallQueryService`. Names remain
subject to integrator agreement before shared-file edits.

Raw result reuses `artifact.RawArgumentEvent`: original identity, ABI, time,
outcome, optional duration/errno and ordered argument values with truncation.
Copy `decimal:`, canonical `base64:` and `unavailable:fault` without interpreting
them or inventing missing bytes. Existing 128-byte captured memory values and
8192-byte native lines remain stricter than public value-schema ceilings.
Treat zero/empty, unavailable, truncated, unmatched and unfinished distinctly.

Bind cursors to exact source/version, view and normalized filter; preserve the
first omitted matching event across encoded-page limits. Each page Begin has
its own stable key. Same-key Begin returns only the original pending handle
after current checks, without another page read or charge. Polls retain the
same fixed query cutoff; observed response times may advance. A cursor is
neither a grant nor permission to move to a changed artifact.

Agree the total result reserve and maximum-shape witness before code. Existing
24 KiB applies to direct and nested envelopes, including cursor, coverage and
warnings. Whole-event prefix only: no partial argument clipping or false empty
success. Logical page stop still drains/authenticates canonical complete EOF.
Current source limit is 8 MiB; no schema ceiling advertises larger support.
Use existing source record/event bounds and original command deadline.

For an initial candidate, evaluate the existing four-unit/two-batch allowance,
24 KiB/one raw operation per actual batch and worker resource profile. These
are proposed configured accounting bounds, not measured cost. Reuse existing
allowed values if the composed maximum-shape checks support them; record final
choices before behavior. No new role, pool, journal or configuration switch.

## Ownership and delivery sequence

1. Contract/interface freeze: revise normative syscall/MCP language and schemas
   for regional Go interpretation, exact recorded values, scan/page/EOF,
   idempotency and raw review. Include standalone and combined action-operation
   eligibility. Keep metadata views and native download independent.
2. Domain/parser owner: closed source/selection/result and decoder callback;
   meaningful current-source refusal RED, raw marker versus metadata isolation,
   corrupt tail, full counts, cursor and full-row byte boundaries. No new parser
   framework or acquisition-engine changes.
3. C3/C18 owner: dedicated raw purpose, initial/current exact grant, key replay,
   immutable source/child and current post-blocking identity/authority; native
   codec and protected bootstrap. Missing/wrong grant never becomes a metadata
   fallback. Keep registration spend on later failure conservative.
4. SQL owner: closed operation and source/scope guards, actual atomic grant-use
   batch association, original invocation replay/current grant check, compiled
   role grants and exact upgrade/Down restoration. Inspect account-unit and
   encoded control-binding constraints before service qualification.
5. Public/UI owner: audited request normalization/MAC, exact raw result union,
   approval remedy/current-client defaults, controller-owned cursor/key/expiry,
   escaped argument text and bound coverage/truncation copy. Reuse the actual
   built React driver/Go TLS fixture before installed dispatch.
6. Integrate one private candidate, freeze writers, independent producer/consumer
   review, one broad gate/affected compiled-role services and resource checks,
   then one fresh installed workflow after eligible CI and review. No public
   parallel feature candidate while PR169 remains pending.

Concrete files are assigned before writers start; these are ownership groups,
not permission for overlapping edits or another component handoff as the final
outcome.

## Acceptance and retained evidence

- RED before fix: real runtime operation absent; legitimate exact syscall grant
  rejected by current closed operation list; metadata views never contain the
  synthetic argument marker. Add actual receiver/native-command and public
  audited direct/pending/nested delivery tests, not just parser tests.
- Denials: missing/raw-only scope, wrong client/operation/case/version, revoked
  parent/child, expiry, changed key/filter and exhausted shared pool. Ordinary
  metadata/share or download-only approval cannot inspect arguments. Source
  absence and denial retain the common privacy-preserving refusal.
- Full source: maximum valid line/record/output expansion, faults/truncation,
  empty values and long escaped identity/coverage envelopes; bad footer/tag/tail,
  cancellation and source error produce no page and join. Prove strict cursor
  advancement with no omitted/repeated row and full EOF after logical stops.
- Real managed services: compiled hub/key roles, ordinary/source checks and
  exact grant materialization/current lookup; paid batch uses and three key
  roles per read, shared same-human client accounting, replay/no additional
  worker/use, atomic rollback and revocation after blocking. Acquisition credit
  and original deadlines remain unchanged. Test actual release upgrade/Down/Up.
- Resource component: separate producer and actual receiver/outer reader through
  encrypted TLS store and three key roles; declared maximum source/output
  shapes, complete/cancel/error joins, memory/CPU configuration and observed
  counters. Do not inherit packet resource qualification or claim sustained
  CPU enforcement from short configured-quota runs.
- Installed: extend **`continuation-manual-arguments`**, not metadata
  `continuation-manual-syscall`. Preserve existing fixed summaries/events and
  marker exclusion, independently reviewed raw MCP/React query, exact native
  JSONL parity and original grant/pool/key/live-worker/terminal proofs. Marker
  occurs only in explicitly authorized raw query/native output, never metadata,
  ordinary logs, SQL or audit. Actual UI values, not an injected controller,
  must match the delivered page. No second capture merely to query.

PR150's metadata fixture passed Go/workflow in 842.843 seconds. Its argument
fixture passed Go in 919.995 seconds with unchanged sources and clean cleanup,
but the outer job was cancelled at its wall-clock limit. Reuse those named
acquisition/native/metadata boundaries only; do not call the argument workflow
green or this query qualified. Before the new installed run, plan the whole
workflow within its unchanged 20-minute ceiling. Avoid blindly adding expensive
serial queries to the prior fixture. Any pipeline reuse must retain immediate
live proof, exact original worker joins and positively proven retirement.

## Complexity gate

| Question | Bounded answer |
| --- | --- |
| 1. Observed problem | Required raw query is absent; existing raw recording can only be downloaded or inspected as metadata. Not a newly invented attack. Usage frequency is not measured. |
| 2. Accepted risk | ADR-286 shares parser/process credentials; retain it. No new instantaneous revocation or scratch requirement. |
| 3. Typical benefit | Sensitive opt-in investigations of already captured arguments; no cost to metadata-only capture. |
| 4. Precedent | Existing syscall decoder/metadata views and packet-query authority/delivery are local precedents. No novel language/engine; no new external-mechanics claim. |
| 5. Privilege/exposure | 0 new Kubernetes calls/RBAC, credentials or destinations. One new explicitly approved raw result operation; existing scoped worker capabilities. |
| 6. States | 0 new fallback states; reuse pending/ready/refusal/expiry/cancel and conservative unknown spend. |
| 7. Configuration | 0 switches/timers solely for this mechanism. |
| 8. Dependencies | 0 new dependencies/services; current engine/native format/provider behavior remains a dependency. |
| 9. Aggregate cost | 1 existing worker/query; 3 key roles/read. Finite batch/units/output caps to agree above; measure full scan, output, crypto and transport. No watches/background loops. |
| 10. Upgrade/disable | Extend existing closed guards/schema; prove exact Down/Up and historical unavailable behavior. Missing composed port refuses the operation. |
| 11. Smaller solution | Native download remains useful but does not satisfy the explicit typed-query promise. Reuse decoder/ledger/UI beats a new language, parser, capture or scratch service. |

This document authorizes no behavior by itself. Final interface/contract review,
implementation, local/service/resource checks, CI, installed qualification and
normal merge remain pending. No complete S-05 or supported release claim.
