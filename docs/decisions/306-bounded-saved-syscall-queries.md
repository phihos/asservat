# ADR-306 — Bounded queries over saved syscall arguments

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

Date: 2026-11-05. Status: component implementation and named service/resource
checks pass under standing delegation; installed qualification pending. Requirements: REQ-SYS-003 / SC-SYS-003,
REQ-MCP-002/003/005, REQ-EVD-005/008, REQ-AUT-003/004/006.
Plan: [saved-syscall query implementation](../reviews/s05-syscall-query-implementation-2026-11-05.md).

## Outcome and authority

Complete the specified `syscall_query` workflow: an authorized human or agent
selects syscall names/errors in an existing saved argument recording and reads
bounded recorded arguments through React or MCP after independent raw review.
No new acquisition, user-memory read, live tracing, pointer dereference or
expression execution occurs. Native JSONL download remains independently
available under its own covering operation; downloading is not a substitute
for the query workflow.

This is an implementation proposal under the maintainer's standing complexity
delegation, not a new explicit maintainer requirement. The capability is already
required by [REQ-SYS-003](../../specs/syscalls.md#req-sys-003--evidence-projections-and-mcp).
Reuse ADR-286's regional bounded Go interpretation and the existing validated
argument-record decoder. Revise the unimplemented tool description's “offline
sandbox” wording before behavior: parser and credentials share the regional
worker process; no intra-process sandbox is claimed. Native tools and execution
of evidence-supplied content retain ADR-036. This decision does not reopen the
narrow acquisition-engine exception in ADR-281.

## Source, selection and result

Accept only the protected original `SyscallArgumentsArtifact`, class `raw`,
format `asservat-syscall-arguments/v1`, with exact published case/artifact,
version, Pod identity and authenticated capture interval. Metadata recordings
cannot supply arguments. A new source/display definition and dedicated raw
query read purpose must not widen `ReadApproved`, syscall metadata projections
or raw-summary rights.

Preserve the existing schema's bounded selectors: up to 64 qualified syscall
names, `errors_only`, a source-bound cursor and requested limit 1–100. There is
no query language, regular expression, argument-content predicate, path lookup
or new parser. Add the existing query-ledger idempotency-key contract to this
currently unimplemented public tool before behavior, with canonical/browser
parity. A cursor selects the next page; it is not authority or an idempotency
key. Normalize names before binding the selection and key digest.

Return the existing closed raw-event shape: process/thread/Pod references,
syscall name and ABI, recorded timestamp, optional paired duration and errno,
outcome, and up to six `{name, value, truncated}` arguments. Copy only validated
recorded values. Scalars retain their `decimal:` representation, captured
bytes their reversible `base64:` representation, and a failed memory read
`unavailable:fault`. A successful empty buffer differs from a failed read.
Do not format pointers, decode arbitrary bytes as trusted text, infer missing
values or change acquisition truncation flags. UI renders values as untrusted
text; it never executes or follows argument contents.

The public schema allows values up to 4096 characters, but the current native
verifier is stricter: 8192-byte event-line bound, closed definitions and at most
128 decoded bytes in a captured memory value. Schema ceilings do not authorize
larger recorded values or expanded acquisition. Preserve recorded coverage,
faults, unmatched/unfinished calls and explicitly unknown loss; filtering does
not turn the saved file into complete workload coverage.

The current remote recording source is at most 8 MiB. Bound line/record counts,
logical selection work and total full-read work independently. Stop retaining
rows at the requested or encoded-page limit, but validate/authenticate the
entire original and canonical footer before returning any page. Continuation
starts at the first omitted matching event; never split an event or silently
trim an argument to fit. A valid event that cannot fit the admitted response
must produce an actionable bounded refusal, not an empty successful page or a
nonadvancing cursor. Prove whether that case is reachable under current native
bounds. Cancellation, bad tail or source failure produces no page and joins the
existing owner/worker cleanup.

Use the existing 24 KiB public envelope ceiling. Reserve sufficient space for
both direct and nested `get_query_result` envelopes, provenance, coverage,
warnings, times and cursor; the packet query's 4096-byte reserve is a candidate
to verify against actual maximal syscall envelopes, not inherited proof.
Keep inner truncation/narrowing and outer query-result semantics consistent.

## Exact grant, replay and charge

Every argument query requires current `evidence:raw`, current ordinary/retained
artifact rights and an exact `syscall_query` parent/child for the original
human and selected client. This applies even when no argument matches the
filter. A collection grant, metadata share, metadata-only event query or
`download_artifact`/`pcap_query` operation cannot cover it. No raw-share fallback
is added; broader raw sharing remains separately scoped.

Extend standalone review and same-human combined result access using the
existing protected-output association and finite shared parent pool. Resolve
omitted requested client IDs once to the authenticated client before review
digest creation. Preserve explicit selected clients, exact original output
scope and expiry through approval retries. Query-only bytes fund bounded
disclosure; a combined download operation retains verified whole-file coverage.
Do not duplicate the pool or treat acquisition observation credit as query
funding.

Initial C3 authorization reuses exact idempotent child materialization before
immutable query construction. Current/poll checks read that same child rather
than materialize another one. Bind original parent/child, source, normalized
selection and caller/client key in the existing query ledger. Resolve same-key
replay before another admission, read or charge; return only the same original
pending handle/deadline, even if its original first call returned a page.
Changed input, grant or client cannot reuse that key or select a successor.

Reuse the existing atomic paid-read transaction and grant-use journal. A real
raw batch reserves one operation and the worst-case bounded page bytes, with
use ID equal to its batch ID. Replay validates operation as well as original
parent/child/bytes/count. A distinct actual batch pays again; no refund follows
failure or unknown completion. Query-unit allowance and batch count need typed
agreement and qualification before behavior; packet-query four units/two
batches are available conservative candidates, not measured syscall costs.
Acquisition grants and prepaid observation spend remain unchanged.

Retain current identity, client, original audience, deny, retention, recovery,
worker/source/grant deadlines and all post-blocking/final-delivery checks.
SQL, audit and logs contain bounded control selection/identities, never
argument rows, payload values or secrets. The hub receives only the authorized
page, never the native original or unwrap keys.

## Cost and qualification

No new acquisition, service, dependency, parser language, Kubernetes API call,
permission name, watch, PVC or background task. Reuse one query worker and
three scoped data/index/manifest key roles per actual read; normal query SQL,
audit and grant checks remain nonzero. Added exposure is the explicitly
approved raw argument page. Use existing states and conservative uncertainty;
add no fallback or tuning switch. At N simultaneous queries the existing worker
pools bound N reservations; no new concurrency coordinator.

Implementation must cover metadata/raw isolation, exact review and shared
pool accounting, stable replay, full authenticated EOF, hostile source/output
bounds, maximum encoded direct/nested pages, cancellation and joined cleanup.
Measure new parser/output shapes in the actual encrypted worker composition.
Then use real compiled-role services/upgrade checks and a fresh
`continuation-manual-arguments` installed workflow with MCP, actual React and
same-original native JSONL parity. Preserve fixed summaries/events and their
argument-marker exclusion. The earlier argument Go test passed in 919.995
seconds but its outer workflow was cancelled; it is partial reused evidence,
not a successful full workflow or qualification of this raw query.

The typed domain/decoder/encrypted-reader/C3/SQL/C20 and console paths now have
component implementations. The configured accounting choice is four units,
at most two batches and 24 KiB/one operation per actual raw read. The private
page ceiling is 20 KiB with a 4096-byte public-envelope reserve. An actual C20
maximal encoded fixture retained seven whole events: private 20,349 bytes,
direct 21,223 and nested 21,890, preserving the first omitted cursor. That is a
hostile structured-output fixture, not native acquisition or resource proof.
An actual workspace/approval/projection HTTP-client unit journey passes through
Pending→Approved before querying the same selected source; transport replies
are synthetic. Component checks do not establish installed operation.

The SQL/upgrade evidence
and encrypted-reader resource evidence
now pass their separate scopes. SQL paid loops use synthetic crypto/join proofs;
the resource component runs the actual encrypted reader/parser. Neither proves
the full installed composition. The new installed fixture retains all five fixed
views, Repeat and Stop and adds MCP/React raw queries against the same native
original. A rolling two-slot test pipeline retains original worker lifetimes;
its advancing-clock model is not a measured installed speedup.

No installed pass, complete S-05 exit, all-maxima coverage or release follows.
