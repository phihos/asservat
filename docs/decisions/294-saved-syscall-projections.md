# ADR-294 — Fixed saved-syscall projections

Date: 2026-11-03. Status: implementation in progress; public query and installed qualification pending.
Requirements: REQ-SYS-003, SC-SYS-003, REQ-INV-002.

## Decision

Implement `get_syscall_summary` and `get_syscall_events` through the existing
approved-query coordinator and bounded regional Go worker. Both return extracts.
A summary reports counts, errors, paired counts and duration totals; event pages
contain only the existing fixed metadata event fields. They never select paths,
arguments, buffers or pointer values, execute expressions, or start collection.
The event filter changes display only; it does not reduce source read work or
retroactively change observation authority.

Bind the exact native source, display version, view, normalized filter, page
selection and original identities in admission, audit, worker and result scope.
Continuation binds case/artifact/version/view/filter; page size may change. Use a
comparable fixed-capacity filter value in accepted scope, retaining exact scope
equality and omitting the entire new field for legacy scopes. Preserve original
source, caller, query, retention, recovery and identity deadlines after blocking
work. Existing current permission and retained-audience checks precede evidence.

Metadata source reads use ordinary `ReadApproved`. A stored syscall-argument
source uses the separate internal `ReadSyscallProjection` operation, confined to
that raw native type and these fixed approved views. It conveys neither native
raw download nor `syscall_query` authority. The pprof exception does not authorize
it. Source class remains raw for processing/placement; output is extract. No raw
share fallback is introduced. Raw arguments remain regional and encrypted in
managed storage; the hub receives only the bounded result.

Reuse the current query ledger, processing quotas, audit, key slots, authenticated
native stream, cancellation and delivery owner. Consume and validate the complete
bounded native source before returning an aggregate or page, and independently
confirm final authentication in the source owner. Event pages keep a byte-bounded
prefix and continue at its first omitted matching record. Malformed tails or
incomplete reads return no successful prefix. Counters preserve unmatched,
unfinished and unknown records separately. Missing acquisition loss counters
remain unknown; a quiet or filtered result cannot prove complete observation.

## Cost and qualification

1. Benefit: two explicitly required saved-artifact operations are currently absent.
2. Accepted constraints: bounded Go analyzers in the regional worker; no new human
   approval for an already approved metadata projection.
3. Typical path: saved syscall investigation, including argument traces.
4. Precedent: reuse this repository's installed profile-summary and HTTP-page
   pipeline; no novel execution mechanism.
5. Fixed metadata inspection of raw syscall artifacts is a distinct internal
   read capability under existing ordinary rights and retained audience; it does
   not confer raw disclosure. Added services, Jobs, storage, credentials, RBAC
   and network exposure: all zero.
6. Added fallback or degraded states: zero; existing unavailable/invalid-cursor
   results apply. Two views are separate typed selections.
7. New machinery-only configuration: none.
8. External dependencies: existing SQL/KMS/object-store/worker composition only;
   no new package, provider or public service.
9. Each charged page scans at most the existing recording native-byte ceiling.
   There are no new watches or background loops. Parsing, framing, key and source
   read costs must be measured together before selecting worker funding; local
   CPU/allocation benchmarks alone do not qualify it.
10. Preserve legacy scope encoding; extend the existing closed SQL validators and
    audit tool mapping. Rollback must refuse retained new query scopes.
11. A parser or raw-download link alone does not satisfy summary/events or the
    synthetic-credential non-disclosure scenario; complete both public workflows.

Prepared components are not enabled routes. Remaining work includes funded scope
and SQL admission, raw-source extraction, key/worker/result composition, browser/
MCP/console parity, service fixtures and native comparison with downloaded JSONL.
The existing collector reports quiet metadata captures as failures without
artifacts; quiet-success acquisition remains a separate limitation.
