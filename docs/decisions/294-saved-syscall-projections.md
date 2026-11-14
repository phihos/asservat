# ADR-294 — Fixed saved-syscall projections

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

Date: 2026-11-03. Status: implemented; owned metadata/argument saved-view fixtures qualified.
The argument Go test passed; its outer workflow was cancelled at the job limit.
Broader query/kernel qualification remains open; see implementation progress.
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

## Integrated component checkpoint

The fixed extractor now handles metadata and argument sources, with canonical
manifest validation and full native authentication before either result or a
cursor refusal. Regional startup and optional public composition retain the
existing worker. SQL132 extends the closed scope/audit/tool mappings and spends
two existing query units, one read batch and three one-use key slots. Both
physical and declared transient worker memory must be at least 256 MiB. No
service, watch, background task, Job type, credential, privilege or configuration
is added.

Local isolated consumers of approximately 8 MiB encrypted sources measured
65,952–74,608 KiB peak process RSS (64.4–72.9 MiB) and
0.489–0.621 seconds for repeated metadata, distinct metadata and arguments across
both views. The exact report and binary digest are retained under
`test/results/syscall-projections-local/`. This includes framed cryptography,
canonical native validation, TLS object ranges and exactly three synthetic
unwraps. It does not measure real SQL/KMS, CPU-limited deployed workers or
installed end-to-end latency. A later fixed-page provenance check was added
after that measured binary; final-source qualification remains required.

Two units cover one native frame/index read plus another full 4 MiB context
allowance for commit/manifest work (less than the reserved 16 MiB). Each filtered
page pays for the entire source. The maximal comparable filter adds 24,695 bytes
of escaped JSON to the prior 16 KiB key child: the purpose-specific ceiling is
48 KiB for syscall scopes, retaining 16 KiB elsewhere. It fits existing query
row/backing bounds and adds no key slots. SQL upgrade/rollback parity passed against real PostgreSQL (Go 4.598s),
including canonical JSONB size, exact previous function restoration and unchanged
trust. Initial-schema handover passed in 146.989s; both owned fixtures report
unchanged sources and complete cleanup. These are component/installation-schema
checks; installed syscall workflows remain pending.

Public results preserve recorded unmatched, unfinished and unknown counts.
Acquisition loss and truncation are nullable unknown values where these stored
formats cannot establish them. Public and private envelopes are byte-bounded;
public trimming retains a prefix with a cursor at the first omitted item. The
temporary rows are cleared only after serialization. Empty filtered pages keep
`[]`, full-source counters and unknown coverage. Browser/MCP response lifetime
and exact invocation association remain in the shared query owner.
