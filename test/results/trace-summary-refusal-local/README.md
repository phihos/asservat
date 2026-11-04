# Known profile-summary refusal before admission

Installed trace41863096785 captured and published a trace, then received503 for
its unsupported pprof-summary request. The current native-source reader correctly
refuses Go traces; the C18 nil delivery previously became a transport failure.
Signed ede71f3f (integrated43439e44) adds a private marker only at summary authority
resolution before any admission. C20 emits one audited, content-free NotAvailable
for access/missing/unsupported/provider failures at that point. This intentionally
includes unavailable providers before admission. Unknown/nonclassified and
attempted/post-admission failures retain transport errors. Audit, final current
identity, original deadlines and cancellation still gate every response. There
is no SQL allowlist, parser, worker, resource or timeout change.

A composed real C3/C18/audited-C20 regression over synthetic publication and
permission ports reproduces the old authority/catalog503 with one catalog read
and zero admissions/workers (exit1/0.316s). The new matrix passes4.557s and covers
identical denied/missing/provider bodies, no effects, audit failure, cancellation,
final group/deadline changes and post-admission uncertainty. Affected races pass
1.054s/95.325s; pure trace fixture checks pass0.098s, specification/architecture
checks pass. Independent readback review found no blockers. Existing owner
failure diagnostics now cover manual heap/trace without happy-path I/O.

Exact commands, actual exits and source attribution are retained in the handoff.
All eight integrated source files match the signed source hashes. Every original
payload is deterministic gzip with byte-exact readback. Installed trace/native
qualification remains pending; this local proof is not an installed pass.
