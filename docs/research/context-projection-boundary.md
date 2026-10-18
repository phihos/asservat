# Approved context query audit and response components

This ADR-206 component adds canonical query timing, the C-08 query audit names
and purpose-separated input MAC, C-20 owned response cleanup and the concrete
invocation/delivery bridge to the C-18 coordinator. It does not
register public tools, install query SQL/provider credentials, implement the
browser projection view or qualify an installed query journey.

## Contracts

`get_file_excerpt` and `get_query_result` successful/pending data carry
`query_observed_at` and `query_expires_at`; errors are unchanged. The browser
OpenAPI components match the MCP catalog. The canonical result-poll tool remains
capable of other specified original tools. The current runtime schema bundle
accepts only the fixed pod-status excerpt and validates the nested original
result, equal request IDs/timing, and the sixty-second maximum interval.
Schema availability alone does not add an application route.

Both names use the existing normal audit lane and `context-query-input/v1` MAC
domain. Canonical normalization includes the exact selection/defaults, original
tool and fixed display version. A handle remains keyed audit input, never
evidence or a permit. Private effect dispositions distinguish acknowledged spend,
proven pre-dispatch rejection and uncertainty; a prepared pending reply is a
successful bounded response rather than proof of no effects.

The private reply owner requires an application guard and exact outcome
association callback. Its original context and audit slot survive the audit
wrapper returning; copies of the reply share one cleanup owner. The final
browser/MCP send checks disclosure after serialization, binds cancellation to
the actual socket, checks short writes and flushes. Cleanup uses the original
finite cleanup cutoff capped by the audit invocation's thirty-second allowance,
not an expired public request deadline. Failed or expired cleanup remains an
error and cannot stand in for joined remote completion.

`ContextProjectionOperations` is an inert adapter with separate initial-admission
and result consumer ports, both returning the concrete C-18 delivery. It has no
tool discovery or unaudited `Call` method and is absent from the existing public
composition. Its private invocation comes from the existing wrapper only after
`Begin`; typed selections and poll handles must match the original normalized
input MAC before any effects. The adapter binds the exact C-18 pointer and
immutable timing/result to validated canonical bytes, and records the existing
keyed output digest only after `Finish`. No second auditor or public guard
constructor exists. A rejected final guard or canceled request closes locally
under the original prepaid cleanup cutoff; uncertain private closure cannot
complete the SQL batch. Pending polling carries accepted control spend and has
no worker-admission capability.

The bridge also carries the C-18 owner's read-only cancellation signal into the
actual browser/MCP write context. A shorter application lease can cancel a
blocked socket while the original HTTP request remains live. The single
reply-owned watcher and write deadline callbacks are joined before cleanup/slot
release. A shorter lease discovered by the final guard rejects that prepared
response; it never leaves the transport using the previously longer bound.

Protected provider/SQL composition and the browser managed-view timer remain
subsequent work. Poll/control/history remain explicitly budgeted profile
dimensions, independently of the two read-batch limit.

## Verification on 2026-10-18

The original regression command selected both new tests and exited 1 before
implementation: the audit and runtime schema validators rejected
`get_file_excerpt`. A later focused run found the additional closed MAC-domain
allowlist before any intent dispatch; that exact format was added with a
purpose-separation regression.

The final affected race evidence covers 218 top-level tests and 843 named passes:

| Package | Top-level tests | Named passes |
| --- | ---: | ---: |
| application/audit | 37 | 78 |
| domain/audit | 26 | 186 |
| contracts | 44 | 206 |
| transport/presentation | 52 | 104 |
| transport/browser | 33 | 173 |
| transport/mcp | 26 | 96 |

Commands used `GOMAXPROCS=2`, `GOFLAGS=-p=2`, and the explicit build-cache
`TMPDIR`/`GOTMPDIR`:

```sh
go test -json -race -count=1 ./internal/application/audit ./internal/domain/audit ./internal/contracts ./internal/transport/presentation ./internal/transport/mcp ./internal/transport/browser
go test -json -race -count=1 ./internal/transport/mcp ./internal/transport/browser
go vet ./internal/application/audit ./internal/domain/audit ./internal/contracts ./internal/transport/presentation ./internal/transport/mcp ./internal/transport/browser
make spec-check architecture-check go-architecture-check openapi-check investigation-schema-check
```

The first race command passed the four audit/contracts/presentation packages but
exited 1: existing browser/MCP deadline tests detected the new send helper plus
the old handler both setting the final socket deadline. The redundant handler
setters were removed; the complete two-package transport rerun exited 0 with
the original assertions unchanged. Vet and all listed design/schema gates
exited 0. The spec checks used the existing `requirements-spec.txt` environment
with format validation.

Logs and the per-package result index are retained at
`~/.cache/asservat-build/context-projection-boundary/` (`race.jsonl`,
`transport-race.jsonl`, `vet.log`, `design-gates.log`, `result.json`). These are
component checks with synthetic application/audit fixtures, not real SQL/S3,
installed worker or end-user disclosure qualification.

## Concrete bridge verification

The follow-up bridge uses the actual C-18 coordinator with synthetic authority,
ledger, reader and audit ports. The tests cover ready and pending initial/poll
responses, original normalized input and principal/client lineage, exact output
pointer acknowledgement, request cancellation/expiry, later retention/permission
denial, unknown admission and uncertain cleanup. The only fixture human scope is
`evidence:read`. A paid poll never calls worker admission; a successful read stays
active until the same reply owner joins close.

```sh
go test -json ./internal/transport/presentation -run '^TestContextProjectionBridge' -count=1
go test -json -race ./internal/transport/presentation ./internal/transport/browser ./internal/transport/mcp ./internal/application/analysis -count=1
go vet ./internal/transport/presentation ./internal/transport/browser ./internal/transport/mcp ./internal/application/analysis
make spec-check architecture-check go-architecture-check
```

These commands exited 0. The final race run selected 134 top-level tests and
428 named passes:

| Package | Top-level tests | Named passes |
| --- | ---: | ---: |
| transport/presentation | 60 | 125 |
| transport/browser | 33 | 173 |
| transport/mcp | 26 | 96 |
| application/analysis | 15 | 34 |

Evidence is in the same cache directory under `bridge-focused.jsonl`,
`bridge-final-race.jsonl`, `bridge-final-vet.log`, `bridge-design-gates.log` and
`bridge-final-go-architecture.log`. The initial focused and two-package race
runs preceded the final live-owner/write link. The final four-package run
includes that link, rejection of a newly shorter lease and poll-input
substitution. A separate regression experiment omitted only the live-owner
cancellation propagation: the selected blocked-write test exited 1 with
`owner cancellation did not reach socket`. The exact tested source was restored
and its hash verified; this experiment is recorded in
`bridge-missing-lifetime-regression.jsonl` and its adjacent JSON report. It is
not a separate passing qualification.

These results qualify the component handoff only and do not establish native
SQL writer acknowledgement, worker enforcement or public query availability.
