# Approved context query audit and response components

This ADR-206 component adds canonical query timing, the C-08 query audit names
and purpose-separated input MAC, and C-20 owned response cleanup. It does not
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
proven no-effect observation and uncertainty; a prepared pending reply is a
successful bounded response rather than proof of no effects.

The private reply owner requires an application guard and exact outcome
association callback. Its original context and audit slot survive the audit
wrapper returning; copies of the reply share one cleanup owner. The final
browser/MCP send checks disclosure after serialization, binds cancellation to
the actual socket, checks short writes and flushes. Cleanup uses the original
finite cleanup cutoff capped by the audit invocation's thirty-second allowance,
not an expired public request deadline. Failed or expired cleanup remains an
error and cannot stand in for joined remote completion.

The concrete C-18 invocation/delivery adapter, protected provider/SQL composition
and browser managed-view timer are subsequent work. The adapter must bind the
exact C-18 pointer and immutable timing/result to the canonical bytes before
acknowledging the existing C-08 outcome; no second auditor or public guard
constructor is introduced here. Poll/control/history remain explicitly budgeted
profile dimensions, independently of the two read-batch limit.

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
