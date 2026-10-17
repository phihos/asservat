# ADR133: positive managed setup-copy closure

Frozen payload: `manifest.json` (30 paths: 18 replacements, 12 new), `adr133.patch`, `dependencies.json` (11 unchanged dependencies). Apply only after each original/payload hash matches. Evidence helpers, overlays, reports and local package notes are not repository payload. The current decisions index includes the parent's ADR134 addition.

## Result and contract

Fresh installations automatically select internal bootstrap v3. Retained v2/v3 metadata selects only its original exact version. Complete protected pre-seed retries retain their original pins and native proof; partial or contradictory states cannot select a new format. Old v1/v2 policy, binding and probe-role wire bytes remain unchanged. No operator format selector is added.

After original complete handover, independently scoped activation history and positive original manager retirement, the product joins its manager pool and persists one fifteen-minute copy-closure claim. Its two-minute attempts and five-second observations do not renew that claim. Each fixed tombstone CREATE requires an acknowledged first claim; unknown replies permit exact lookup only. Both guards are checked before every closure effect and replay.

Kubernetes VAP does not evaluate VAP/binding mutations. The original trusted installation administrator and RBAC retain those objects; this is not resistance to administrator/cluster-admin sabotage. Missing/replaced identity/content denies without recreation/adoption. The native fixture checks actual probe RBAC and detects actual administrator binding removal after completed replay. The original v3 guard is never replaced by the product.

Each immutable SQL/provider copy is marked under its exact UID/RV, that mark is retained before DELETE, and positive exact absence is recorded under current guard proof. One final CAS replaces broad seed data with `retired:true` and makes it immutable. Completed producer/retire replay reads metadata/history only. First manager retirement still uses original bounded setup material after independent completed-history classification. A concurrent already-retired observation cannot skip owed v3 copy closure.

Only the trusted installer fixture account gains PATCH on the three exact existing seed/SQL/provider Secret names. Probe/runtime privileges do not broaden. No SQL migration, public route, Helm enablement or placeholder runtime is included. Removal covers managed API copies; operator originals, upstream credentials, Go heap and etcd/backup erasure are not claimed.

## Verification and actual outcomes

All Go commands used `GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp` from the live repository with the isolated Go overlay; no live files changed.

- 57845 exit0: initial router regressions, `evidence/first-router.log`.
- 6754 exit1: an owned SIGQUIT diagnostic ended a blocked httptest teardown. The mock PATCH handler had not consumed its body; this is not a normal timeout verdict or a product cancellation failure. Stack preserved in `evidence/bootstrap-race-first.log`. The mock now consumes its bounded body and has explicit joined release.
- 20824 exit0: corrected Copy/V3 races and fixture compilation, `evidence/copy-race-second.log`.
- 73107 exit0: final `go test -race -overlay=<stage>/legacy-overlay.json ./internal/adapters/kubernetes ./internal/bootstrap ./internal/contracts ./test/integration -run '^TestInitialBootstrap(Copy|V3|Router)' -count=1 -timeout=90s -v`. Kubernetes16.103s; other three packages compiled with no selected tests. Log `evidence/copy-final-race.log`.
- The evidence-only `TestInitialBootstrapV3LegacyFullWireCompatibility` compares complete JSON with reference functions extracted from the retained original builder: v1 policy8,852 bytes, v2 policy11,887 bytes; both binding352 and Role394 bytes match exactly. The helper is outside the payload. This is byte compatibility evidence, not real API enforcement.
- 43655 exit0: `go vet -overlay=<stage>/overlay.json` on those four affected packages. `evidence/copy-final-vet.log`.
- 6566 exit1: first staged spec check reported a new-document link missing because the isolated path overlay did not normalize `../`. Corrected only that local helper; no links/requirements were weakened.
- 47218 exit0: `check-source-overlay.py check-specs.py`, 85 schemas,49 MCP tools,173 examples,176 requirements/scenarios,11 tasks,3028 links,608 rejected invalid examples /9899 assertions. `evidence/copy-final-spec-second.log`.
- 79019 exit0: staged Go architecture (51 packages/269 edges) and design architecture (1202 positive/120 invalid checks). Respective `evidence/copy-final-check-*.log` files.

Tests cover original state/date/UID/RV/receipt sequencing, immutable sanitization CAS, cancellation, lost claim response with zero CREATE and no renewed claim, no broad Secret fallback, exact pre-seed version routing and occupied/unknown names. The first SIGQUIT log is a fixture diagnostic; no failing-before product regression is being invented for the entirely new closure capability.

## Parent-owned next qualification

UNRUN for this payload:

```sh
/home/phil/.cache/asservat-build/spec-venv/bin/python scripts/test-context-storage.py --initial-bootstrap-chain
```

This selector creates an owned empty database and runs `TestInitialBootstrapChainWithRealServices`: the exact compiled product image, original activation Pod and four fixed commands. The new fixture starts an exact seed watch before execution, retains only the actual manager-retired fields needed for assertions, verifies original manager login denial, both copy absences, same immutable seed UID, exact guard denial, and fresh setup/provider-file-free replay. A missing watch event fails instead of manufacturing completion from sanitized final state. Actual Secret/CEL shape, PartialObjectMetadata PATCH negotiation, additive policy enforcement and complete v3 timing require this native run. The previous parent's native chain result is v2 evidence only.

Remaining qualified-recovery gaps are partial unprotected pre-seed state, expired original cleanup and a lost original tombstone CREATE with no visible object. No new interval/recreation is inferred. Helm packaging remains the next independent source/design task under reserved ADR137; it must wait for this native prerequisite before any enablement claim.
