# Frozen SQL51 prepaid connector retirement

Thirty owned source paths are frozen in `changes/`, with exact original/payload hashes in `manifest.json`, retained original files in `bases/`, and `changes.patch`. This extends ADR-126 with immutable retirement tickets, original-cohort restriction, prepaid conversion and bounded cleanup. It enables no public route or installed runtime.

Manifest SHA256: `25131b02cf4957cb23a6dce5a2ae2722540bffeb6af9c335d83d264256c34f70`.
Patch SHA256: `57b8f82ee3b6a4eedca0087ff5d9c81ead1a191639b6a7cb8e4d757d4d3e91e9`.
Migration51 SHA256: `e35a4d4c2d60dc148b3fe6d4781c78eea26799e3e5f2ff18aec443a1e1639527`.

One ticket is reserved for each accepted profile; independently audited backing promotion atomically reserves the complete successor set. Normal admissions include the outstanding restrictive reservation. An old ticket never retires a newer cohort. Historical expiry uses current recovery and the private journal with the original actor as provenance; explicit retirement requires the distinct live retirement proof. Neither path fabricates current identity.

Restriction commits before audit. The exact business outcome is stored before encrypted outcome creation. Lost replies reuse original ticket/operation/dates; audit failure leaves the fence and uncertain charges. Acceptance/writer-reference closure alone cannot prove quiescence or release an admitted pair. Existing positive object/certificate/history verification remains mandatory. Ticket deletion starts only after original HistoryReleaseAt and exact positive dependency closure, within the original cleanup window; independently reserved source row/WAL backing remains through original RetainUntil.

## Required merge correction found after freeze

Independent review identified one shared MAC regression in the frozen payload: `OperationMAC.Digest` drops the existing `processing-result/v1` domain. Parent reproduced it with three existing privacy workflow tests (`test/results/connector51-processing-mac-before.log`) and owns the narrow additive integration correction plus privacy races. Preserve that existing domain and the existing `ProcessingAccount` documentation while adding `connector-retirement/v1`. The frozen source and its evidence remain immutable; do not apply the MAC replacement without this correction. The staged passing race selection did not include privacy.

## Verification

Final wrapper 61292 returned 0 with all 30 staged source hashes unchanged (`evidence/final-checks.json`):

- Pinned sqlc generation: exit0, 0.204s.
- Compile domain/audit, application/audit, application/fleet, PostgreSQL and integration source: exit0, 6.124s.
- Full affected four-package race: exit0, 7.626s (domain 1.011s, application/audit 1.098s, fleet 2.149s, PostgreSQL 1.258s).
- Vet those four packages plus integration: exit0, 1.380s.

Exact commands and logs are included. They used `GOMAXPROCS=2`, `GOFLAGS=-p=2`, and explicit build TMPDIR. No build is active.

`TestConnectorRetirementStoresExactBusinessOutcomeBeforeAudit` failed against the saved prior coordinator as intended (exit1: business outcome was not frozen before provider work). It passes in the final full race. Further tests cover lost successful commits, outcome retry without new spend, blocked work across shortened bounds, final recovery loss and expired unknown writers. The actual held SQL event-lock and real-time deletion-window regressions are compiled fixture source, not executed qualification.

Bounded independent review by workflow and parent found no new concrete service/Store/deletion blocker. It did not qualify PL/pgSQL, role attacks, full admission/cleanup concurrency, maximum footprint or provider behavior.

## Integration and next task

Follow `INTEGRATION.md`: parent must update shared schema head 51, permanent table inventory 88, compiled migration expectations and regenerate SQL. The staging overlay left the live 50 embedded bundle/head intact; its race pass is not integrated 51 schema qualification. The generated dependency files are excluded from the payload. Canonical schema, fixture grants, dependency hashes and additive52 audit merge instructions are explicit there.

First run the fast actual SQL/S3 selection and preserve existing49/50 regressions, then the opted-in real-time cleanup case with the parent's frozen harness. Qualify actual bundle/initial installation/recovery and affected repository gates after integration. No SQL51 external fixture has run. Protected source/Pod/backing-qualification and local issuer facts are explicitly synthetic even where SQL/S3 effects are real.

The real 30-second configured admission case is distinct from the unimplemented/unrun maximum A+1800 boundary gate. Full transaction/WAL/object/history backing measurements and 4096-cohort/five-second throughput remain unqualified. Type-valid arithmetic supplies no performance claim.

Finite profile/source/root teardown, complete protected production provisioning and installed connector supervision remain pending. Last-cluster removal must leave the ordinary root reusable; permanent minimization belongs to explicit installation teardown and retains its inert installation fence. No complete lifecycle or public-runtime enablement is claimed.
