# ADR118 retained private state and historical installation result

Frozen checkpoint from the initial preparation continuation. No live edits, module changes, migrations, schema-head changes, public transports, shared indexes or chart changes.

## Scope and contracts

- One closed private material DTO/schema holds the installation/request IDs and three independently random SQL password values. It has redacted formatting and no authority interval. The existing ADR100 password generator and role-name rules are reused. Exact original accepted timestamps reconstruct the existing credential-state bytes; expired original state remains decodable for cleanup. This codec does not accept or persist an interval itself.
- The concrete Kubernetes reader consumes an independently pinned immutable Secret in the original bootstrap namespace. It requires the current installation administrator, original staging/continuity protection, original root, exact UID and content. There is no CREATE, adoption, generation fallback or password rotation. The first five-second deadline survives the final check.
- C04 has an exact-scope historical result port with MissingObservation, Prepared, Audited and ActivatedHistorical. The distinct PostgreSQL reader uses one SELECT, validates original scope/plan/claim ID/receipt/timestamps and preserves the first current operator deadline after all reads. It requires a separately supplied SELECT-only pool. It does not mutate, grant activation, prove no effect, clear current recovery, or prove retired writers.
- The concrete current Kubernetes history authority uses the original immutable input UID/digest and exact native administrator/workload protection. It works after the original activation Pod terminates; it does not read the Pod or private credential material. Complete witness/account/cluster scope remains bound.

## Paths and integration

`manifest.json` records every base/new hash. Sixteen paths are included; thirteen are Go files. Three existing test paths use guarded changes: initial_credentials_test.go, initial_installation_test.go and initial_installer_pod_test.go. All three base hashes matched live at packaging. The SQL fixture provisions its own distinct synthetic SELECT-only role; runtime-roles.sql is unchanged. No test credential is production authority.

The native valid initial-installer Pod scenario adds one call after the actual binary exits successfully: independently reconstruct current native read protection, open a separate SELECT-only fixture credential and read the original successful record. The old process need not be running. Existing real-service tests additionally cover every disposition, later RecoveryBlocked remaining unchanged, mutation SQLSTATE42501, current denial, final-check expiry, and an actually observed blocked SQL read that crosses the original deadline.

## Measured checks

Command (from live root, with source overlay only):

```
TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -race -p 2 \
  -overlay=/home/phil/.cache/asservat-build/planning/initial-preparation-continuation-20261011/overlay.json \
  ./internal/adapters/kubernetes ./internal/adapters/postgres \
  ./internal/application/fleet ./internal/contracts ./test/integration \
  -run 'TestInitialSQLMaterial|TestInitialInstallationHistoricalObservation|TestInitialCredentialStateNativeGuardAndUncertainCreate|TestInitialInstallationWithRealServices' -count=1
```

Terminal 0: Kubernetes 9.610s, PostgreSQL 1.035s, fleet/contracts compilation, integration 1.059s. The external integration test skipped without its fixture. `qualification.log` preserves the output. `qualification-first.log` is a command-shape error (`-p2` instead of `-p 2`) before package testing; it is not a test result.

The private schema passed Draft202012 validation and canonical base64url/UUID negatives using `/home/phil/.cache/asservat-build/spec-venv/bin/python`, with FormatChecker and local canonical references; see schema.log. The ambient Python lacks jsonschema; no package was installed and format validation was not omitted.

No native fixture, full repository gate or standalone vet campaign was run by this agent. Parent qualification should run the existing owned initial-installation suite and the existing exact native initial-installer context selection with ASSERVAT_INITIAL_INSTALLATION_NATIVE=1. The new SQL deadline checks add approximately 0.4s intentional waiting, not a changed authority deadline.

## Remaining implementation and limits

This is an implementing checkpoint, not a completed installer. Production initial private-state persistence, public one-use interval binding, gated Pod/final inputs, exact guard handover, provider provisioning/retirement and command supervisor composition remain required. The history reader's purpose-specific SQL role producer is not supplied by the fixture. Its setup probe remains a prerequisite: after that account's permission/token retirement, RBAC denial cannot substitute for native guard enforcement. A protected post-retirement status/handover composition is still needed.

A missing SQL row, terminated Pod or historical success is never proof of no effect or current activation authority. Pre-witness retry requires a separate positively fenced cancellation/pristine protocol; claimed or uncertain work must reconcile the original attempt. Original five-minute claim and fifteen-minute SQL credential intervals never renew. The private material binding codec must only be called with the retained accepted interval; arbitrary caller timestamps are not acceptance. No deterministic password/key generation or provider-output reconstruction is introduced.

The next concrete producer step is a durable public binding of the known private Secret UID, original full startup digest and original fifteen-minute interval, followed by typed gated Pod/final-input/handover effects. Keep it separate from provider-generated output reconciliation and preserve all original pins and occupied keys.
