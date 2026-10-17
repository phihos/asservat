# ADR139 frozen handoff

The fourteen-path payload adds closed same-NativePort context-start dispatch, cancellation-first joined owner shutdown, and actual-service qualification fixtures. No migration, public runtime enablement, provider producer, installed regional command or general dispatch framework is added.

## Scope and contracts

- `native.Serve` remains the ordinary native entry point. `ServeWithContextStart` accepts exactly the existing native handler and fixed context-start handler, with original accepted-time native ten-second / context thirty-second bounds, a shared two-second TLS/header prelude, independent purpose reservations and one conversation per socket. Certificate/proof expiry only shortens bounds. Cancellation reaches non-I/O work; reservations remain charged until handlers join.
- The raw pre-TLS ceiling is shared (sum of configured purpose slots, at most sixty-four). Unclassified connections may temporarily occupy that global capacity until their original two-second bound. Separate purpose reservations prevent admitted context conversations from consuming native reservations; they do not promise pre-TLS fairness under an unclassified connection flood.
- `OwnerNativeRuntimeConfig.ContextStarts` is optional protected typed composition. The same Router pointer belongs to the public request bridge and private ingress; successful runtime composition owns its closure. Missing mounted producer remains explicit. Absence keeps ordinary native Serve behavior.
- Runtime shutdown cancels work, removes readiness, disables retained keys and closes listeners before joining every started child. The old six-second return while work remained blocked is removed; forced process termination remains distinct from successful joined cleanup.
- Owner SQL enumeration and signed first/continuation fixtures compose real existing adapters. The context wire has no object receipts: the fixture reads the exact stored execution receipts using its existing read role for independent verification.

## Verification and evidence

See CHECKS.md and logs. The deterministic blocked-child regression failed before the product correction. Corrected bootstrap selected races passed. Corrected native listener races passed (13.585s), integration source compiled, affected three-package vet passed, and four pure selector tests passed. First failed H2 fixture evidence is preserved; its correction only narrows a test frame context. No external lab was run independently. Integrated repository gates and actual service selections below remain parent-owned and unrun for this payload.

## Exact native selections

1. Owned custody/fleet environment using `^TestContextStartOwnersWithRealServices$` (actual separate SQL role/encrypted object fixture).
2. `python scripts/test-context-storage.py --regional-context-start first`.
3. `python scripts/test-context-storage.py --regional-context-start continuation`.

The latter modes own ordinary two-cluster context fixtures, reject --run and installation mode combinations, clear inherited fixture flags and require their own exact `native-regional-api-first` or `native-regional-api-continuation` PASS. A default/direct API-runner PASS cannot satisfy them. No service run is claimed here.

## Fixture boundaries and remaining risks

The SQL fixture uses separate source, enrollment, audit, activation, current-read and cleanup credentials with encrypted S3 records. Initial fleet recovery, issuer and native protection roots remain synthetic. It checks missing/unactivated/client/retired exclusion, seventeen-candidate overflow, read-role write denial and original-deadline failure behind an actually observed blocking row.

The signed exchange fixture uses actual ServeWithContextStart, SQL52 capture/pair admission and publication, Pod-bound API reads/local start, encrypted storage, separate publication and native exact-byte verification. Human, owner route/protection, connector process/source/registry and work-signing roots remain explicitly synthetic. Fixture-process API checks do not attest physical execution inside the referenced Pod. All synthetic backing/configuration precedes Preview/admission.

First request and explicit fresh same-key continuation preserve original capture/pair bounds; passive replay creates nothing and a canceled original caller cannot be reused. Native same-request timing and per-frame API-check amplification remain unqualified. The production connector proof-reuse native timing selector is separate, parent-owned work. Protected signing/trust/input provisioning, installed regional startup and public production startup remain pending. No collection enablement follows from this package.

## Integration

`manifest.json` lists exact base and payload hashes; `dependencies.json` records the non-payload current code/contracts/migrations/fixture inputs. `changes.patch` is reviewable; apply only after checking hashes. Seven modified paths and seven new paths are included. The refreshed harness base preserves parent's registry image identity and finally-path hash accounting changes. No shared progress, catalog or decision-index files are included; add ADR139's index at parent integration.

Frozen sources are immutable. Follow-up corrections must use a separate stage and the then-current integrated base.
