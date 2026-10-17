# Exact original managed-copy metadata correction

Frozen two-file source package. No live edits or native run. Original 30-file ADR133 package remains immutable.

## Defect and correction

The actual producer `bootstrapPrivateObject` retains `asservat.io/installation-id` and `asservat.io/preparation-request` on each SQL/provider material Secret. `copyMetadata` rejected those required fields as unknown, so it could not inspect either original copy before cleanup admission. The native first chain failed at retirement with `cfg.ErrChanged`; its PostgreSQL log records actual original-manager login rejection. Source-level before regression independently reproduces the deterministic copy rejection.

Every copy metadata read now receives the already-retained closure claim, verifies its exact installation/request values and keeps the closed annotation list. Copy refs must equal one of that claim's two original refs. All UID/RV/desired-digest/mark/cancellation/PartialObjectMetadata checks remain. No annotation merely being present authorizes cleanup; original handover, independent history, positive manager retirement and guard checks are unchanged. No broad Secret read was added.

The new test uses the actual private-object producer and its CREATE annotations. Both SQL/provider copies pass first marking and resumed existing-mark recovery after correction. Missing/wrong installation, missing/wrong request, arbitrary extra annotations and wrong closure marks deny without effects. The test asserts original UID/RV retention, no broad private reads and no invented deletion receipt.

## Actual bounded checks

All ran from `/home/phil/Projekte/asservat` with `GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp`.

- Before: `go test -overlay=<stage>/before-overlay.json ./internal/adapters/kubernetes -run '^TestInitialBootstrapCopyProducerMetadataRemainsBoundDuringMarkRecovery$' -count=1 -timeout=45s -v`; handle36846 exit1, four original producer copy cases fail before writes; `evidence/before.log`.
- After: `go test -race -overlay=<stage>/overlay.json ./internal/adapters/kubernetes ./internal/bootstrap ./test/integration -run '^TestInitialBootstrap(Copy|V3)' -count=1 -timeout=90s -v`; handle97257 exit0, Kubernetes17.166s. Bootstrap/integration compiled with no selected test, not native qualification; `evidence/after-race.log`.
- `go vet -overlay=<stage>/overlay.json ./internal/adapters/kubernetes ./internal/bootstrap ./test/integration`; handle82376 exit0, `evidence/vet.log`.

Original native failure remains `test/results/bootstrap133-native-first*`: terminal1,0passes,1345 unchanged source hashes, cleanup[]. The next parent-owned actual chain is still required to qualify the remaining native copy guard/DELETE/sanitization sequence. This package changes no schema/spec/authority contract or public interface. Reapply only the two manifest paths after exact base/dependency checks; preserve parent progress/diagnostic changes.
