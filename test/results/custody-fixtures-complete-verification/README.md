# Custody fixture rollback and connection qualification

## Result

Pass. The complete `TestContextAdmissionWithRealServices` run finished in 877.834 s with `sourceUnchangedDuringTest: true`, `buildScratchRemoved: true` and `cleanupFailures: []`.

- Rollback probes now recognize migration 145's retained 30-second API start bindings instead of stopping at older expected versions.
- Joined publication bursts release their idle pools. Shared parent, retention and recovery pools reset at the same boundaries. Fixture pools are capped at eight connections, without changing the 48-slot server or concurrent operations.
- Lifecycle cleanup, verification, finalizer and pending-writer pools reset before pending reads, absence acknowledgement, finalization and four-way history release.
- The API start fixture uses ADR-311's 30-second target/capability/process observations and refreshes the separate five-second permission observation immediately before preparation.
- The aggregate harness allows 1,050 seconds for full and targeted context runs; the actual passing run took 877.834 s.

The separate recording start case passed in 4.37 s (5.846 s package total), with unchanged sources and no cleanup failures. Full `make pre-push` also passed, including the affected integration suite and all 611 console tests.

No production source changed. These are fixture correctness and resource-budget fixes, not relaxed authorization, custody or product-deadline changes.

## Retained records

- [Complete context-admission run](context-admission.log)
- [Environment, source hashes and cleanup markers](environment.json)
- [Recording start run](recording.log)
- [Recording environment and cleanup markers](recording-environment.json)
