# ADR131 reserved policy variable correction

The actual Kubernetes guard fixture rejected the corrected match condition's policy because `namespace` is a reserved CEL identifier. This two-path follow-up removes the three now-unused `group`, `namespace`, and `name` variables. The used `sub` variable and every match/validation expression remain unchanged. The previous match-condition correction and its native fixture are not replaced.

Frozen manifest SHA256: `9ad772e9d580adfa4a8558d0767af99b530585fb3a46f8d677f094999f1c34a5`.
Frozen patch SHA256: `8fa9805f62ff41a5843448d206da733972bc43a701e2ee4b7d6bb3184c367df9`.
`manifest.json` records the two exact payload hashes and the original builder base hash.

## Actual local evidence

Checks used the live repository with the bounded sparse Go overlays, `GOMAXPROCS=2`, `-p 2`, and `TMPDIR=/home/phil/.cache/asservat-build/tmp`.

- Before: the new `TestInitialBootstrapAdmissionHasNoReservedCELVariable` failed, exit 1, with `namespace is a reserved CEL identifier`; `evidence/before.log`.
- After: the affected Kubernetes race selection passed, 1.141s. The combined integration compile then failed while the parent's two-file role-helper integration was incomplete (`connectorSQLRolePrefix` undefined). The original failed combined output is retained in `evidence/after-race.log`.
- After the parent confirmed the shared files were stable, the affected integration compile/recheck passed, exit 0, 0.012s; `evidence/integration-recheck.log`. External fixtures were not run by this command.
- Final Kubernetes and integration `go vet` with the same after overlay passed, exit 0; `evidence/vet.log` (empty successful output).

No build remains active. No live files were edited by this agent. The parent owns native qualification with the existing `^TestInitialBootstrapGuardWithRealKubernetes$` selector. Its prior failed run and source/cleanup evidence remain distinct from these passing local checks. No runtime or full bootstrap qualification is claimed by this patch.
