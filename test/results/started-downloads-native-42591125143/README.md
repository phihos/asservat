# Started downloads across permission suspension

Native run: [42591125143](https://github.com/phihos/asservat/actions/runs/42591125143), `workflow_dispatch`, suite `continuation-native-paced`.

Tested commit: `724f7860593eed00310e46a2fea24acd3fc30072`. Eligible PR CI run [42589840700](https://github.com/phihos/asservat/actions/runs/42589840700) passed with `ci-ok`. The guarded disposable GitHub runner executed the collector; no collector ran on the workstation.

## Result

Pass. `TestInitialBootstrapChainWithRealServices` completed in 479.054 s; the installed approved-recording focus completed in 201.70 s.

- The original unpaced, paced, two-range and stale-`If-Range` comparisons completed across four distinct sessions; both ranges reused their original session.
- Permission suspension was injected after the final stale-`If-Range` response started. That response completed all 8,388,476 bytes with the same SHA-256 as the unpaced control.
- A fresh preparation under verified suspension was refused either at audit-admission HTTP `Service Unavailable` or as typed `NotAvailable`; no successful preparation was accepted.
- The permission projection was restored and required to be fresh before parent history checks.
- `sourceUnchangedDuringTest: true`, `buildScratchRemoved: true`, `cleanupFailures: []`; 4,531 source inputs matched Git.

This qualifies ADR-312's started native response path and the existing native comparison scenarios. It does not add broader CNI, raw-grant or sustained-operation qualification.

An earlier identical-code run, [42589561376](https://github.com/phihos/asservat/actions/runs/42589561376), stopped before download comparisons because generated traffic was below the existing near-full minimum. It is not qualification evidence.

## Retained records

- [Go test output](context-storage.log)
- [Test timing](context-storage-timing.log)
- [Environment, source hashes and cleanup markers](context-storage-environment.json)
- [Native pacing measurements and body hashes](native-paced-report.json)
- [Approved recording provenance](approved-recording-report.json)
- [Native Kubernetes audit](native-paced-kubernetes-audit.json)
- [Suite harness output](ci-native-continuation-native-paced.log)
