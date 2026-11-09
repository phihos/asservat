# Unrecorded regional completion recovery

Native run: [42630012490](https://github.com/phihos/asservat/actions/runs/42630012490), `workflow_dispatch`, suite `continuation-journey-start-failure`.

Tested commit: `20e56205b96f2a66cbba01e7d8149cc6d61ffec9`. Eligible PR CI run [42630023231](https://github.com/phihos/asservat/actions/runs/42630023231) passed with `ci-ok`. The owned fixtures ran only on the guarded disposable GitHub runner, not the workstation.

## Result

Pass. `TestInitialBootstrapChainWithRealServices` completed in 611.45 s; the installed start-failure focus completed in 331.58 s.

- A fixture-scoped PostgreSQL trigger rejected only capture `a56035fa-a1e4-4c3e-bba0-7cd41f18a689`'s `started → stored` transition after regional storage. The public operation returned `OutcomeUnknown`.
- The exact attempt retained all four regional ciphertext objects (`data`, `index`, `manifest`, `commit`), while execution remained `started` and custody remained `reserved`. This is the durable lost-reply state; the trigger avoids racing a process kill against a small capture and is not a measurement of TCP packet-loss timing.
- Passive resolution/replay named the original capture, with one admission, at most one execution and one custody attempt. The committed regional result was not imported and collection was not repeated.
- The installed hub-worker observed the original deadline. Public progress became `Indeterminate/DeadlineOutcomeUnconfirmed` and stayed terminal through a further observer sweep.
- The separate pre-start KMS failure left capture `96d0eeee-e645-4ac8-900a-3b37e8d7fa42` `Pending` after reconnection, with zero executions, until its original deadline produced the same indeterminate reason.
- `sourceUnchangedDuringTest: true`, `buildScratchRemoved: true`, `cleanupFailures: []`; 4,531 source inputs matched Git.

This qualifies ADR-223's recovery behavior through the real installed storage, execution, replay, progress and deadline-observer path. It does not qualify a separate network-partition injection or broader capture profiles.

## Retained records

- [Go test output](context-storage.log)
- [Test timing](context-storage-timing.log)
- [Environment, source hashes and cleanup markers](context-storage-environment.json)
- [Suite harness output](ci-native-continuation-journey-start-failure.log)
