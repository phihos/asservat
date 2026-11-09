# Installed live-view owner failover

Native run: [42705246482](https://github.com/phihos/asservat/actions/runs/42705246482), `workflow_dispatch`, suite `continuation-ongoing-live`.

Tested commit: `c890dc862d12ae602f84e3b64d7398a87ca2818d`. The guarded disposable GitHub runner executed the collector; no collector ran on the workstation.

## Result

Pass. `TestInitialBootstrapChainWithRealServices` completed in 428.42 s; the installed live-observation focus completed in 157.14 s.

- The exact original owner Pod was deleted after the initial MCP replay and React's ordinary close. A replacement Pod activated a distinct server epoch without changing the accepted Deployment or ReplicaSet.
- The recovered MCP view returned an empty same-revision `Closed` batch with no continuation and a reconnect gap. The minimized SQL control was `Closed` with unchanged spend; no private source/filter state was adopted.
- Packet, syscall and HTTP policy sources then completed their ordinary MCP and React paths. Twenty-one bounded MCP live operations ran without viewer acquisition.
- The separate HTTP Save downloaded 3,036 native bytes, SHA-256 `f21821cc73c113ba55f507766df819210b293ba12189e2df7df88e573c3f7d93`; transient live rows were not persisted or reused as evidence.
- `sourceUnchangedDuringTest: true`, `buildScratchRemoved: true`, `cleanupFailures: []`.

The real-PostgreSQL control fixture passed in 11.472 s and the upgrade/rollback fixture in 7.970 s. Both record unchanged sources and no cleanup failures. Full `make pre-push`, final-head PR CI run 42703180422 (`ci-ok`) and Gitar review also passed.

## Earlier failures retained as scope, not passes

- Run 42689236964 reproduced the missing terminal recovery: the owner was replaced but repeated reads produced no gap or closed state.
- Run 42697776758 stopped during `tshark` setup and executed no test.
- Run 42700800627 passed the failover leg, then found the ordinary-close stale-revision fixture defect corrected in `c890dc86`.
- Run 42703171355 failed before failover when its first policy source missed the activation dispatch window. The same commit was rerun with fresh activation deadlines rather than extending the lease.

## Scope and retained records

This qualifies the named installed policy-owner failover and its MCP terminal path, not every live-view matrix, cursor-less close-after-loss scenario, CNI variant, grouped/argument/peer profile or sustained-operation claim. React completed its ordinary close before owner deletion; this is not a React-failover claim.

- [Go test output](context-storage.log)
- [Test timing](context-storage-timing.log)
- [Environment, passed tests, source hashes and cleanup markers](context-storage-environment.json)
- [Native harness output](ci-native-continuation-ongoing-live.log)
- [Real-PostgreSQL control output](live-watch-ledger.log)
- [Control environment and cleanup](live-watch-ledger-environment.json)
- [Schema upgrade/rollback output](live-watch-upgrade.log)
- [Upgrade environment and cleanup](live-watch-upgrade-environment.json)
