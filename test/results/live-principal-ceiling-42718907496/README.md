# Installed shared live-view principal ceiling

Native run: [42718907496](https://github.com/phihos/asservat/actions/runs/42718907496), `workflow_dispatch`, suite `continuation-ongoing-live`.

Tested commit: `4fdb3fb23b9b4cdecd883d7c9ef229bd5eb629d9`. The guarded disposable GitHub runner executed the collector; no collector ran on the workstation.

## Result

Pass. `TestInitialBootstrapChainWithRealServices` completed in 422.27 s; the installed live-observation focus completed in 146.53 s.

- React proved its `opened` event and stayed open until Go released it after the ceiling assertion. MCP had an independent active view at the same time.
- A third concurrent `open_live_watch` with a fresh idempotency key returned `CapacityUnavailable`. Both original controls remained active; the refusal did not substitute a source or acquire data.
- The original MCP view completed owner-failover recovery. Packet, syscall and HTTP policy sources then completed ordinary MCP and React paths, with 24 bounded MCP live operations and no viewer acquisition.
- The separate HTTP Save downloaded 2,945 native bytes, SHA-256 `8b6cdc0cc71577fb089947e40edbb9267f42b37b7129143690b8e032198fbfb1`; transient live rows were not persisted or reused as evidence.
- `sourceUnchangedDuringTest: true`, `buildScratchRemoved: true`, `cleanupFailures: []`.

Full `make pre-push`, final-head PR CI run 42718916862 (`ci-ok`) and Gitar review passed.

## Earlier runs and exact scope

Run 42710638099 failed because React had already closed before the fixture's control count. Run 42712800039 then passed the MCP-only ceiling, establishing the underlying open–open–refuse–close behavior but not the cross-surface requirement. Run 42715109504 exposed the remaining open-proof mismatch. The final fixture adds explicit `opened`/`release` synchronization and decodes that event with diagnostics; it qualifies React plus MCP sharing one principal's two slots.

This is a bounded principal-ceiling qualification, not a storm, multi-principal, installation-wide overload, sustained-throughput or incident-priority claim.

## Retained records

- [Go test output](context-storage.log)
- [Test timing](context-storage-timing.log)
- [Environment, passed tests, source hashes and cleanup markers](context-storage-environment.json)
- [Native harness output](ci-native-continuation-ongoing-live.log)
