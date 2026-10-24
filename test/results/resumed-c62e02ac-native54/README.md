# Native54 retained postmortem

Candidate `840f27fc338f0c170a4f6069bc95db4c109bbfaf`, run `context-lcscbtz7`, actual harness exit1 after1292.094284s. Regional join and readiness progressed; the accepted capture remained pending after the original request and four continuations. This is not installed acquisition/download/Stop success.

Source verification exited0 (tool chunk2910bc): all2778 hashes match the candidate Git blobs, with unchanged sources during qualification and removed build scratch. See `source-verification.json`, `.exit`, `.err` and exact command record.

The existing retained collector exited0 (session42684/chunke73a64), verified exact ownership, and completed35 bounded commands with no failures. `retained-collection/collection.json` records all commands and actual exits; the four SQL scripts match the pinned native48 hashes. The collection itself performed no cleanup or source edits. Private kubeconfigs were held in separate0700 `../native54-private`, outside the archive, and subsequently removed as recorded below.

## SQL state

`retained-collection/postmortem.log` contains one capture, `f5c6a41a-ec21-4eb4-ba72-f1756616879b`, state `intent_audited`. It was inserted at21:11:20.014095Z; its immutable intent RequestUntil is21:11:20.952470Z (0.938375s after insertion). The intent object was stored at21:11:20.223185Z and acknowledged at21:11:20.422597Z. Its operation outcome is accepted and fully acknowledged; no intent reconciliation reads were used.

The parent request began at21:11:17.858880Z with original until21:11:22.858398Z. The first start refused before that parent cutoff, while its shorter retained intent cutoff was nearly consumed. This arithmetic does not identify which earlier fact supplied the shorter cutoff.

`postmortem-requests.log` records one accepted resolution, five successful current get_capture operations, and five request_capture operations (original plus four continuations), each ending unavailable/authority_unavailable/unknown. The retained preview remains present. There are zero context_execution rows, one reserved custody record, no published artifact and zero download sessions. Exact execution/publication snapshots are in `postmortem-execution.log` and `postmortem-publication.log`.

## Timestamped process evidence

Current owner log: `retained-collection/cluster-0-pod-2-container-0.log` (previous container log separately archived). Current worker: `cluster-0-pod-4-container-0.log`; regional connector: `cluster-1-pod-0-container-0.log`. Sanitized Pod status snapshots pin their exact UIDs. Original product diagnostics do not carry per-request IDs, so timestamp correlations are evidence to investigate, not new identity assertions.

Owner refusal sequence:

- 21:11:20.940710Z: local route endpoints/read/other, start-left<0.5s, bound parent.
- 21:11:26.957156Z: execute/Check/ResolvePod, start-left>=2s, bound parent.
- 21:11:32.065430Z: execute/PrepareAPIExecution, start-left<2s, bound parent.
- 21:11:38.192292Z: execute/Check/Process, start-left<2s, bound parent.
- 21:11:43.411806Z: execute/PrepareAPIExecution/effect/headroom, start-left<2s, bound receiver.

The final headroom diagnostic and zero execution rows are consistent with refusal before a first irreversible execution preparation; they do not establish a shared root cause for all earlier refusals. Native54 does not prove that additional retries or larger deadlines would be correct. The parent owns source diagnosis.

## Completed cleanup and preceding gates

Exact-manifest cleanup exited0 (session31948/chunk6bb0c3), cleanupFailures[]. Independent read-back confirmed all12 owned Docker resources absent and neither exact cluster listed by Kind. The separate private kubeconfigs were removed. `cleanup-command-result.json` and `cleanup-verification.json` retain actual commands/exits; no guard bypass or force removal was used.

`native53-followup-gates/` archives the already-completed checks of the native53 fixture correction on this same commit: design/spec/architecture/Go dependency exit0 in13.820s, integration race-instrumented compilation with no selected tests exit0 in23.560s, and Helm lifecycle integration exit0 in53.985s. All3773 tracked non-result source hashes were unchanged. This archive introduces no new test run.
