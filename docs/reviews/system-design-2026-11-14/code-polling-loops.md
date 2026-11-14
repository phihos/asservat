# Runtime polling loops (code audit, 2026-11-14)

I found about 65 distinct runtime polling, retry or periodic loops under `cmd/` and `internal/`. Of these, 19 are clear high-benefit replacements (A), 29 are replaceable with moderate benefit (B) and 17 are legitimate (C). About 35 more one-shot deadline, lease or event-with-timeout timers are not loops and aren't counted. Two more 1s loops are unused code.

The code has no informers, no `LISTEN/NOTIFY` and no NOTIFY triggers at all. The only Kubernetes event sources are hand-made finite watches: access bindings (`permission_watch.go:65`, timeoutSeconds=4), retention policies (`retention_watch.go:40`, 3), and namespaces and workloads (`permission_namespaces.go:30`, `permission_workloads.go:130`, 2).

**Main cause:** SQL projections and observations carry short validity windows (`CapacitySourceInterval`=5s, connector identity 5s, `AuthorityRecheckInterval`/`PermissionObservationInterval`/`PolicySourceInterval`=30s). Many loops exist only to re-read unchanged state before it expires, which conflicts directly with the new rule "cached state remains valid until replaced". Removing that rule from the domain makes most of group A collapse into watch- or NOTIFY-driven updates.

Paths below are relative to `/home/phil/Projekte/asservat-nopoll/internal/`.

## (A) Clear replacements, high benefit (19 loops)

| # | file:line | Process | What it polls / interval | Cost scaling | Replacement |
|---|---|---|---|---|---|
| 1 | `application/configuration/reconciler.go:504` (`refresh` at :427) | hub-worker | 1s ticker beside the existing AccessBinding watch: full binding LIST, trust read ×2, guard proofs, remote namespaces and workloads via connector (`RemoteNamespaceRefresh`=10s, :79/:181/:243), then SQL accept. "Full LISTs renew deny completeness." | 1 LIST + several reads/s; remote part ×clusters (≤8) ×selections | Watch already exists. Resync only on watch restart or digest mismatch. Remote namespaces/workloads should be watched by the connector and pushed. |
| 2 | `application/capacity/reconciliation.go:225` (and :226–237 variant) | hub-worker | Capacity source observe, 1s: recovery SQL, source-revision SQL, K8s source; result valid 5s | constant, 1/s | Watch the capacity CRs and processing source, NOTIFY on recovery/revision |
| 3 | `reconciliation.go:244` | hub-worker | Root reconcile, 1s, SQL | 1/s | Run on source change (#2) |
| 4 | `reconciliation.go:289` → `reconciliation_discovery.go:38` | hub-worker | Per-cluster discovery, one step per 250ms: namespace LIST pages, LIST per namespace × {Deployment, StatefulSet, Pod}, then an exact read + SQL reconcile per workload, endless round robin | Up to 4 API calls/s per cluster; pass time grows with namespaces × 3 + workloads | Informers on Namespaces, Deployments, StatefulSets and Pods; reconcile on event |
| 5 | `reconciliation.go:370` (`ReadCapacityRefreshDemands`, `postgres/capacity_refresh_demand.go:51`) | hub-worker | Demand lane, SQL read every 250ms | 4 queries/s, always | NOTIFY from the `DemandCapacityRefresh` insert, or push the demand in-process |
| 6–7 | `application/capture/context_storage_wait.go:114` and `:271` | hub-api, inside the request | Re-reads `ContextStorage` SQL every 250ms until hub-worker writes a fresh binding | per preview request | NOTIFY from the binding write. Together with #5 the write side is a NOTIFY round trip. |
| 8 | `application/capture/policy_trigger.go:113` (cycle :169, tick :216) | hub-api, every replica | `TriggerPollInterval`=15s, retry 5s ×2. Per active policy (≤16 per cluster): policy GET, accepted-authority SQL, and a connector query `ObserveWorkloadRestarts` (`adapters/kubernetes/workload_restarts.go:78`): namespace GET, workload GET, Pod LIST, plus Events LIST, pods/log GET per container, PodMetrics LIST and Alertmanager GET depending on detector. Also settles occurrences, publishes acceptances, sweeps ongoing sources, and renews the 30s ongoing-source leaf each tick. | policies × (several K8s calls + connector round trip) / 15s | Connector-side Pod watch (restartCount/status) pushes occurrences over the existing connector channel; policy watch. Alertmanager can stay polled or use its webhook. Drop the 30s leaf or renew it on change. |
| 9 | `application/configuration/retention_reconciler.go:259/290` (maintain :141) | hub-worker | Full EvidenceRetentionPolicy LIST + protection proof ×2 every 1s, beside the existing watch | 1 LIST/s | Rely on the watch; LIST only on restart |
| 10–11 | `application/fleet/reconciliation.go:33`, and the same pair in `worker_owner_audit.go:173` (used in production via `bootstrap/hub_worker.go:458`) | hub-worker | Fleet trust settings ConfigMap and owner source ConfigMap (+ key-service PKI roots over HTTP), each every 1s, into a 5s-fresh SQL projection | 2 loops × (GET + SQL) / s | ConfigMap watch; PKI roots on change |
| 12 | `bootstrap/hub_worker_permission_workers.go:122` | hub-worker | Worker configuration ConfigMap + SQL every 1s ("so an accepted revision stays within its five-second freshness") | 1/s | ConfigMap watch |
| 13 | `bootstrap/hub_worker_permission_child.go:327` | hub-worker | Browser settings ConfigMap → SQL every 1s | 1/s | ConfigMap watch |
| 14 | `application/configuration/policy_grant_settings.go:76` | hub-worker | Identity policy ConfigMap → SQL, `PolicyGrantSettingsCadence`=10s. The comment at `hub_worker_permission_child.go:319` says "one projection per second", which is out of date. | 0.1/s | ConfigMap watch |
| 15 | `bootstrap/hub_worker_permission_child.go:375` (`publish`) | hub-worker | Authority/retention audit outbox drain, `PendingAuthorityAudits` every 1s | 1/s | In-process signal from the reconciler that writes the record (same process), or NOTIFY |
| 16 | `bootstrap/hub_worker_permission_retention.go:122` | hub-worker | Retention catch-up page every 1s when idle | 1/s | In-process signal from the retention reconciler (same child) or NOTIFY on checkpoint insert |
| 17 | `bootstrap/publisher.go:380/423` (`PendingContextPublications`, `postgres/context_key_unwraps.go:178`) | publisher | Outbox drain every `PollSeconds` (chart default 2, `values.yaml:324`) | 0.5 queries/s per replica | NOTIFY from the transaction that enqueues the publication |
| 18 | `bootstrap/context_regional_collect.go:55` (`postgres/api_context_recording.go:24`) | hub-api, every replica | `StartedRecordings` SQL every 3s (`collectInterval`) | 0.33/s per replica | Due time is known at insert: a timer per recording, plus NOTIFY on insert or a connector "stored" push |
| 19 | `bootstrap/context_regional_start.go:440` (`ReadContextStartOwners` → `regional_lifecycle.go:201` → `postgres/context_start_owners.go:16`) | connector | Asks the hub for its owner candidates every 1s; each ask opens a new lifecycle conversation and runs a hub SQL query | 1 hub round trip/s per connector; hub load × connectors | Hub pushes owner-set changes over the existing standby/lifecycle channel, or the hub watches its owner pool |

## (B) Replaceable, moderate or low benefit (29 loops)

**Short watches with 1s re-LIST pause:** namespace feed `application/configuration/inheritance_run.go:58` and workload journal `workload_journal.go:238` (one loop per selection × 3 kinds). Watch sessions are deliberately 2–4s (see header) to mark freshness on EOF. That is a watch reconnect every 2–4s per kind. Use long watches; freshness on bookmark needs a policy decision, because AGENTS.md:333 currently forbids it. (2 loops)

**SQL due-work sweeps:**
- `bootstrap/hub_worker_cleanup_runtime.go:97`: `DueWorkerOperations` + `DueOperationHistory` every 1s.
- `application/capture/history_parameter_service.go:396/429`: retirement sweep every 3s, plus preview cleanup.
- Both are TTL/due-time work. Sleep until `min(due_at)` and NOTIFY on insert. (2 loops)

**Node and collector:**
- `bootstrap/node.go:398` statusLoop sends a full report every `StatusInterval`=15s per node (stale after 45s, `domain/collector/channel.go:14`).
- It is a heartbeat plus full resend, and cost grows per node.
- Send on change (the kick channel exists) with a small liveness beat, or treat the held long-poll as liveness. (1 loop)

**Per active capture:**
- `bootstrap/regional_peer_verifier.go:105`: connector re-resolves packet peers every 1s (`peerVerifyInterval`). Replace with an EndpointSlice/Pod watch.
- `adapters/gadget/arguments_gadget.go:395` and `traceloop_gadget.go:327`: BPF map + `/proc` cgroup/mount-namespace scan every 1s. Replace with a container-runtime/Pod watch or exec/cgroup events from inspektor-gadget's container collection.
- `adapters/diagnostics/go_profile.go:371`: re-checks the guard every ≤1s, or half the validity. This is an expiry-driven re-read; push revocation instead.
- (4 loops)

**Cluster-catalog ConfigMap GET, restart on change:**
- `publisher.go:382` (15s), `key_service.go:439` (15s), `owner_deployment.go:473/515` (hub-api, every 15 ticks).
- The same hub-api 1s ticker re-reads the mounted `worker-controls.json` every second (`:506`).
- Replace with a ConfigMap watch and inotify on the mount. (3 loops)

**Fixed sleeps waiting for a fresh connector standby (hub-api):**
- `policy_trigger.go:398/453` (2s ×3)
- `capture/composition_group.go:477` (500ms ×3)
- `bootstrap/context_regional_start.go:77` (250ms)
- `bootstrap/history_dispatch.go:115` (250ms)
- `application/capacity/reconciliation_work.go:195` (1s, "no free standby")
- `contextstart.Router` already has a `registered` channel signal (`transport/contextstart/router.go:385/519`); wait on that instead. (5 loops)

**Download path:**
- `bootstrap/download_worker_native.go:114/138`: a 1s gap after each parked long-poll (the server side is already signal-driven, `transport/native/router.go:191`). Low benefit; keep the stream open and push.
- `adapters/kubernetes/download_jobs.go:671`: 20 × 100ms Job/Pod GETs waiting for deletion. Use a watch on the Job/Pods.
- (2 loops)

**Bootstrap and renewal checks:**
- `application/fleet/local_bootstrap.go:143`: Secret existence check every 15s or 1min until claimed. Secret watch.
- `bootstrap/regional.go:324/418`: connector `credentials.Reconcile` every 1min (2 hub registration round trips each), and the rotator every 1min for a 24h rotation. Use a timer to the due time.
- `bootstrap/hub_worker_capacity_child.go:125`: 5s retries waiting for the sibling permission child's stream to become current. Use an in-process signal.
- (3 loops)

**Local due-check tickers (I/O only when due; cheap):**
- `adapters/kms/federation_provider_effects.go:193`
- `kms/publisher_provider_effects.go:160`
- `kms/owner_provider_installed.go:299`
- `kms/configuration_provider_installed.go:257`
- `adapters/mtls/verifier_credentials.go:185`
- All 1s; a timer to the next renew time would do. (5 loops)

**Other:**
- `application/evidence/download_response_transfer.go:148`: 100ms retry for at most 2s while the browser session is busy. Use an in-process signal.
- Context deletion sweep, 30s (`hub_worker_permission_workers.go:221/367`): TTL cleanup, borderline C.
- (2 loops)

## (C) Legitimate (17 loops)

- **Long-poll, already event-driven:** node work poll with 25s hold and wake channel (`application/delivery/node_channel.go:333`). The client side is `node.go:439` pollLoop, which also has 5s and 1s backoff.
- **Lease renewal:** client-go leader election, 15s/10s/2s (`adapters/kubernetes/reconciliation_leader.go:131`).
- **Certificate renewal at the due time:**
  - node `renewLoop` (`node.go:579`)
  - `application/evidence/worker_runtime.go:58/101/108`
  - `application/fleet/owner_runtime.go:71/107`
- **Bounded startup waits and failure backoff:**
  - `setup.go:101` (2s) and `waitSchema` `setup.go:460` (2s, init container)
  - node enroll retry 5s (`node.go:366`)
  - hub-worker child open/restart retries: cleanup 5s, permission open 5s, capacity restart 5s (`:200`), permission epoch restart 1s/31s, retention reconciler 31s
  - connector bootstrap and context restart, 5s (`regional.go:385/400`)
- **TTL/idle GC:** in-process idle check every 10s (`workload_journal.go:203`).
- **Serialization retry:** jittered retry on 40001/40P01 (`adapters/postgres/custody.go:179`).
- **Diagnostics only:** `bootstrap/event_log.go:98` (10s); stats lines in `owner_deployment.go` (every 30 ticks) and traceloop (every 30s).
- **Not loops** (deadline, lease and window timers, all fine):
  - `time.AfterFunc` deadline narrowing in `adapters/postgres/capacity_*.go` (7) and `postgres/policy_sources.go`
  - analysis/evidence/identity/live expiry timers
  - `node_local_observation_gate.go`, `node_packet_source.go`, `node_live_source.go`
  - waits until a capture window ends: `node_source_snapshots.go:114`, `regional_logs.go:30`, `regional_logs_holder.go:118`
  - upload rate limiting: `node_packets.go:364`
  - event waits with a timeout: router, stream, native/ownerrelay handoff, worker admission/source notice, `regional_store_wait.go`

## Unused code
- `application/identity/browser_session.go:42` `RunSessionCleanup` (1s ticker) has no caller.
- `adapters/mtls/connector_process_credentials.go:339` `ConnectorProcessCredentials.Run` (1s ticker) has no caller; `regional.go` drives `Reconcile` every 1min instead.
- `application/capture/policy.go:27` `PolicySourceObserver` is never constructed.

## Steady-state load at default 1-replica settings
- **hub-worker:** about 10 loops at 1s or faster. Together they drive 4 discovery API calls/s per cluster, 4 demand queries/s, a full AccessBinding LIST/s, a full retention LIST/s and about 5 ConfigMap GETs/s.
- **hub-api:** policy polling every 15s per policy, a recording SQL scan every 3s, a 1s file re-read, and 250ms SQL polls inside requests.
- **Each connector:** a hub round trip every second.
