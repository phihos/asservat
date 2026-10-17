# Deployment and operations

## Helm packaging

Helm is the officially supported installation method ([ADR-058](decisions/058-official-helm-installation.md)). Maintain one `asservat` OCI chart with explicit `mode: hub | cluster | combined`; also support verified local archives. Production multi-cluster installs use one hub release and one cluster release per enrolled cluster; `combined` is an evaluation convenience. CRDs have documented explicit upgrade ordering. [ADR-063](decisions/063-small-deployment-alternatives.md) adds explicit internal/bundled dependency choices for small deployments; do not install services or operators implicitly. Keycloak remains the first tested external identity provider. Local users/login, static keys and Helm-provided PostgreSQL are required planned alternatives; SeaweedFS/pgBackRest are the recommended bundled storage/backup implementations, pending qualification.

The [current chart and commands](../charts/asservat/README.md) install the four implemented configuration CRDs and release inventory only. Runnable services remain in progress. The [installation guide](installation/helm.md) distinguishes this tested foundation from the following production packaging requirements.

Permission bindings/sources and administrator policies live in the configured hub control namespace (`asservat-system` in examples). Cluster registrations, grants, shares/intents, runtime quota state and hub work live in PostgreSQL. Collection policies remain in their workload namespaces. Team access is configured through AccessBindings and PermissionSources. Existing namespace provisioners can write trusted ownership annotations; GitOps or machine clients can manage the same hub permission resources. Inheritance rules are off until configured and qualified for that cluster.

Planned runtime values groups: `hub`, `database`, `enrollment`, `identity`, `permissions`, `presets`, `privacy`, `storageProfiles`, `kmsProfiles`, `nodeCollector`, `coreHandler`, `gadget`, `analysis`, `ceilings`, `capacityPools`, `budgetPolicies`, `sharing`, `retention`, `events`, `networkPolicy`, `observability`, `images`, `offline`. These are not accepted values in the foundation chart; add their typed schema and actual consumers together. Every image/gadget accepts a private registry and digest. References to secrets are explicit. Helm values and rendered manifests must not print credential values or evidence.

Use a collector namespace explicitly allowed privileged pods. Keep hub, browser and ordinary control-plane pods Restricted. Analysis can use a separate Restricted namespace and optional sandbox RuntimeClass. Workload namespaces retain Restricted enforcement. Core interception defaults **off** until the node qualification/ownership check is acknowledged. Packet/log/resource features do not require enabling core interception.

Two replicas for hub/API and cluster controller are the proposed HA default; use leases for reconciliation and per-work-item fencing. Node collector and Gadget run once per eligible node. PDBs, topology spread and resource requests protect control components, but must not prevent cluster recovery. Do not set unlimited collector priority or CPU/memory.

## Defaults, readiness and privacy

Provide a read-only installation/capability report with missing prerequisites, affected features and the responsible role. Reuse qualified permission sources, endpoint templates and presets across applications. Document kubectl apply/dry-run/diff and generation-aware health; application maintainers use the hub without a management-cluster kubeconfig. Fully resolved YAML is an advanced view, not a prerequisite for basic capture.

Install one protected baseline EvidenceRetentionPolicy and distribute current snapshots to each cluster. Local policies may tighten it. Reject incompatible lock/backup profiles, show effective maxima by evidence type, and enforce the copy/deletion rules in [privacy](../specs/privacy.md). The sample uses 24-hour user evidence and 6-hour core/heap maxima; neither is a legal prescription. Default deletion budget is 5 minutes inside the cap. Emit one actionable overdue condition with retries/copy status rather than expecting manual cleanup per core.

Maintain reviewed mechanism/qualification rule versions with capability data and the approved handling-policy reference. Missing or mismatched benchmarks must surface as uncertainty, not a default numeric estimate. Operators can inspect assessment/deletion reasons without disclosing user contents, and shortening retention updates visible deadlines through the normal privacy reconciler. See [capture assessment](../specs/capture-assessment.md); no ongoing profiling is enabled merely to populate forecasts.

## Storm and capacity operations

Configure protected workload allocations and shared burst once per storage pool, with automatic namespace budget profiles. The [sample pool](../examples/storage-pool.yaml) backs four 16 GiB workload allocations in 128 GiB total, with separate system/headroom and 40 GiB shared burst. The [budget profile](../examples/budget-policy.yaml) caps each workload at 32 GiB, reserves context space and limits dumps to one episode per 15 minutes and two individual process starts per rolling hour. These are illustrative values requiring workload/backend qualification.

Check byte and object reservations before acquisition; keep versions, multipart remnants and deletion-pending copies charged. Defaults preserve existing evidence and refuse new expensive capture when that workload fills its quota. Optional rolling deletion affects only its own eligible evidence. Never borrow another workload's protected allocation. Show physical/backend capacity separately from logical usage and refuse an unsupported isolation claim on best-effort storage.

Fair rate/CPU/scratch profiles must agree with dump size/time budgets: the example 32 MiB/s workload upload ceiling cannot stream an uncompressed 2 GiB artifact in the generic 30-second acquisition deadline. Preflight must expose that conflict and require a supported adjustment; it is not resolved by unlimited buffering or hidden timeout extension.

## Initial sizing budget

Values are starting budgets to measure, not guaranteed consumption.

| Component | CPU request / limit | Memory request / limit | Notes |
| --- | --- | --- | --- |
| Hub API/MCP | 250m / 2 cores | 256 MiB / 1 GiB | Scale by concurrent queries and auth load |
| Hub reconciler/index | 500m / 2 cores | 512 MiB / 2 GiB | Index cache can be split from API if measured |
| Cluster controller | 100m / 1 core | 128 MiB / 512 MiB | Batched watches and bounded work references |
| Node collector | 100m / 1 core | 128 MiB / 512 MiB | Aggregate ring reservation is included in memory planning |
| Gadget | Determine in EXP-02 | Determine in EXP-02 | Do not invent a resource recommendation before packet tests |
| Basic analysis Job | 250m / 2 cores | 256 MiB / 2 GiB | Runtime packs can demand more under explicit profile |
| Heap/GPU analysis | Explicit profile | Explicit profile | Admission estimates scratch/RAM, then enforces actual ceilings |

At 1 Gbit/s a 30-second full-payload ring would require about 3.75 GB before overhead; byte caps make high-rate history shorter. A 16 MiB ring is a memory budget, not a guarantee of 30 seconds. Core transfer time has a lower bound of bytes divided by effective bandwidth; compression ratios are workload-dependent. Measure CPU and process-stop time, not only upload throughput.

Object-operation cost also matters: durable per-call audit produces small writes, and a 90-day retention period at one audited call per second is about 7.8 million call records before intent/result splitting. Measure PUT/list costs, record counts and control-plane update rates. Archive completed records into sealed batches only with a tested migration/retention protocol that preserves audit completeness; never silently reduce audit guarantees to meet a cost target.

Proposed runtime admission ceilings: 100 active captures per workload cluster; 1,000 active grants, 1,000 active shares, 500 retained sharing intents, 2,000 workload accounts and 2,000 active capacity reservations per installation; <=64 active slices per account. Cap aggregate active runtime work at 10,000 records, excluding bounded catalog/history rows. These SQL application ceilings protect workload/worker demand and remain until measurements justify changes; the former hub CRD total is retired. Separately cap Kubernetes configuration at 2,000 AccessBindings and 100 PermissionSources. Each source supports <=1,000 namespaces, with explicit unavailable status on overflow rather than arbitrary selection.

Terminal ordinary work rows have a proposed 24-hour operational retention, but parent authorizations, tombstones and accounting survive until dependent access/replay/restore windows close. Per-intent limits remain 100 captures, 64 distinct shared artifacts per capture, and one concrete child per capture/selection; installation share limits can bind sooner. No per-recipient payload copy. Publication pressure is visible and does not discard ordinarily accessible evidence. Size SQL catalog and audit history separately using the approved metadata retention and measured workload; SQL storage is not unlimited.

Packet defaults resolve to four 4 MiB ring segments per target, with separately reserved frozen/upload and HTTP parser memory. Show actual history coverage and update/loss gaps; the optional encrypted-disk ring profile needs explicit qualification. Capacity and privacy policies include every segment and snapshot.

## Network allowlist

Hub: configured PostgreSQL TLS endpoint, local Kubernetes API, configured IdP endpoints, hub object store, operator-selected webhooks, optional private metrics/traces. Connector: local Kubernetes, hub, regional storage/KMS, approved private registry/symbol services. Node: local connector/Gadget, KMS wrap endpoint and artifact upload destination. Acquisition: approved storage/KMS/registry/symbols. Analyzer: no network. Publisher: storage upload and local completion endpoint only.

All links use TLS; internal node-local UDS traffic is filesystem/peer-credential protected. HostNetwork traffic may bypass ordinary NetworkPolicy enforcement: use provider/VM firewall or qualified host policy during isolation/no-egress testing. Do not rely on DNS deny rules alone. Public access is limited to the operator's authenticated hub endpoint and configured webhook receiver if enabled.

## Air-gap operation from the first slice

Release bundles contain chart/CRDs, all architecture-specific images, gadget OCI objects, signatures/public verification material, SBOM/notices, test fixtures and a dependency manifest. Import into operator registries before deployment. No runtime image installation, public debuginfod, public PDB/symbol fallback, CDN script/font, remote gadget resolution, licence service, update check or crash reporting.

Configured identity, storage and key endpoints remain reachable, whether internal/bundled or operator-provided; "no internet" is not "no communication between required services". Offline tests distinguish these. Operator metrics scraping is supported; external OTel exporters are absent by default. Toolchain/package acquisition for development is a separate build-time supply-chain activity, also mirrorable.

## Health and observability

Expose content-free counters/histograms: target coverage, policy generation lag, sensor gap seconds, log records/bytes dropped, packets observed/sanitized/dropped, ring time coverage, trigger delay, suppressed occurrences, queued/running actions, pause duration, core-handler rejection/timeout, core_pattern drift/conflict, encryption/KMS latency, upload bytes/errors/multipart age, analysis status, hub heartbeat, query duration/output, grant/share denial/revocation, audit durability latency and deletion lag.

Avoid pod UID, case ID, signature, username or arbitrary labels as metric labels. Use bounded labels such as cluster, detector/action kind and reason; detailed IDs belong in access-controlled structured logs. Traces contain opaque IDs, never payload or command secrets. Health distinguishes process readiness, collection capability and evidence durability. A green HTTP probe alone is not proof that cores can be collected.

## Backup, recovery and upgrades

Back up Kubernetes configuration/local control through the platform process and authoritative PostgreSQL through its qualified base-backup/WAL process under finite metadata/backup policies. Never include full manifests, log/profile/packet extracts or arbitrary sensitive strings in SQL backups. Exclude raw/derived evidence and plaintext scratch from general backups by default. Evidence replicas/backups require a qualified profile honoring each absolute deletion deadline; retain object-store records only under the [privacy policy](../specs/privacy.md). KMS backup/restore is operator-owned and necessary for evidence recovery. Restoring an old backup must apply tombstones, expired grants/shares, revocation checkpoints and current identity and access policies before access opens. The initial memory evidence-text index has no backup; optional durable expiry cohorts require REQ-PRV-008 qualification. SQL live authorization/accounting state is mandatory recovery state; artifact manifests alone cannot reconstruct it. Apply [database recovery](../specs/persistence.md#req-db-005--durability-outage-and-disaster-recovery), primary fencing and old-permit invalidation before opening service.

Upgrade hub first within the N/N-1 compatibility window, then connectors, then node agents/gadgets. Canary on synthetic selected workloads. Drain active intrusive actions before node-agent upgrades; preserve helper path during handover. Migration must not reopen grants, widen shares or change manifest interpretation silently. Keep schema readers for retained artifacts. Rollback uses prior images/config but cannot reverse completed side effects.

Uninstall suspends policies, stops new captures, drains helpers, conditionally restores owned `core_pattern`, removes helper files only after safe handover, revokes cluster identity, then removes components. Evidence and KMS keys are not deleted by Helm uninstall; explicit retention/admin workflows handle them. A partial uninstall produces recovery instructions.

## Operator runbooks to ship

1. Qualify node pool / inspect missing capabilities without changing it.
2. Enroll/rotate/revoke a cluster identity; recover a lost connector.
3. Arm a Deployment/StatefulSet policy and verify actual selected pods.
4. Resolve competing core handler ownership without destructive overwrites.
5. Investigate missing/partial evidence and multipart backlog.
6. Approve/revoke a policy grant; inspect aggregate spend and ambiguous actions.
7. Share selected evidence or configure result sharing during capture/policy authoring; inspect pending selections and recipient view, distinguish Stop from Revoke, and recover stalled materialization without duplicating or widening grants.
8. Rebuild an index without changing authorization.
9. Apply administrator retention policies through Kubernetes; preview existing-evidence impact, hold limits and lock conflicts; inspect access cutoff, deletion deadline and every overdue copy.
10. Perform fully offline installation/upgrade and no-call-home verification.
11. Configure a namespace ownership source, preview its scope, verify metadata writer protection and explain a team member's access.
12. Enable exec inheritance only after identity mapping and admission-parity qualification; revoke a binding/source and verify expiry.
13. Manage permission bindings through the Kubernetes API/GitOps and handle an ownership change without exposing retained evidence.
14. Restrict processing, handle an authorized early-erasure request and generate a content-minimized processing/deletion report.
15. Diagnose preset resolution, pod/replica coverage and safe analysis-only retry without repeating collection.
16. Diagnose a trigger storm, inspect suppressed counts and impact breakers, recover orphan reservations and expand backed capacity without stealing another workload's allocation.

## Database installation and runbook

Reuse a qualified operator PostgreSQL 18 service where available, or explicitly select the planned Helm-bundled single-instance option. Supply or bootstrap endpoint, dedicated database/roles, TLS CA and Secret references; chart preflight checks connectivity, schema compatibility and declared durability/backup profile. Do not auto-install an operator or request database credentials from application maintainers. A two-replica hub does not make a single database highly available. HA requires a tested synchronous/fenced failover profile; small single-instance mode reports downtime and failure-domain limitations. The [dependency report](research/small-deployments.md) recommends pgBackRest encrypted base/WAL backup and tested restore, with a separately accounted repository. No same-disk backup claim substitutes for independent disaster recovery.

Provide runbooks for primary loss, full disk, connection exhaustion, slow queries, migration interruption, PITR and complete restore. Run migrations once with a separate DDL role; use expand/backfill/contract and preserve N/N-1 compatibility. Default pool is at most 32 connections per replica, summed across replicas/jobs within database allocation. Monitor transaction/lock time, WAL/archive/replication lag, pending audit/outbox rows, backup age and restore drills. Never log raw SQL parameters containing protected values. RecoveryBlocked is actionable: reconcile current configuration, restore independent deny/delete checkpoints, fence old epochs and preserve uncertain charges before lifting it.

Team management setup reuses existing owner-group bindings. The UI shows creator and managing teams separately; group departures do not require per-share reassignment. Historical ownership changes remain explicit, and raw approval remains person-specific.

Policy approval defaults/maxima live in protected installation configuration (`approvals.policyGrants`), not in maintainer requests; see the [approval settings example](../examples/approval-policy.yaml). Observation ceilings are separate from per-incident maxPods. All-replica monitoring reports coverage overflow before Ready; pod-wide fanout shares aggregate budgets. Provide a single readiness/expiry view covering observation, collection approval and independent future-sharing expiry.

Storage/backup preflight checks REQ-PRV-008 residual horizons, not just finite TTL. Read-only preflight reports configuration inspection separately from synthetic deletion/failover verification. Text indexes initially use bounded memory with qualified swap/core exclusion; persistent caches require expiry-cohort qualification.

## Discovery defaults and controls

Install the immutable `inspect-processes/v1`, `inspect-network/v1` and `inspect-protocols/v1` diagnostic catalog entries with their qualified projection/classifier digests. Administrators can disable entries and lower [guidance](../specs/guidance.md) survey limits centrally; maintainers need no per-workload setup. Qualification status must distinguish identity, socket-owner, packet-header and protocol adapters. Disable the affected recommendation when a required adapter is unavailable; keep ordinary context paths usable. Report discovery budget refusals and actual sample coverage without recording process/traffic content in telemetry. Inspect expiring draft/object cleanup alongside other retention copies.

## Catalog operation and tracing readiness

Install the shipped CaptureProfile bundle offline into its protected namespace and configure one organization catalog location; workload namespaces may publish local versions under delegated Kubernetes rights. Show catalog validation/visibility/propagation separately. Upgrades add versions without moving existing pins; deprecation suggests migration, disablement blocks new starts under current permit rules. Removing a bundle does not erase retained evidence or bypass its deletion deadline. Keep SQL catalog projections reconstructible from authoritative Kubernetes state.

Capability reports distinguish syscall metadata from sensitive argument support per node/ABI/engine digest. Neither profile availability nor a successful spec-check proves kernel coverage or overhead. Surface missing adapters, bounded-loss counters and affected pod counts; maintain ordinary Restricted workload policy and impact limits.

Read policy readiness as detector freshness plus per-action source coverage. Ongoing recorders consume capacity and sensitive-observation budgets without incidents; monitor warming, dropped/expired history, grant exhaustion and active frozen windows separately from dump starts/uploads. Policy pause/delete stops its sources, while cancelling one incident leaves otherwise authorized policy recording intact. Recovery must fence source epochs before reattaching. See [action lifecycles](../specs/action-lifecycle.md).

## Stop collection without losing stored evidence

For an incident affecting the observed workload, use the existing local CollectionCeiling emergency deny for the affected action/scope, or suspend the specific DebugPolicy. Surface this path in policy health; no new permission service or special destructive button is required. Connected workers cancel unstarted work and stop recorders within cancellation bounds. Disconnected nodes are bounded by their already issued lease/permit expiry, so the UI must show pending acknowledgments and the latest possible stop time rather than promise an instantaneous global stop. Denial overrides stopped-source grace. Preserve already committed evidence, privacy enforcement, deletion workers and audit; re-enabling collection rechecks current authority/capacity and never resets budgets. Run the process-resume watchdog after an interrupted live dump before reporting recovery.

Analysis storage qualification includes writer fencing, encrypted input/output PVC lifecycle, backend snapshots/reclaim, node-loss cleanup, no uncontrolled worker cores/swap, and tool-output isolation under REQ-EVD-005/008. Missing qualification is a capability gap, not an invitation to mount an ordinary plaintext PVC or share emptyDir across Jobs. Accepted ADR-036 makes a qualified encrypted scratch StorageClass mandatory for offline analysis. Helm configuration must select an operator-provided class per region/analysis profile, bounded per-analysis/aggregate scratch capacity, and the validated reclaim/key/backup profile; there is no implicit default StorageClass. Installation reports analysis unavailable until those checks pass. Collection, encrypted storage, catalog access and existing approved extracts may remain available; tools requiring staging return AnalysisScratchUnavailable with an administrator remedy. Read-only checks cannot certify physical deletion. Qualify on disposable synthetic PVCs, including faults, before advertising the analysis capability.

## Operating live views

Enable only qualified approved live projections and finite liveRead limits under existing local ceilings/deployment configuration. Configure aggregate node/installation CPU/scan, transient memory, viewer/subscription, transfer and rolling principal/workload allowances; incident saves retain their protected allocation and scheduler priority. Inspect active-view count, source loss, projection drops, subscriber lag and spent output separately from recording-ring usage. Increase a limit only with supported-environment evidence; returned-row limits alone do not constrain parser work.

When a live view fails, check current viewer/source executor entitlement, source epoch and lease, supported projection, local liveRead deny, scope/fanout quotas and connector/owner readiness. A stopped source or changed pod needs fresh selection. A live-only failure need not stop recording or invalidate stored evidence. Disabling live delivery releases subscriber work while collection, privacy and deletion remain independently controlled. SQL restore cannot revive expired views; fenced owner takeover must expose any lost replay. Use the ordinary policy recording-save path to preserve evidence, not a live stream export.

## Native evidence download operations

The normal install supports all native artifact formats without a new always-on service. Configure admitted transfer concurrency/bandwidth/read-work, authenticated relay locality, short authority leases and download-only acquisition Job credentials. Downloads are below protected incident uploads in scheduling priority. Do not enable ingress/CDN response buffering or body logging. Check native output size and grant/retry allowance before transferring large cores; an interrupted format without qualified bounded seeking offers a clear full-restart choice. Existing covering grants are reused. Verify expiry/revocation and explicitly document that local copies follow the organization's endpoint handling policy, not Asservat automatic deletion.
