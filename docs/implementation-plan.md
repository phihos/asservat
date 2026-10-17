# Implementation plan

The [product implementation status](implementation-status.md) records the current
capability baseline and next complete user workflow. The checklist below retains
the full scope; neither code volume nor component-test counts are a completion
percentage.

[ADR-098](decisions/098-first-installation-activation.md) implements the first-installation SQL/audit coordinator and its native protected-input composition. Continue protected installer plan/credential/pin provisioning and the separate qualified restart/restore protocol. This does not enable Helm runtime services or complete S-01/S-02.

Work has resumed after the [ADR-097 witness component](architecture/installation-witness.md). Its protected one-use record is implemented; production installer provisioning and independent restart/restore activation remain required. Complete atomic eligible-SQL checks, independent encrypted activation audit, protected installer credentials/pins and qualified recovery before enabling activation. Current verification and open gaps are in [implementation progress](implementation-progress.md).

[ADR-096](decisions/096-database-incarnation-fence.md) adds a database-incarnation prerequisite to recovery activation. Continue the independent protected installation/recovery protocol, including retained checkpoints, conservative spend and automated qualified lossless-restart activation. A view or a synthetic administrator fixture is not that protocol.

[ADR-095](decisions/095-hub-workload-garbage-collection.md) qualifies native foreground workload deletion while retaining source, credential and spec-mutation protection. Continue protected installer provisioning and independent restore activation.

[ADR-094](decisions/094-native-hub-worker-projections.md) adds native hub-worker workload/projection composition. The source-matched native worker/lifecycle case now passes in the full context suite; continue protected installer provisioning and independent initial/restore activation before owner/public workflows.

[ADR-093](decisions/093-bounded-hub-scheduling-permission.md) composes named scheduling updates with the private namespace guard. Continue installation provisioning and independent initial/restore activation; native configuration tests remain prerequisites to in-Pod and public workflows.

[ADR-092](decisions/092-independent-source-admission-probes.md) fixes namespace/source admission composition with exact nonpersistent probes. Its actual qualification is recorded in [implementation progress](implementation-progress.md); installation, restore and end-user workflow completion remain open.

[ADR-091](architecture/configuration-reconciliation.md) adds protected fleet/owner source reconciliation through the private hub-worker command. Continue installer-generated inputs/roles, independent initial recovery/restore acceptance and native in-Pod operation before enabling public evidence flows.

[ADR-090](architecture/owner-deployment.md) supplies the owner deployment loader and private `hub-api` command. Continue installation-generated projections, source/recovery reconciliation and native in-Pod routing, followed by actual evidence transfer and public investigation flows. Provider composition tests do not complete a slice.

[ADR-089](architecture/worker-routing.md) removes the single-cluster assumption in owner forwarding. The loader/credential composition is now supplied by ADR-090. Continue protected control-document synchronization and native multi-cluster routing; read-facet and synthetic TLS tests do not complete a slice.

[ADR-088](architecture/owner-startup.md) implements pre-Ready identity checking and a concrete owner runtime lifetime. ADR-090 adds the loader and private entry point. Continue installation provisioning, recovery/source reconciliation and native in-Pod routing before evidence transfer; no full TASK or S-01/S-02 exit follows.

[ADR-087](decisions/087-live-owner-delivery.md) connects remote request cancellation to the existing worker ingress through one finite open TLS response. Continue protected process startup, native routing, connector proof mediation and actual evidence transfer; no complete TASK or S-01/S-02 exit is claimed.

[ADR-086](architecture/owner-forwarding.md) adds outbound owner certificate transfer using current identity and exact locator checks before HTTP, non-replayable transport and verified worker results. Protected startup, native routing, connector proof mediation and evidence transfer remain necessary before enabling the public workflow.

[ADR-085](architecture/owner-relay.md) implements the private enrollment receiving boundary with current local/remote identity checks and socket lifetime. Continue outbound exact-owner forwarding, protected startup, connector proof mediation and native transfer; this does not complete S-01/S-02 or a whole TASK.

[ADR-084 process-owned credentials](architecture/owner-credentials.md) adds private key custody, actual TLS callbacks and paired renewal under TASK-02. Continue protected bootstrap/listener composition and exact-request forwarding. This does not complete a whole TASK or S-01/S-02; measured qualification remains in [implementation progress](implementation-progress.md).

[ADR-083 peer authentication](architecture/owner-authentication.md) adds the current TLS/registry/protection/Ready-route gate and native enrollment-to-activation composition. Continue owner credential transport/supervision, protected bootstrap and locator-bound forwarding; no whole TASK or S-01/S-02 exit follows from component qualification.

[ADR-082 owner registration](architecture/owner-registration.md) implements private durable process/key enrollment, audited bounded signing/activation and finite SQL history under TASK-02. Protected bootstrap, owner transport, native forwarding and full S-01/S-02 acceptance remain pending; component results are in [implementation progress](implementation-progress.md).

Status: the maintainer authorized initial implementation after the feasibility phases. Artifact storage/context, PostgreSQL custody and complete pod-status verification are **in progress** under TASK-02/03/05/11 and S-01/S-02; no whole TASK or slice exit is complete. See the [artifact implementation record](research/artifact-foundation.md), [custody continuation](research/custody-foundation.md) and [manifest verification](research/manifest-foundation.md). Current custody records do not authorize capture or publish readable artifacts. Next connect trusted accepted execution/current authorization, durable object audit and catalog publication, retaining production writer fencing/privacy requirements before the UI/MCP/native-download flow. Other product work remains planned.

TASK-07 now also has an [initial identity/eligibility implementation](research/identity-foundation.md): strict access-token verification, current organization/client policy checks and ordinary retained-audience rules. The production policy/source/catalog readers, actual provider qualification, signed accepted execution and audit remain pending. This advances the prerequisite; it does not complete the OAuth/ACL task or permit public capture.

The [permission observation continuation](research/permission-foundation.md) implements Kubernetes configuration/namespace read ports and unaccepted mapping proposals, with real API/RBAC tests and a corrected five-second deny deadline. Next implement protected configuration acceptance and persistent SQL audience assignment continuity across ownership changes/watch gaps; then supply accepted authorization projections. Raw API observations, CRD status and the test fixture's administrator identity do not fill that gap. TASK-07 and S-01/S-02 remain unchecked.

Current download continuation: [ADR-070](decisions/070-protected-worker-configuration.md) adds protected worker configuration and rollout fencing under TASK-02/07/11. The [progress record](implementation-progress.md) is authoritative for actual qualification and supersedes the older prerequisite snapshots above. [ADR-071](decisions/071-download-worker-enrollment.md) now adds audited acquisition credential issuance/activation and bounded renewal. [ADR-072](decisions/072-worker-credential-channel.md) supplies the bounded private credential transport and process-owned key/renewal client, with a request-bound current-authority operation. [ADR-073](architecture/worker-startup.md) adds typed immutable startup pins and the initial credential-phase executable/supervisor, with original-template cleanup. [ADR-074](architecture/worker-request-routing.md) adds bounded process-local request-owner routing and response lifetime. [ADR-075](architecture/worker-owner-locator.md) adds minimized shared owner locators and exact local receiving under migration 28. [ADR-076](architecture/hub-owner-discovery.md) adds pinned hub endpoint observations and exact TLS process identity verification. [ADR-077](architecture/owner-configuration.md) supplies protected pool/public-root observations and current route composition. [ADR-078](decisions/078-owner-configuration-acceptance.md) adds durable source/revision acceptance and encrypted audit under migration 29, retaining current recovery and original deadlines. [ADR-079](decisions/079-owner-certificate-issuance.md) adds the owner certificate provider/verification boundary and fixed renewal periods. Next compose protected recovery/workload/issuer bootstrap and durable enrollment/activation, authenticated private forwarding, connector proof mediation and actual supervised native transfer before enabling downloads. Continue local identity and bundled-service installation; no whole task or S-01/S-02 exit is complete.

## Architecture and implementation sequence

The [implementation architecture](architecture/README.md) defines applications, components, ports, state ownership and failure handling. Its [code organization](architecture/code-organization.md) is the canonical future repository layout, replacing the earlier package sketch. The [architecture catalog](architecture/catalog.yaml) maps requirements and domain entities to primary components and allowed dependencies.

Use [S-00–09 implementation slices](architecture/implementation-slices.md) to order concrete end-to-end work across the TASK IDs below. TASK numbering is not permission to enable collectors before their identity, audit, privacy and capacity foundations exist. The first complete context slice includes authorized UI/MCP retrieval, encryption, expiry and verified deletion. Run high-risk mechanism spikes early, then enable each only after qualification.

Do not create empty implementation directories as evidence of progress. No CI hosting provider is imposed before a remote repository is selected. Use portable local Make targets; CI invokes the same targets. Release publishing is a distinct authorized action.

## Ordered work packages

### TASK-01 — Feasibility, governance and contract baseline

Technology planning is now written in the [stack](technology.md) and [24-component build/reuse matrix](architecture/build-or-reuse.md). The [isolated experiments](../experiments/technology-selection/README.md) establish limited dependency behavior only. Before production format/code freeze, complete the [ordered qualification gates](research/technology-selection.md), especially native download resume, Gadget dynamic filters/syscall metadata and kernel crash behavior. No TASK exit is marked complete by these tests.

The first two mechanism spikes have [measured findings](research/feasibility-packet-downloads.md): packet capture plus separate compiler/map/ring probes, and encrypted native download through a real S3 fixture including a 2 GiB synthetic artifact. Retain real libpcap compilation; integrate its bytecode and peer generations into Gadget before claiming the full packet contract. ADR-048 now fixes 8 MiB native frames and a paged index for the first product format; production backend/commit qualification remains open. The subsequent [SQL/crash experiments](research/feasibility-control-crash.md) passed selected PostgreSQL contention/restart and local kernel-core tests, exposing and correcting expiry-ordering and completion-reporting hazards. Full core/SQL/KMS/Ceph qualification remains open. The persistent artifact contract and initial code are now recorded separately; continue the S-01/S-02 authority/custody and end-user context workflow, including native download and verified deletion. These labs do not complete TASK-01 or enable intrusive product actions.

- [ ] Review this architecture, license proposal and accepted user decisions.
- [ ] Run EXP-01/02/03/04/08/09/10/11 spikes with concrete logs and failure decisions; schedule authorized large/GPU/managed tests separately.
- [ ] Pin exact source/toolchain/image/gadget versions and licence notices; finish dependency egress review.
- [ ] Resolve domain registration/trademark before public API-group/event publication; maintainer owns registration/legal decisions.
- [ ] Generate production API skeleton/schema checks from reviewed contracts; publish capability claims only after tests.
- [ ] Run EXP-21/22 and inspect the pinned syscall engine/ABI/map implementation; keep unsupported metadata/argument modes unavailable.
- [ ] Qualify workload-impact rules and combination benchmarks under EXP-17/19/21/22; publish environment/coverage references and keep unsupported numeric predictions unavailable.

Exit: risky mechanisms demonstrated or explicitly excluded, no unapproved paid resources, all consequential unresolved decisions recorded. Planning artifacts can be reviewed before runtime experiments; the latter are not silently waived.

### TASK-02 — Multi-cluster control foundation

[ADR-081 owner proof](decisions/081-hub-owner-enrollment-proof.md) now supplies current online Pod/token/CSR observations before readiness. Compose them with trusted clean installation and durable enrollment/audit/signing/activation before exposing private forwarding. It does not complete the task or provide execution authority.

[ADR-080](decisions/080-private-hub-workload-protection.md) adds the private hub namespace admission/proof component. Complete clean-installation qualification, Pod/token/CSR proof and durable owner enrollment/signing/audit/activation before private forwarding. The current guard does not prove historical integrity; no whole task exit is complete.

- [ ] Implement hub/connector identity, enrollment, local ceiling and version negotiation.
- [ ] Implement configuration/local-control CRDs, accepted SQL projections/executions, immutable IDs, outbound poll/ack/records and fencing.
- [ ] Implement bounded capture history projections, keyed selector/settings indexes and immutable encrypted parameter snapshots with retained audience and independent expiry; no coupling of history eviction to active execution/accounting.
- [ ] Implement REQ-DB-001 through REQ-DB-005 logical tables/migrations, query contracts, canonical lock order, transactions, work leases, SQL outbox with object-audit gate and bounded connection pools. Keep grants/shares/intents out of CRDs.
- [ ] Implement storage-pool/budget configuration, bounded capacity accounts/reservations, transactional hub parent allocation and fenced prepaid local slices with conservative failure recovery.
- [ ] Implement authenticated submission provenance and separate resolved collection/sharing digests under REQ-EXE-001; cross-language canonicalization fixtures and late matching-grant binding. Prevent controllers/GitOps from substituting privileged execution identities.
- [ ] Freeze concrete manual pod/node/boot bindings in execution scope; cross-language digests and replacement/restart rejection under REQ-EXE-002.
- [ ] Produce internal OpenAPI, RBAC and admission tests; install hub plus two synthetic workload clusters.
- [ ] Add CaptureProfile structural schema, immutable publication/availability admission, catalog configuration projections and namespace/publisher identity checks; no SQL configuration writer.

Exit: disconnected/reconnected connector recovers work without duplicate intrusive starts; no hub-held admin kubeconfig; cluster identity binding and namespace/workload access controls proven.

### TASK-03 — Encrypted evidence and durable catalog

- [ ] Implement accepted ADR-036; qualify separate-Job encrypted scratch handoff, single-writer fencing and copy-ledger cleanup under REQ-EVD-005. No shared emptyDir fallback.
- [ ] Enforce REQ-EVD-008 bounded child-output handling, no uncontrolled secondary dumps/swap, hostile output-tree rejection and trusted publication metadata.

- [ ] Implement S3/KMS interfaces, streaming encryption, commit protocol, manifests and upload verifier.
- [ ] Reserve worst-case stored bytes/object count before acquisition; reconcile committed/partial/version/multipart charges and release only on verified deletion. Implement protected workload/context capacity and separate shared burst.
- [ ] Add content-minimized SQL cases/occurrences/artifact catalog, encrypted immutable outcomes, orphan/multipart reconciliation and regional rebuildable evidence-text index. Keep full manifests and extracted text out of SQL backups.
- [ ] Implement EvidenceRetentionPolicy reconciliation, privacy classification/purpose, first-acquisition age, inherited deadlines, deletion budget and policy-impact preview.
- [ ] Implement managed-copy inventory, absolute residual-backup/WAL horizon arithmetic, bounded memory text indexes (optional qualified expiry cohorts), expiration/tombstones, derived lineage, early erasure, restricted-processing state, hold/lock conflict checks and verified/overdue deletion from the first slice.
- [ ] Project per-artifact sensitivity, access cutoff, deletion due/state and scoped handling policy from the authoritative privacy/copy ledger; include overdue/unknown/restricted cases.

Exit: corruption/outage/restart tests pass; a committed artifact remains recoverable independently of CRD/index state.

### TASK-04 — Targets and dynamic trigger engine

- [ ] Implement precise resource units/reset behavior, Alertmanager episode/transition deduplication and content-free policy health explanations. Cover receiver restart, retry/new episode, missing samples and ancestor coverage.

- [ ] Implement whole-pod Deployment/StatefulSet targeting and internal runtime identity; all-authorized-replica observation under administrator caps, contributor-first capture and separate visible overflow. No container selection or ACL surface.
- [ ] Implement CRI logs, cgroup resource/pressure, probe/exit watches and authenticated Alertmanager input.
- [ ] Implement typed event/level expressions, pod/workload correlation, activation/rearm/Unknown semantics, bounded schedules/DST/missed slots, deduplication, activation acknowledgements and quotas.
- [ ] Add workload-wide dump rate/rolling-byte budgets spanning replicas/policies, bounded suppression aggregation and fresh-request checks.
- [ ] Implement immutable preset catalog/authoring resolution, one-time target pinning, incident-pod resolution and generation-aware readiness without rewriting GitOps-owned spec.
- [ ] Split detector readiness from per-action source Warming/Ready/Degraded coverage; arm authorized observation pods independently of incident selection under REQ-LIF-002.

Exit: changing policy generation arms correct nodes; restart/rotation/gaps produce accurate outcomes; no evidence leaks into control/event fields.

### TASK-05 — Generic evidence recipes

- [ ] Implement REQ-LIF-006 stopped-source grace inside existing capacity/authority, node-boot identity and full-versus-partial window provenance; target churn/revocation fault tests.

- [ ] Implement Kubernetes/process/log/file/network snapshots and bounded action DAG execution.
- [ ] Implement bounded process identity/socket-owner discovery projections and three packaged inspection diagnostics under REQ-GDE-002/003; no argv/environment enrichment.
- [ ] Implement confined pseudo-file access and safe runtime command adapter, initially disabled until grants exist.
- [ ] Implement named diagnostic endpoints, reusable administrator templates with scoped credentials/ports and Go pprof CPU/heap acquisition; add other Go profile types when application sampling prerequisites exist.
- [ ] Add aggregate pod/action/fanout scratch/output budgets, per-action approval waiting, cancellation and partial/indeterminate outcomes; ready-file completeness and named endpoint confinement.
- [ ] Add fair transfer/analysis scheduling, finite workload/node spools, impact circuit breakers and deadline/service feasibility checks before expensive starts.
- [ ] Implement REQ-CPR-001–005 shared typed composition compiler, default/override validation, namespace IDs, safe context deduplication, endpoint rewrites, aggregate scheduling and provenance. Implement REQ-SYS-001/002 qualified metadata/argument tracing, bounded rings/maps/rates and loss/accounting.
- [ ] Implement executionMode normalization/validation, separate source and incident graphs, finite manual sessions, per-incident snapshot idempotency/provenance and dependency semantics under REQ-LIF-001–005.
- [ ] Implement REQ-ASM-001/002 shared per-action/combined assessment after normalization, scoped quantity aggregation, current-rule/metric binding, alternatives and no-acquisition preview behavior.

Exit: Restricted/distroless/blocked-read/PID-reuse tests pass, with no host-identity fallback.

### TASK-06 — Packet capture and historical rings

- [ ] Integrate pinned Gadget node-local output, checked pcap syntax and CIDR/Pod/Service/Deployment/StatefulSet peer resolution.
- [ ] Implement generation-swapped follow maps without restarting healthy hooks, UID/freshness/IP-reuse protection and Service VIP/backend semantics.
- [ ] Implement verified network-header stripping, segmented encrypted rings, separate live/frozen/upload/parser budgets and loss accounting.
- [ ] Implement bounded plain HTTP/1 reassembly/framing and approved header projections; prove body/credential exclusion. Explicit raw prefixes support transport caps without privacy claims. Defer HTTP/2/TLS plaintext until separately qualified.
- [ ] Qualify CNI/encryption/dual-stack/NAT paths and stream encrypted pcap-ng artifacts.
- [ ] Implement short survey classification/projections, confidence per protocol/peer/process association, retained-rate/filter replay, qualified observation-point descriptions and bounded ring-sizing recommendations; run EXP-20.
- [ ] Qualify source continuity across trigger storms, window anchoring and copy-on-write frozen reservations; source lifetime is not an incident timeout.

Exit: EXP-02/03 and SC-NET-001 through SC-NET-005 pass; no application bytes in networkHeaders or body/credential markers in approved HTTP outputs; uninterrupted healthy peer update, measured gaps, ring/parser pressure and supported-profile matrix.

### TASK-07 — Identity, grants, sharing and audit

Implement accepted [ADR-059](decisions/059-unattended-policy-authority.md) under [team policy automation](../specs/policy-automation.md): standard human sessions and bounded team execution that survives creator departure. Configuration/eligibility and the initial SQL/encrypted acceptance components do not complete protected submission/source production, transactional spending or worker composition. No mandatory directory reader, stale human-claim extension or silent executor migration.

Current component scope and next wiring: [identity and ordinary eligibility](architecture/identity-eligibility.md), [permission acceptance](architecture/permission-acceptance.md) and its [test record](research/permission-acceptance-foundation.md). All task checkboxes below remain open until their complete integration and acceptance gates pass.

- [ ] Implement AccessBinding/PermissionSource CRDs, structural schema/explain documentation, status readiness, server-side apply/conflict behavior and delegated admission checks. Add read-only preview/explanation to the existing browser service.
- [ ] Implement protected namespace/workload metadata sources, exact exec/generic SAR inheritance and per-cluster identity/admission qualification.
- [ ] Implement retained audience provenance and ownership-change handling; run EXP-16 before enabling inheritance.
- [ ] Implement OAuth and namespace/workload ACLs, SQL grant state/transactional reservations, local prepaid permits and second-person step-up approval.
- [ ] Implement configurable finite policy-approval lifetimes and separate sensitive-observation session/rate/wire-byte reservations; never extend short permit freshness through a longer grant.
- [ ] Implement SQL EvidenceShare user/group recipients, projection, revocation and membership freshness.
- [ ] Separate immutable creator from personal/multiple owner-team management, pinned assignments, team departure/suspension and explicit historical transfer without budget/expiry reset.
- [ ] Implement optional capture/policy sharing declarations, immutable protected SharingIntents, bounded registration/publication reservations, per-selection reviews, parent/child revocation and replay-safe tombstones. Preserve concrete snapshots and raw-query separation.
- [ ] Add capture-time recipient/output preview and distinct collection/sharing progress; recurring count/expiry, Stop versus Revoke, and explicit renewal/resume under current authority.
- [ ] Build workload/preset, case/approval/sharing pages with one evaluator, grant reuse and bundled review, recipient preview, safe draft/retry handling and durable intent/result audit.
- [ ] Add bounded retention/rights-request operator workflows, separate retention authority and content-minimized processing reports; respect configured legal-exception mode.
- [ ] Integrate catalog publication rights, profile dependency/availability revocation and syscall pre-read observed-event grants; keep collection, sharing and raw-query purposes separate.
- [ ] Verify sensitive observation approval before arming, no-trigger budget exhaustion, source revocation and policy-versus-incident cancellation behavior.
- [ ] Integrate REQ-ASM-003–005 data/deletion explanations in existing approvals, sharing and accepted operation records; prevent classification downgrades, hidden-parent disclosure and new consent ceremonies.

Exit: EXP-08/12/16 and authorization/permission-management scenarios pass. Intrusive generic commands remain unavailable until this task passes.

### TASK-08 — Analysis and MCP vertical slice

- [ ] Implement get_http_headers over approved structured extracts, bounded records/cursors and capture-mode metadata; qualify sharing/client/privacy controls for this output.

- [ ] Implement acquisition/offline-analysis/publication Jobs, trusted pcap/basic file/log analyzers and exact-image staging.
- [ ] Implement discovery/extract MCP tools plus list_targets/list_diagnostics/preview_capture/get_capture/cancel_capture, expiring handles and idempotent capture-by-preview; result bounds/cursors/query handles and both client protocol paths.
- [ ] Materialize selected outputs only after commit, projection and complete lineage checks; extend request_capture/list_shares/revoke_share with SharingIntent references and bounded personal/team management views.
- [ ] Implement stable case-to-agent handoff, authorized baseline selection and actionable own-access/approval errors with current evidence deadlines.
- [ ] Implement REQ-HIS-001–004 Recent captures/Repeat capture, list_capture_history/get_capture_settings, history-based preview and non-authorizing repeat lineage. Validate idempotency, stale identities, mutable/deleted recipes, retention and 30-second active-effort goal.
- [ ] Implement REQ-GDE-001–006 deterministic playbooks, shared browser/MCP recommendation compiler, get_target_discovery/recommend_diagnostics, bounded draft/source lifetimes and existing-handle preview flow. Verify task effort and goal relevance in EXP-17/20.
- [ ] Implement offline pprof parsing, hotspot/call-tree extracts and authorized baseline comparison; distinguish runtime traces and incompatible units.
- [ ] Add search/index projection and case events/outbox.
- [ ] Implement catalog/card customization and Save as profile, list_capture_profiles/get_capture_profile, composition previews/history, syscall summaries/events/raw query and approval/retention parity; run EXP-17/21/22.
- [ ] Expose lifecycle categories in catalog, preview and history; show ongoing versus incident costs and missing/warming prehistory consistently in browser/MCP.
- [ ] Implement capture_assessment and artifact handling_notice parity across browser/MCP/GitOps projections, direct-query reminders, repeat reassessment and accessible compact warnings; run comprehension and stale-preview cases in EXP-17/18.

Exit: a trigger in either of two clusters yields encrypted evidence, authorized analysis, an event and a readable MCP case; a share with an otherwise ineligible colleague works and revocation stops access.

### TASK-09 — Native crash and live dump support

- [ ] Prove natural-core local admission uses single-use prewrapped keys, prepaid capacity and precommitted authority; remote outages never block the pipe helper while replenishing resources.

- [ ] Implement helper installation/ownership/drift/uninstall, node identity enrichment and crash limits.
- [ ] Qualify prompt natural-core rejection with prepaid local capacity, helper cgroup placement and storm overhead without remote calls on the crash path.
- [ ] Add native/Rust/Go symbolized analysis, build/mapping/companion fidelity, exact PID and logical process/descendant selectors, bounded serial multi-process batches, liveCore grant enforcement and provisional/refined signatures.
- [ ] Measure probe/reaping impact and incomplete large-core behavior; no default fatal signal action.

Exit: native crash and approved live dump work on qualified node profiles; unsupported profiles retain generic collection.

### TASK-10 — Runtime packs and deeper queries

- [ ] Qualify .NET; then Python, JVM and Node.js packs independently, with explicit version/architecture matrices.
- [ ] Qualify EventPipe, JFR/async-profiler, Python samples and V8 CPU profiles as distinct original formats with common bounded summaries.
- [ ] Add raw bounded memory/debugger/pcap tools and payload capture under separate grants.
- [ ] Run authorized GPU/100+ GiB experiments; ship CUDA/TLS plaintext support as experimental until each gate passes.

Exit: every advertised runtime/action has synthetic crash/live tests, licence/egress evidence and impact documentation. Unsupported packs do not block the generic platform release if explicitly excluded.

### TASK-11 — Production packaging and operations

- [ ] Implement REQ-DEP-001–005 and [ADR-063](decisions/063-small-deployment-alternatives.md): independently selectable small/external providers, local accounts/OAuth/step-up/recovery, local purpose-scoped keys/signing/PKI and explicit bundled PostgreSQL/evidence storage. Qualify the [selected candidates](research/small-deployments.md) before adopting exact versions; add canonical identity/key/provider contracts and real consumers together. [ADR-064](decisions/064-local-key-material.md) supplies the private wrapping/signing payload, crypto backends and generic browser credential ports. [ADR-065](decisions/065-local-key-service-boundary.md) adds private mTLS handler/remote facets and exact-authority coordination ports. [ADR-066](decisions/066-download-key-authority.md) adds a concrete SQL authority resolver and remote reader for the audited context-download batch. [ADR-067](decisions/067-protected-local-key-lifecycle.md) adds protected immutable Secret reads, durable additive rotation and mandatory bounded lifecycle checks. [ADR-068](decisions/068-download-worker-attestation.md) adds current Kubernetes worker proofs and immutable SQL proof binding. [ADR-069](decisions/069-download-worker-dispatch.md) adds audited dispatch, exact restricted Job/Pod binding and durable termination/retirement. Remaining key-purpose resolvers, protected profile acceptance/rollout, acquisition issuance/control/runtime, full pending/orphan cleanup, source enrollment/key administration/retirement, PKI, runnable bootstrap and installer remain unfinished.
- [ ] Package PostgreSQL TLS/Secret/preflight settings, the explicitly selected single-instance Helm bundle and one qualified external/HA failover profile; no implicit operator installation. Test migration interruption, PITR, backup/WAL retention, lost-commit recovery, primary/connector fencing and RecoveryBlocked runbooks.
- [ ] Qualify bundled store conditional writes, pinned ranges/checksums, versions/multipart cleanup, physical disk pressure, scoped credentials, restart and deletion. Test stable secret bootstrap, lost-key recovery, upgrades/uninstall and gradual provider migration without extending evidence retention or authority.

- [ ] Finish the officially supported Helm runtime installation: role templates/RBAC/NetworkPolicy/typed values, offline bundles, SBOM/signatures, read-only capability/prerequisite reporting, retention and recovery runbooks. The [foundation chart](installation/helm.md) now packages implemented CRDs; it does not complete this task. Keycloak is the first external browser/MCP provider; the requested local alternative remains to be implemented.
- [ ] Run EXP-17 usability/accessibility, EXP-18 privacy/retention and EXP-19 storm/quota/fairness tests; resolve mandatory workflow/deletion-control failures. Document operator GDPR responsibilities and external-client limits.
- [ ] Run full two-cluster fault/security/scale suite, no-egress image tests and managed-provider qualification.
- [ ] Establish vulnerability intake, dependency refresh policy, public docs and release ownership.

Exit: first production scope in [product](product.md) passes with published limitations; no evidence of implementation is inferred from this unchecked list.

## Milestones and dependencies

```text
M0 reviewed plan + feasibility spikes: TASK-01
M1 secure two-cluster evidence slice: TASK-02 → TASK-03 → TASK-04/05
                                      + TASK-07 → TASK-08
M2 incident-quality capture: TASK-06 + TASK-09
M3 expanded runtime/raw coverage: TASK-10, independently qualified packs
M4 first production release: applicable M1–M3 scope + TASK-11
```

Identity, sharing, encryption, no-call-home, usable workflows and privacy/retention are acceptance criteria throughout, not deferred to M4. Development can use synthetic fixtures before every runtime pack exists. Do not turn roadmap ordering into a claim that intrusive features are safe before the grant service is ready.

## Review and release gates

Future local gates: format/lint, unit/property/fuzz regression, controller integration, image/SBOM/licence scan, contract compatibility, offline e2e and synthetic runtime matrix. Name concrete Make targets when implemented. Pin CI services and deny public egress during runtime tests. Record actual exits and logs. Re-run affected gates after changes; never mark absent checks as passed.

A security review must cover privilege boundary, custom commands, file confinement, header sanitizer, grant accounting, sharing projection and offline analyzer escapes. A maintainer approves release scope, publication and cloud spending. No code is published by this specification task.

No calendar estimate is claimed before the high-risk spikes. This is a substantial platform with a privileged data plane and a security-sensitive control plane; task completion is measured by acceptance evidence, not file count.

## Accepted recording-save integration within existing tasks

- [ ] TASK-02/04: add recordingSaves policy scope/default/transition handling, bounded current-source inventory, typed recording-save/v1 acceptance/t0/idempotency and content-minimized SQL work/history projections.
- [ ] TASK-05/06: implement snapshot-only dispatch with current source identity, no recipe DAG traversal, original-window pinning, capacity/retention/grace handling, partial output and cancellation isolated from live sources.
- [ ] TASK-07: prove caller and original executor checks, reviewed sensitive-source save budgets, source-audience inheritance and independent per-capture sharing; no recurring-sharing inheritance or grant transfer.
- [ ] TASK-08: add passive MCP inventory/preview, existing submit/poll/cancel dispatch and distinct history/settings repeat; browser parity and incremental impact/privacy disclosure.
- [ ] TASK-03/11: implement the accepted encrypted scratch prerequisite, profile-specific readiness/remediation, isolated per-analysis PVC handoff, independent cleanup and failure qualification.

All items remain unimplemented. The new requirements are REQ-SAV-001–004; storage isolation remains REQ-EVD-005/008 under accepted ADR-036. No third database, broker, public permission API or new collector deployment is introduced.

## UX, interface and domain implementation handoff

The [interactive prototype](../design/ui/index.html), [surface catalog](ux/surfaces.yaml), [domain model](domain/README.md) and [outward contracts](interfaces/README.md) are completed design artifacts. Production implementation remains **not started**.

- [ ] TASK-01: review REQ-UI-001–007, REQ-DOM-001–005 and REQ-INT-001–005; validate precise public mappings before generating Go/CRD/database types. Confirm task studies and accessibility criteria.
- [ ] TASK-02: implement domain IDs/value types and authoritative repositories; shared browser/MCP application services, typed OpenAPI adapters, configuration draft/preview/current-rights submission and schema parity gates.
- [ ] TASK-03: implement artifact/copy/lineage projections with truthful read cutoff/deletion progress and no sensitive SQL fields.
- [ ] TASK-07: implement recipient-only projections, multiple manager teams, independent review and step-up, owner transfer, namespace permission preview and exact Kubernetes handoff.
- [ ] TASK-08: implement the inventoried responsive React/TypeScript console, evidence viewers, guidance/composition/history/save flows, async progress and MCP task ergonomics. Replace synthetic data and static controls with shared service projections; do not deploy the prototype as the product.
- [ ] TASK-11: run supported-browser, keyboard/screen-reader, zoom and participant studies; negative role/revocation tests; real OAuth/MCP transport tests; multicluster partial/offline/capacity scenarios.

Use `make design-check` for catalog/schema consistency and optional `make ui-check` for the synthetic prototype. These complement `make spec-check`; they do not implement the acceptance scenarios or runtime qualification gates.

## Live-watch implementation handoff

[REQ-LIV-001–006](../specs/live-watch.md) are integrated into the design and synthetic mockup; production implementation is **not started**.

- [ ] TASK-02: implement minimized LiveWatch control records, exact source binding, revisions/idempotency, prepaid view resources, finite idle/hard expiry and conservative recovery; no per-row database writes.
- [ ] TASK-06/10: qualify nonblocking live packet/HTTP/syscall approved projections, bounded scan/parser work and source-cohort reuse; preserve acquisition/snapshot priority and report loss/pairing/clock gaps.
- [ ] TASK-07: enforce viewer plus source executor/retained-audience eligibility at every delivery; no artifact-share inheritance, raw live content or automatic source expansion. Test region constraints and paused-view revocation.
- [ ] TASK-08: implement source picker/live console, bounded MCP/browser batches, filter/pause/close and explicit save-current workflow, short client row expiry and accessibility without focus theft.
- [ ] TASK-11: run storm/fanout/slow-client/failover, quota, cursor, privacy and both MCP profile tests below. Validate that measured live overhead cannot starve protected collection.

## Minimalist console handoff

The researched visual overhaul is integrated into the [63-screen prototype](../design/ui/index.html) and [design system](ux/design-system.md). It changes presentation and interaction hierarchy, not domain entities or public API contracts.

- [ ] TASK-08: implement the light section-based console, contextual capture navigation, shared tables/forms, essential review summary, optional disclosures and state-specific live controls under REQ-UI-007. Keep the prototype inspector out of production. Use the accepted static React build served by Go; preserve local assets and server-side authentication.
- [ ] TASK-11: qualify keyboard/screen-reader and zoom behavior, then run the task studies in [web-design research](ux/web-design-research.md). Check navigation discoverability and handling comprehension as well as speed.

Prototype checks do not complete these production tasks.

## Application/component architecture handoff

[REQ-ARC-001–007](../specs/implementation-architecture.md) and [ADR-042/043](decisions/README.md) refine the implementation baseline. Runtime implementation remains not started.

- [ ] TASK-01/02: implement role composition and catalog-mapped packages; review/generate internal DTOs and version negotiation; qualify JWS/key handling.
- [ ] TASK-02/07: implement typed local reservation/lookup, stable attempts, explicit SQL facets and receiver fencing; test lost responses, old epochs and duplicated collectors.
- [ ] TASK-05/06/08/09: implement disjoint action/source/snapshot/live/analyzer ports with qualified adapters; retain prepared natural-core special handling.
- [ ] TASK-11: add real import-graph checks once Go code exists and run each slice's runtime/fault acceptance. `make architecture-check` currently checks design/catalog/DTO/synthetic semantics only.

## Native download correction

- [ ] TASK-07/08: implement REQ-DLD-001–004 for every artifact kind, covering grant reuse, raw download review, authenticated native transfer/resume and browser/MCP handoff. C-14 owns ArtifactDownload; no new CRD or mandatory service.
- [ ] TASK-11: test packet files in Wireshark, exact core/executable inputs in GDB and all other native formats in appropriate local tools, plus checksum, large interrupted files, current rights, fair bandwidth and no managed plaintext caches. Run actual user task completion, not only tabletop consistency.

The earlier blanket file prohibition is superseded; original brief and historical review records remain preserved.

## User-task review corrections and remaining work

TASK-07 implements REQ-INV-001/002: paired capture/result decisions, commit registration, exact child grants, shared result pool, parent revocation and distinct acquisition/result exhaustion. TASK-08 exposes REQ-INV-003 consistently across browser/MCP/DebugCapture, conditional optional configuration, and immediate saving of already reviewed displayed defaults. TASK-11 must test the full capture → approval → committed artifact → local-tool outcome, not isolated request DTOs. `make investigation-check` checks paired synthetic contracts only.

[U03–U07 and U09–U11](reviews/user-task-review.md) remain open: bounded temporary watches, time-oriented search, private symbols intake, qualified postmortem access, multi-case investigation, trigger tests, real approval/support routing and portable batches. U10's misleading label is corrected but routing is still absent. These are findings/recommendations, not implemented first-release claims; acceptance and corresponding contracts/UI are required before marking them resolved.

The browser-session continuation implements code/PKCE sign-in, encrypted credential storage, coordinated refresh, current identity checks, logout and bounded credential cleanup under migration 00020. Migration 00021 adds current protected Kubernetes settings, finite SQL observations, runtime issuer/client/origin binding and irreversible shortening of existing session deadlines. Real Keycloak/PostgreSQL/OpenBao/HTTP and Kubernetes/SQL qualification passes; [scope and remaining deployment gates](architecture/browser-sessions.md). TASK-07 and S-01/S-02 remain open until protected bootstrap, independent-review/execution and public developer workflows pass together.
