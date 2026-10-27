# Decision records

[ADR-253 — Approval step-up sign-in](253-approval-stepup-login.md) adds an explicit console
sign-in path using current protected ACR settings and fresh authentication. The
existing signed-claim check still decides assurance; real-provider LoA qualification
remains pending. No migration or new credential.
- **ADR-255 — Encrypted parameterized capture history:** [Bounded immutable settings and faithful repeat](255-encrypted-capture-history.md); implementation in progress, native qualification pending.

[ADR-249 — Sensitive acquisition grants](249-sensitive-acquisition-grants.md) is S-04 increment
12 (12a, individual approval): an adHocCapture AccessGrant per reviewed packet/syscall plan that
needs review (a raw-byte filter predicate, now compiled with REQ-AUT-006 observation limits, or
every recording when the protected identity settings set `approvals.requireRecordingApproval`).
`request_capture` opens one review request and is refused with `ApprovalRequired` until an
approved, current grant covers the exact plan (capture UID, execution digest, data class, reasons,
requester); a distinct human with a current `action-approver` assignment decides it, and approval
needs an IdP step-up verified from the signed `acr`/`auth_time`. One finite result-access pool with
exact children for published artifacts of the approved capture; Migration 00097; `get_grant` and
the browser-only `list_reviews`, `decide_review`, `revoke_grant` with a console inbox. Policy
grants (12b) and observation spend remain open.

[ADR-248 — Manual packet capture end to end, network headers only](248-manual-packet-capture.md)
is S-04 increment 4: Inspektor Gadget's published tcpdump gadget, pinned by digest and loaded from
the collector image, records one Pod; the collector runs the hub-compiled libpcap program on each
frame (`x/net/bpf`), cuts frames at the transport header (gopacket) and uploads a bounded PCAPNG
(8 MiB) over its mTLS channel; the connector encrypts it with the ADR-244 producer and holds the
completion until the hub's collect exchange records it; publication rechecks headers-only.
Requests are accepted only when the target node reports the recorder. Migration 00098.

[ADR-247 — Guarded, group-ID, remote-cluster and workload permission sources](247-guarded-and-workload-permission-sources.md)
completes REQ-PER-003/005: `admissionEnforced` namespace sources need a live proof of the capacity
namespace label guard covering their keys; `groupID` values are validated against the identity
settings' configured `eligibleGroups`; namespaces of joined clusters are read from each
connector's continuous LIST+watch journal over the cluster-observation channel with versions that
change only with an observed value (unrelated writes keep assignments, A → B → A re-mints); and
`workloadMetadata` sources grant over single Deployments/StatefulSets under an opt-in workload
metadata admission guard. No migration.

[ADR-245 — Decision-time permission sources](245-decision-time-permission-sources.md) implements
REQ-PER-004: `kubernetesExec` and `kubernetesAccessReview` PermissionSources are accepted as
subject-free configuration, and before a capture, explanation or read hub-api asks the target
cluster's connector (existing regional query channel) to submit one SubjectAccessReview for the
request's human principal, mapped through a connector-local identity mapping record. An allowed
review mints one persistent assignment per source and principal (the capturing principal's
audience) and a per-Pod decision of at most `maxDecisionAgeSeconds`; a refusal or SAR outage ends it
at once; explicit denies still win; reads repeat the recorded review. Migration 00096.

[ADR-250 — Standby residency for regional work and unstarted acquisition](250-standby-residency-and-unstarted-acquisition.md)
fixes intermittent installed `OutcomeUnknown` starts: the hub router attached regional work to the
oldest standby exchange, whose 30-second residency cut the region's observations and stream
mid-run. Attach and target queries now take the standby with the latest residency end that
covers the work's deadline plus 3 s, and an idle standby that can no longer cover work is retired
so the region reopens at once. A start refused before any start effect reports the retryable
`AcquisitionNotStarted` naming `continue_acquisition`.

[ADR-244 — Native artifact types and larger saves](244-native-artifact-types.md) is S-04
increment 2: an artifact-type registry (pod status, PCAPNG, syscall JSON Lines, HTTP header JSON)
with media type, format, safe filename and coverage; typed expectations with verified
`actionLifecycle` provenance for ongoing saves; streaming native checks; a framed producer and
full verifier; ADR-166 streaming custody raised to 256 MiB/33 parts (migration 00095); and a
multi-frame `NativeResponseSource` whose transfer renews the delivery lease before a chunk write
with less than two seconds left. A 200 MiB synthetic PCAPNG is stored, verified and downloaded
whole and resumed on real PostgreSQL/S3; the installed worker path stays pod-status-only until
increment 4.

[ADR-246 — Node collector role and work channel](246-node-collector-role.md) is S-04 increment 3:
the `asservat node` DaemonSet in its own namespace (the only privileged Pod Security exception;
root, not privileged, `BPF`/`NET_ADMIN`/`SYS_RESOURCE`, host PID, four read-only hostPaths, no API
permission), off by default and guarded by the host file `/etc/asservat-disposable-host`. A
Pod-bound token with its own audience and an identity-free CSR enroll the process with the
connector (TokenReview plus live Pod/DaemonSet/Node and kubelet boot ID), which signs a 20-minute
leaf from an in-memory issuer. Long-poll work and 15-second status over TLS 1.3; one current
process per node; a capability probe (kernel, BTF, cgroup v2, BPF, TCX/tc, tracefs, host PID,
runtime, embedded Inspektor Gadget v0.57.0 runtime) reports `AdapterUnavailable` truthfully; node
ring/frozen/upload ceilings, with optional EvidenceBudgetPolicy `maxRingBytes`/`maxFrozenBytes`.

[ADR-241 — Log and resource triggers](241-log-resource-detectors.md) implements the detectors
ADR-230 paused, after the maintainer's 2026-10-26 decision that every specified feature ships: a
log policy's regional poll reads its Pods' containers through bounded `pods/log` GETs (≤ 32
containers, ≤ 4 MiB, sinceSeconds = eventWindow) and matches a literal, RE2 regexp or JSON field;
a resource policy lists the workload's `metrics.k8s.io` PodMetrics (cpuCores, cpuQuotaRatio,
memoryBytes as working set, memoryLimitRatio). Only counts and one second per Pod leave the region;
an unprovable Pod is Unknown for the poll. Regional connector RBAC: `get pods/log`,
`list pods.metrics.k8s.io`. Migration 00094 widens the detector CHECKs and adds the `overlong`
suppression reason. Cgroup-only metrics and stream filters stay rejected capability gaps.

[ADR-243 — Packet and syscall plans in preview](243-packet-syscall-plans-in-preview.md) is S-04
increment 1: `preview_capture` accepts one release-embedded builtin capture profile
(`network-connections/v1`, `syscall-activity/v1`) with typed edits and returns its
`action-lifecycle/v1` plan, hub-compiled libpcap filter program and digest, composition provenance
and `recorder-assessment/v1` assessment. Every such plan carries `RecorderUnavailable`;
`request_capture` refuses it before any reservation, and a composed DebugPolicy is refused at
compile time. libpcap 1.11.0 is a static archive linked only into the hub build (`libpcap` tag).

[ADR-242 — Namespace metadata permission inheritance](242-namespace-permission-inheritance.md)
accepts `namespaceMetadata` PermissionSources (explicit value map, `administratorManaged`) for the
hub cluster: the hub-worker LISTs and watches namespaces, keeps only digests of the configured keys,
and accepts one whole-namespace allow per granted namespace into the same audited SQL stream as the
explicit bindings. Every ownership transition is accepted in order; a relist keeps an assignment
only with an unchanged namespace resourceVersion; an unavailable source keeps its assignments but
grants nothing; explicit denies still win. The ADR-237 preview now evaluates source changes against
the accepted observation. Exec/access-review inheritance remains a separate decision-time increment.
No migration.

[ADR-240 — Retention impact preview](240-retention-impact-preview.md) is S-06 increment 11: the
browser-only `preview_retention_change` lets a current fleet operator submit proposed
EvidenceRetentionPolicy changes and see how many retained artifacts would be shortened per cluster
and class, how many would become unreadable or due for deletion at once, and the earliest new
access end and deletion dates, computed by the catch-up's own retained-obligation functions over
the current effective deadlines (at most 10,000 artifacts). Lengthening never moves a bound date;
artifacts needing unrecorded label history are Unknown; clusters whose source is not ready are
incomplete. Console `/retention-preview`. Migration 00093 adds the audit operation name.

[ADR-239 — Bounded recurring-policy sharing](239-recurring-policy-sharing.md) is S-06 increment 8:
a DebugPolicy's `spec.sharing` (≤ 8 recipients, `maxCaptures` 1–100, absolute `notAfter` ≤ 7 days)
is accepted by `activate_policy` only with `evidence:share` and an evidence-owner group of the
automation AccessBinding (the pinned management) and stored in the acceptance record; each admitted
capture claims one slot of a counter on the acceptance (migration 00092) and receives an ADR-235
instruction while under both limits, unstopped and the policy unchanged. `activate_policy` first
returns the review ("Repeated collections will be shared", recipients, limit, end) and accepts only
with `sharing_reviewed`; `stop_future_sharing` stops claims (claimed captures still publish), a
policy edit stops them too (no backfill); revoke-all = `revoke_share(sharing_intent_id)`;
`get_policy_status` reports the sharing state.

[ADR-236 — Recent captures and Collect again](236-capture-history-collect-again.md) is S-06
increment 6: migration 00089 records each accepted capture's cluster, namespace UID, workload UID
and origin at acceptance (no backfill); `list_capture_history` lists the last seven days of a
named workload's captures by its current UIDs to the requester and current retained-audience
members; `get_capture_settings` returns the accepted target, recipe, pins and requested retention;
`preview_capture(history_capture_id)` runs the ordinary preview with every current check. Console
"Recent captures" with "Collect again". Snapshots, digests, eviction and lineage are increment 12.

[ADR-237 — Permission impact preview](237-permission-impact-preview.md) is S-06 increment 10:
the browser-only `preview_access_change` lets a current fleet operator, or a configured previewer of
an installed delegation envelope within it, submit proposed AccessBinding/PermissionSource changes
and see, per workload scope (at most 1,000), whose Allow/Deny/Indeterminate decisions would change
and which assignment revisions decide them, using the real evaluator over the current accepted
projection; paged within 256 KiB. Unavailable data and unaccepted inheritance are Indeterminate,
never Allow. Console `/access-preview`. Migration 00090 adds the audit operation name.

[ADR-238 — Explicit share management, transfer and administrator revocation](238-share-management-transfer.md)

[ADR-238 — Explicit share management, transfer, administrator delegation and revocation](238-share-management-transfer.md)
is S-06 increment 9: `create_share` accepts an optional `management` naming the creator's own
current owner teams (or only the creator); the audited `transfer_share` lets a current manager hand
management to owner teams they hold, without changing creator, recipients or expiry. Operators of
the protected fleet administration are the scoped management delegation: they may assign any current
owner teams inside the artifact's retained audience (also to recover a Suspended share), list every
share management-only (`list_shares(view=administration)`, cursor pages, no recipients) and revoke
any share; none of this grants them a read. Migration 00091 (revision per change, trigger, listing
index, audit operation name).

[ADR-234 — Caller-only access explanation](234-access-explanation.md) is S-06 increment 7:
`explain_access(target_ref, operation)` over MCP and the browser route runs the real ordinary
evaluator for the caller's own access and reports Allow/Deny/Indeterminate, the unmet condition and
the caller's own contributing assignments; callers without an assignment on the target get one
uniform answer. Console "Why?" link on capture errors and blockers. Migration 00087 adds the audit
operation name.

[ADR-232 increment 4 — team management](232-concrete-evidence-share.md#increment-4-team-management)
pins the creator's owner teams (creator-only without a team, more than eight refused), lets every
current holder of a pinned assignment list and revoke the share, and returns `revision`,
`created_by` and `managed_by` in `list_shares(view=owned)`. No migration or new grant.

[ADR-235 — Capture-time sharing of the published result](235-capture-time-sharing.md) is S-06
increment 5: `preview_capture` accepts `sharing` (≤ 8 recipients, optional `notAfter`); admission
requires the requester's evidence-owner authority and stores one instruction on the accepted capture
(migration 00088); the catalog publication transaction materializes exactly one ADR-232 share, and
`get_capture` reports Pending/Shared/SharingUnavailable separately. Console "Share results with…".

[ADR-233 — Recipient native download of a shared artifact](233-recipient-native-download.md) is
S-06 increment 3: the download authorizer consults a recipient's share of exactly the scope's
artifact and version only after ordinary eligibility refuses and before the catalog read, re-reads
it at the final check and at the existing 30-second response reconstruction, and charges the
workload's existing download allocation. No migration or new grant.

[ADR-232 — Concrete evidence share of one stored artifact](232-concrete-evidence-share.md) is S-06
increment 1: `create_share`/`list_shares`/`revoke_share` over MCP, one `evidence_share` row per
share with derived Active/Expired/Revoked/Suspended state (migration 00086), pinned owner
assignments, and a recipient branch consulted only after ordinary eligibility refuses and before
any evidence lookup. Recipients read `get_case`; native download stays refused. Increment 2 adds
the console Share panel (recipient preview, copyable case link) and the `/shares` page over the same
browser operation route.

[ADR-231 — Alert trigger from the in-cluster Alertmanager API](231-alert-detector.md) lets existing
Prometheus and log-stack alert rules trigger captures: the regional connector reads the cluster's
configured Alertmanager v2 API on the existing 15-second poll (no hub endpoint or credential),
maps alerts to Pods by `namespace`/`pod` labels and reuses the probe level (migration 00085).

[ADR-230 — Probe-failure trigger; log and resource detectors paused](230-s03-detectors.md) gates
every S-03 detector (AGENTS.md items 1–11): the probe detector reads kubelet Unhealthy Events in the
existing regional poll (one Event LIST per probe policy, `list events` on the regional connector,
migration 00084); log (`pods/log` polling) and resource (metrics-server) detectors are paused for a
maintainer decision, with the alert detector as the recommended cheaper route.

[ADR-228 — Restart-triggered policy captures](228-restart-triggered-policy-captures.md) is the
first S-03 increment: hub-held exit-detector DebugPolicies, MCP/browser activation, a 15-second
regional restart poll and migration 00082's deduplicated, workload-budgeted trigger ledger; captures
reuse the S-02 pipeline under the policy executor.

[ADR-229 — Policy deactivation and console](229-policy-deactivation-and-console.md) adds
`deactivate_policy` (team-maintainer authority, clears the current acceptance, no refund, no
reactivation of an unchanged revision; migration 00083), the console `/policies` page and
per-policy capture goroutines off the poll loop.

[ADR-227 — Supported upgrade and image-only rollback](227-upgrade-and-rollback.md) adds a
database-declared schema compatibility floor, an `installer-upgrade` migrator and one installation
release record that replaces the per-component image pins; the key service, publisher and federation follow it too, while download workers and the regional connector stay on the original image.

[ADR-226 — Automatic re-activation after a lossless PostgreSQL restart](226-lossless-restart-reactivation.md)
records the system identifier and WAL timeline at activation (migration 00080) so a restart
re-activates by itself while restores, new databases and other clusters stay blocked.

[ADR-225 — Context capture failure causes](225-context-capture-failure-causes.md)
records `targetGone`/`denied` capture outcomes (migration 00079) shown as action
phases TargetGone/Denied, and returns TargetGone for a request whose reviewed Pod
is gone.

[ADR-224 — Remove download-owned browser refresh](224-remove-download-refresh-owners.md)
supersedes ADR-114: browser prepare is the ordinary audited call, the content
GET reads the current session and fails closed when it needs refreshing, and
the console resumes with Range. Migration 00078 drops the owner tables.
Unit checks pass; real SQL and installed qualification are pending.

[ADR-223 — Lost regional completion replies end Indeterminate](223-lost-regional-completion-reply.md)
does not import a committed regional artifact whose reply was lost; the
hub-worker deletion sweep's existing login marks elapsed capture deadlines so
such captures end Indeterminate and keep their charge until normal deletion.
Unit checks pass; real SQL and installed qualification are pending.

[ADR-222 — Consolidate SQL credentials within the hub process](222-hub-process-sql-credentials.md)
uses exact grant unions for ordinary public duties and owner identity/routing,
with separate pinned/nested readers and unchanged process/connection boundaries.
Component checks and independent reviews pass; integrated real SQL and installed
qualification remain pending.

[ADR-221 — Enroll admitted worker identity independently](221-admitted-worker-identity-enrollment.md)
removes the certificate-specific human-request registration and forwarding path.
Current admitted parent, workload, signing and audit checks remain; certificates
confer no evidence authority. Component checks pass; installed qualification is pending.

[ADR-220 — Response-owned ordinary download permissions](220-response-owned-download-permissions.md)
selects a fixed 30-second reconstruction cadence within one original response and
removes duplicate native-reader authorization through an exact short handoff.
Identity, delivery/native bounds and current SQL permission/safety fences remain;
known changes may deny earlier. Component race checks and independent source
review pass; real SQL suspension and installed streaming qualification remain
pending.

[ADR-219 — Share acquisition for approved pod-status reads](219-shared-approved-acquisition.md)
reuses the isolated acquisition lifecycle with a closed download/query parent,
independent approved-read authority and shared aggregate capacity. Component and
console checks pass; integrated SQL and installed projection qualification remain pending.

[ADR-218 — Consume download preflight observations at their phase](218-consumed-download-preflight.md)
consumes readiness at its check and plan freshness through acknowledged session
reservation. Original request/authority and session limits remain, with current
configuration checked at worker effects. Implemented; affected race tests pass,
with installed qualification pending.

[ADR-217 — One SQL login for API execution facets](217-api-execution-role.md)
consolidates the same hub process's read, preparation and recording credentials
and pools. Typed ports, exact union grants, current SQL effect checks and the
32-connection process ceiling remain. Implementation and qualification are in
progress; this is not an installed availability claim.

[ADR-216 — One authority observation for a context start](216-request-owned-context-start-observation.md)
removes repeated complete authority reads within the same original five-second
start. Current SQL effect checks, exact-target acquisition, cancellation and
original deadlines remain. Affected race and selected real SQL suites pass;
native55 reaches capture and publication but fails download preparation.

[ADR-215 — One SQL login for the hub's metadata readers](215-hub-metadata-reader-role.md)
consolidates seven same-process metadata credentials and pools while retaining
their typed adapters, exact union grants and existing SQL checks. Other privilege
boundaries and the hub connection ceiling remain. Implementation and
qualification are in progress.

[ADR-214 — Reuse a bounded download policy observation](214-bounded-download-policy-observation.md)
selects a 60-second download-only policy observation instead of repeating its
Kubernetes protection read at each helper call. Raw administrative reads, original
request deadlines and current SQL effect checks remain separate. Its request-owned
refinement removes repeated full worker authorization within one original
five-second operation. Implementation
and complete-path qualification are in progress.

[ADR-213 — Storage readiness at consumption](213-storage-readiness-at-consumption.md)
adds a bounded consumption phase to the same request-owned readiness wait:
only a valid unchanged storage selection with insufficient margin may wait for
a fresh observation, within all original authority cutoffs and one demand
attempt. Implementation and complete capture race checks pass. Native48 included
the change and reached acquisition/publication, without establishing that
consumption polling caused that success; complete installed qualification remains open.

[ADR-212 — Remaining interval before one-use API preparation](212-api-preparation-remaining-interval.md)
requires one second remaining before the first preparation insert and preserves
expired prepared rows as passive no-create uncertainty. No authority interval,
key attempt or acquisition is renewed. Real PostgreSQL/S3 boundary checks pass.
Native48 observed a headroom refusal followed by a later first preparation and
acquisition before its original deadline. Native49 also recovered the accepted
capture through fresh authorized capture/case reads; native download and the
complete installed lifecycle remain unqualified.

[ADR-211 — Return a completed target query to its original standby interval](211-completed-query-standby-transition.md)
separates a completed pre-work query's socket deadlines from the unchanged
standby residence, with exclusive query ownership and permanent closure after
failure. Implementation and actual HTTP/2/race checks pass; the complete
installed investigation lifecycle remains unqualified.

[ADR-210 — Installed processing changes by a privacy operator](210-installed-processing-changes.md)
adds the console route `POST /api/v1/processing/changes`, the hub SQL purpose
`processing-decision` and the hub-api read of the capacity processing source,
so the configured operator initializes processing before the first capture.
Installed initialization passes; the release lane and browser-session cleanup
remain unimplemented.

[ADR-209 — Two context-start standbys per hub owner](209-two-context-start-standbys-per-owner.md)
was withdrawn: the installed per-cluster standby limit is one, so a second
regional exchange per owner was refused; the change was reverted.

[ADR-208 — Opening limiter for context-start Kubernetes clients](208-context-opening-client-burst.md)
gives the explicitly selected opening, audit, retention, capacity and lifecycle
clients 50 QPS/burst 100 (from 20/20); checks and deadlines are unchanged.
Native48/49 reached installed acquisition and publication; sustained availability
and the complete installed lifecycle remain unqualified.

[ADR-207 — One native proof bracket for context-start setup](207-context-setup-proof-bracket.md)
implements setup composition within the original bounds, preserving closing
native checks and both owner authentications. Native48/49 exercised it through
installed acquisition and publication; successful opening latency, sustained
availability and the complete installed lifecycle remain unqualified.

[ADR-206 — Bounded approved pod-status projection reads](206-bounded-context-projection.md)
defines the accepted implementation contract for ordinary browser/MCP reads of
captured status: fixed text projection, independent read authority, original query
deadlines and separately charged acquisition batches. Component foundations are
implemented; production composition and installed qualification remain pending.

[ADR-205 — Installed context deletion](205-installed-context-deletion.md)
deletes expired context evidence from the hub-worker: three SQL logins, a due list, the operator's
own evidence delete credential, a deletion signing key in Transit and the acknowledged deletion record.
The composition merged in PR #41; installed expiry, failed-cleanup recovery and
charge release remain unqualified.

[ADR-204 — Installed native downloads](204-installed-downloads.md)
runs download workers in their own hub-cluster namespace with the profile source beside them, pins
one hub-local path in the owner input, gives workers their own evidence read credential, accepts
worker configuration in the hub-worker and adds acquisition unwraps and a downloads token.
Provisioning and configuration acceptance pass in the installed test; native
download and its installed lifecycle remain unqualified.

[ADR-203 — Installed publisher](203-installed-publisher.md)
deploys the publication verifier from `installer-continue`: its own OpenBao Kubernetes login for a
private audit Transit key and a verifier PKI role, an in-process verifier certificate, operator
evidence-read and audit credentials, and topology pins read from the guarded cluster catalog.
Scoped SQL/S3 checks pass. Native48/49 record installed verification,
audit acknowledgement and catalog publication. Native49 also recovered the
accepted capture and completed fresh authorized capture/case reads; native
download and the subsequent installed lifecycle remain unqualified.

[ADR-202 — Public API exposure](202-public-api-exposure.md)
lets the operator expose the promoted hub-api's public port on its own NodePort or LoadBalancer Service,
TLS passthrough only, so installed browsers and MCP clients can reach it.

[ADR-201 — eBPF CPU profiles for every runtime](201-ebpf-cpu-profiles.md)
takes CPU profiles for Java, Python, Node.js, .NET, Ruby, PHP and native code from one pinned
OpenTelemetry eBPF profiler in the node collector, keeps only the selected pod's samples before any
output, and leaves allocation and lock profiles to Go pprof and JVM JFR.

[ADR-200 — On-demand capacity refresh](200-on-demand-capacity-refresh.md)
refreshes a workload's binding (binding, root source, permission stream, fleet trust and retention source observation current for 30 seconds since the 2026-10-23 revision) when a capture preview,
request or download needs it: admission records a short demand, the hub-worker reconciles demanded
workloads first, and admission waits within its original deadline.
SQL and installed refresh checks pass; later storage reads still require their
original freshness and selection margin.

[ADR-199 — One source read at each end of the executor proof](199-executor-proof-source-reads.md)
reads the guarded connector source once when the executor's cold proof opens and once when it closes,
checking the owned process and the attestation against those reads instead of six source reads, so
the installed proof fits its five seconds at the unchanged 20 QPS clients.

[ADR-198 — Installed key service](198-installed-key-service.md)
installs the ADR-176 key service as its own hub Deployment: the continuation generates the root key once,
three permanent SQL logins ride in their own projection, connectors resolve from staged SQL profiles
instead of startup pins, and the regional offer carries the key-service endpoint.

[ADR-197 — Regional capacity](197-regional-capacity.md)
admits a regional cluster into capacity through append-only per-cluster qualification rows and an
additive pool revision, uses the v2 holder observation path for regional clusters only, and installs the
region's probe namespace and selector guard before ungating. The spike and
installed regional capacity checks pass; the complete investigation workflow
remains unfinished.

[ADR-196 — Regional cluster join](196-regional-cluster-join.md)
adds a hub-side join command fed by a public join record from `installer-cluster`, a hub-api process
restart on catalog change (API Pod replacement is guarded), the regional executor layout before
ungating and the owner's native L4 Service; regional capacity and the key service get their own ADRs.

[ADR-195 — Installed hub retention source](195-installed-hub-retention-source.md)
runs the retention reconciler, acceptance, catch-up and lifecycle publication as a fifth hub-worker
child with four new SQL purposes, its own guard and projection, and a baseline policy created from
required chart values, so the hub retention source every topology names can become Ready.

[ADR-194 — Promoted owner inputs](194-promoted-owner-inputs.md)
gives every input of the promoted hub-api launch a producer: opt-in promotion settings, derived keys read
back through the inspection token, fixed worker configuration, worker namespace and download environment
sources, an empty retention topology list, and the public projection reference checked at startup.

[ADR-193 — Installed federation and regional cluster enrollment](193-installed-federation-and-regional-enrollment.md)
authorizes cluster enrollment through the fleet operator's audited bootstrap issuance, derives federation
peers from SQL, provisions the federation in the hub continuation and adds an `installer-cluster` CLI whose
connector enrolls credential generation 1 in-band.

[ADR-192 — Capacity readiness before download paths](192-capacity-before-download-paths.md)
derives capacity identities from the public role setup so replays match the committed claim,
lets capacity become ready with zero download paths, and moves the first download path into
regional provisioning with the connector.

[ADR-191 — Worker projection writes under one retained bracket](191-retained-bracket-projection-writes.md)
reads the resource journal once per worker projection publication, through the retained
handover bracket, and writes its claim and receipt as CAS against that read.

[ADR-190 — Capacity readiness around the promoted owner launch](190-capacity-readiness-and-promoted-owner.md)
initializes capacity before the single promoted owner launch, lets the hub-api read the
capacity audit profiles at runtime instead of pinning them in its input, and publishes the
capacity projection after the launch.

[ADR-189 — Installed permission stream](189-installed-permission-stream.md) runs the
permission reconciler and authority audit publisher as a supervised hub-worker child,
with an installer-applied permission guard, two hub-worker-only SQL purposes and an
`authority/v1/` audit scope, before capacity initialization.

[ADR-188 — Configuration role proof after the SQL locks and the bridge](188-configuration-role-post-lock-proof.md)
keeps the full source recheck after the SQL locks before `CREATE ROLE` and lets the receipt
write reuse it, cutting one configuration role from 118 to 83 API requests. The continuation
waits after the guard bridge until the released Deployment controllers' status writes land.

[ADR-187 — Replay after the guard bridge](187-replay-after-guard-bridge.md) computes the
bridge's retained guard from the original plan and journal receipts, so read-only handover
readers, the bootstrap hook and a continuation rerun work after the bridge while every effect
path keeps the original guard.

[ADR-186 — Operation-scoped public role proof](186-operation-scoped-public-role-proof.md)
scopes one current proof to each public runtime role operation, because six full proofs
per role (about 141 API requests) cannot fit the original five-second claim window at 20 QPS.

[ADR-185 — Public sources and the cluster catalog](185-public-sources-and-cluster-catalog.md)
replaces the owner input's fixed regional clusters with a guarded, administrator-written
cluster catalog verified against SQL connector activation at start, fixes per-cluster
source slot names for the owner Role, and adds a public sources phase to the continuation.

[ADR-184 — Promoted owner on its first launch](184-promoted-owner-first-launch.md)
produces every Native and Public owner input before the first owner projection claim,
so the one launch is already promoted: backend logins become identity purposes, public
roles run before launch, and operator credentials sit in a separate rotatable Secret.

[ADR-183 — Installer runtime continuation](183-installer-runtime-continuation.md)
adds `asservat installer-continue`, an in-cluster Pod under the chart's runner account that
runs the existing post-activation producers in phases inside the original 30-minute journal,
publishing exact provider recipes to an outbox and waiting for an operator-written inbox;
`asservat installer-provider-apply` applies recipes with the operator's own credentials.

[ADR-182 — Installed owner promotion](182-installed-owner-promotion.md)
promotes the installed, provider-authenticated hub-api from identity-only to native backend
and public layers, each enabled only by a positive projection receipt and read from its own
fixed projection root, on fixed ports 9444/9445, with provider authentication for every
public purpose and no static tokens.

[ADR-181 — Asynchronous publication verifier](181-asynchronous-publication-verifier.md)
moves `ContextPublisher` into a dedicated hub-cluster `asservat publisher` process with
read-only evidence access, a `verifier` key-client certificate and an attempt-scoped,
bounded verification unwrap authority; it polls stored unpublished captures. hub-api keeps
no unwrap and the key service no ciphertext.

[ADR-180 — hub-api public composition](180-hub-api-public-composition.md)
enables the browser/MCP/download layer only through an optional installer-owned
`OwnerDeployment.Public` section: governed, verified per-purpose public SQL pools,
Keycloak-profile identity with derived MCP/download audiences, per-cluster hub-held
capability and work trust, context-start target queries and selector-free retention.

[ADR-179 — Outbound-only first installed profile](179-outbound-only-first-installed-profile.md)
keeps the hub reading only its own cluster. Evidence store and download workers declare
the hub region; the capability is hub-held. Target resolution is answered by pre-work
queries on the context-start exchange, and selector-based retention or local sources
fail closed until delegated label facts exist. `WorkerAPIs` and the legacy capacity observer are fenced
to the hub cluster.

[ADR-178 — Delegated connector source on context start](178-delegated-connector-source-on-context-start.md)
keeps hub-api away from regional Kubernetes APIs: the context-start exchange carries
numbered source probes answered by the region within an ADR-150-style bracket, hub-api
checks them against installed pins and the SQL49 registry on its `native-read` login,
and hub-to-regional download-worker proofs are fenced and later delegated.

[ADR-177 — Hub SQL connection governor](177-hub-sql-connection-governor.md) keeps one
NOINHERIT login per purpose (the schema pins `session_user`) and caps physically open
connections per process at the specified 32, with hot and cold purposes, so the full
S-02 hub (about 55 purposes) fits.

[ADR-176 — Artifact keys through the local key service](176-artifact-keys-local-key-service.md)
supersedes ADR-174's OpenBao wrapping, which no unwrap path could read: collectors wrap
through the local key service under attempt-scoped authority (three wraps per prepared
execution, bound to the executor's connector leaf).

[ADR-175 — Capacity token by TokenRequest](175-capacity-token-request.md) has the
connector's own Pod-bound credential mint an unbound, 600-second capacity token in
memory under exact admission. The API server refuses to bind it to a Pod of another
account, as the first native run showed.

[ADR-174 — Regional context-start composition](174-regional-context-start-composition.md)
composes ADR-171 context start into the product connector process: a delegated
read-only recovery purpose for verify-only work trust, encrypt-only OpenBao Transit
wrapping, a fixed capacity token file (delivery is an open installer decision) and
pinned hub owners. Component-tested; native qualification pending.

[ADR-173 — Work-scoped process observation](173-work-scoped-process-observation.md)
lets one verified work reuse its single complete regional process observation for
all start operations until its original deadline, never renewed; capacity, guard and
CAS checks stay current. The connector-Deployment executor's local start now passes
natively in 2.57 s of 5 s.

[ADR-172 — Delegated owner discovery](172-delegated-owner-discovery.md) lets the
regional process discover and authenticate hub owners without hub SQL. The federation
channel answers owner candidates and the hub's own authentication facts; the region
verifies its actual TLS session against them and dials one pinned endpoint with exact
owner names. The federation process composes the hub-api's owner reads under a
read-only role (ordinal 56) and the identical guard plan. Component-tested;
installer projection, regional composition and native qualification pending.

[ADR-171 — Hub-run context execution](171-hub-run-context-execution.md) moves the
API context runner and all its SQL/authority ports to the hub. The region answers
only cluster-local operations for a verified signed work, and captures, encrypts and
uploads in place, so plaintext and data keys never leave it. Implemented; the
native public journey passes on this path and the legacy identity-question
frames are removed.

[ADR-170 — Federation compartment](170-federation-compartment.md) moves
connector-facing hub duties into a separate process kind outside the 32-connection hub
budget and adds eight permanent connector duty roles (ordinals 48–55) to the
fixed public runtime layout. All 41 roles pass the
[real PostgreSQL role matrix](../../test/results/adr170-roles-1/result.json). The
product `hub-federation` and regional `connector` processes
[pass as Pods in two clusters](../../test/results/adr170-product-native-10/result.json)
with synthetic setup roots; installer provisioning is pending.

[ADR-169 — Delegated regional lifecycle channel](169-delegated-regional-lifecycle-channel.md)
lets the outbound regional process supply ADR-153 phase observations as
delegated proof over one ADR-168-authenticated full-duplex HTTP/2 conversation,
while the hub keeps every effect. It also delegates source staging and leaf
registration. The [two-cluster native fixture](../../test/results/adr169-direct-native-4/result.json)
passes with no hub connector SQL credential in the regional Pod; production
processes are pending.

[ADR-168 — Rotating cluster enrollment credential](168-rotating-cluster-enrollment-credential.md)
records the accepted outbound-only restart identity: a per-profile Ed25519 key in
one protected workload-cluster Secret, exporter-bound possession proofs that only
admit ADR-126/153 process enrollment, 7-day default validity with 24-hour
rotation, idempotent two-phase rotation, fork fencing and revocation. Migration
00060 (streaming custody moves to 00061). Domain, SQL, transport, rotator and Secret
store components pass; audit, hub composition and installed qualification pending.

[ADR-167 — Phase-bounded context download continuation](167-phase-bounded-download-continuation.md)
ends a continuation that produced a new enrollment as Preparing, keeps a
registration whose enrollment exchange is in flight, and hands acknowledged
prepared facts once to the same process's metadata cache. No identity bound is
stretched. Component regressions and the fixture journey (native36/37) pass; installed qualification remains pending.
[ADR-166 — Bounded streaming custody](166-bounded-streaming-custody.md) adds one
shared multipart path for native outputs above 8 MiB, initially qualified to
128 MiB: plan-bound registration, atomic final plus temporary multipart charges,
a one-use create/complete journal (migration 00061), ranged ciphertext
verification and inventory-proven cleanup. Small-object behavior is unchanged.
Storage components pass on real PostgreSQL/SeaweedFS; profile composition pending.

[ADR-165 — Original observation capability selection](165-original-observation-capability-selection.md)
lets a fresh provider-installed root select `owner-observation/v2` before its
first claim, binds it through every journal/plan/selection/deployment validator
without changing v1 bytes, and derives owner/HWORK participant pins from the
same native brackets. Component gate passes; no runtime selection.

[ADR-164 — Passive convergence of the original owner launch receipt](164-owner-launch-receipt-convergence.md)
separates a pending original launch from current identity authority, preserving
the original startup interval and requiring complete post-wait verification.
Implementation is staged; corrected qualification remains pending.

[ADR-163 — Original-work transport observation lease](163-original-work-transport-observation-lease.md)
retains one complete exact peer observation for correctly ordered exchange frames (identity frames, operation frames since ADR-171),
with original expiry, joined cancellation and full final peer validation. Human
identity and application effect checks remain current. The old amplification
regression fails as expected; component and native qualification are pending.

[ADR-162 — Read-only finalization of original owner projection effects](162-owner-projection-read-only-finalization.md)
selects mandatory independent verification after each original bounded effect.
Known identities and uncertain spend remain binding. The protocol is implemented;
component and native qualification are pending.

[ADR-161 — Separate fleet freshness from restrictive authority locks](161-fleet-observation-separation.md)
adds a version-bound positive observation, original pre-read basis and fixed SQL
producer functions. All 31 focused native SQL cases, 265 race-test parents and
87 initial-installation cases pass, together with all 176 full-fleet cases and
three actual database recovery phases. Remaining custody/full-Go and installed availability remain pending.

[ADR-160 — Purpose-separated context service assembly](160-public-context-service-assembly.md)
adds fixed preview/resolution credentials and one shared capture/case/download
assembly. Component and native role checks pass; installed enablement remains
pending.

[ADR-159 — Complete owner projection preflight across the SQL lock](159-owner-projection-split-preflight.md)
combines overlapping projection reads and selects the private journal after
current locked admission. Post-claim and final checking retain their original
bounds. Component qualification passes; installed qualification remains pending.

[ADR-158 — Owner startup critical sections](158-owner-startup-critical-sections.md)
moves native preflight before the retained recovery lock while preserving exact
post-lock source checks, final checking and original deadlines. The implementation
and regression tests pass component and real SQL qualification; installed startup
qualification is pending.

[ADR-145 — Independent capacity probe](145-independent-capacity-probe.md)
adds an original account/UID-bound dry-run branch to the private namespace guard.
It grants no persistent capacity writes; qualification is recorded in progress.

[ADR-144 — Cluster-local observations](144-cluster-local-observations.md)
adds a bounded local observation transport and an explicitly selected owner TLS
bootstrap profile. Component checks pass; remote exchange, opted provider signing
and installed multi-cluster operation remain unqualified.

[ADR-140 — Protected runtime producers](140-installed-public-runtime-producers.md)
adds fixed post-activation credential provisioning. The configuration-role
component is integrated for qualification; generated installation, command
wiring and the complete public runtime remain in progress.

[ADR-139 — Shared native/context-start listener](139-shared-native-context-start-listener.md)
adds closed dispatch on the accepted native port and waits for every owned child
at shutdown. Focused tests pass; actual regional exchange qualification remains
tracked in the progress record.

[ADR-136 — First-context native content](136-first-context-native-content.md)
connects approved context downloads to regional workers and authenticated HTTP
content. SQL53 adds the fixed content-preflight audit classification; integrated
and real-service qualification are tracked in the progress record.

[ADR-137 — Official Helm bootstrap](137-official-helm-bootstrap.md) packages the
four initial-installation commands, pinned public inputs, private-registry
credentials and terminal-only resume. The optional hook starts no public service.

[ADR-138 — Public context endpoint composition](138-public-context-endpoint-composition.md)
joins session, browser, MCP, console and native content handlers around the same
audited operations. Protected startup and installed qualification remain pending.

[ADR-135 — Live regional API context start](135-live-regional-api-context-start.md)
connects the original accepted request to a connector-originated HTTP/2 stream,
with purpose-separated work signatures, current identity round trips and joined
cancellation. Integrated qualification and protected deployment prerequisites
are tracked in [implementation progress](../implementation-progress.md).

[ADR-133 — Positive managed setup-copy closure](133-positive-bootstrap-copy-closure.md) adds fresh-v3 original cleanup claims, permanent name protection and exact copy removal after positive handover and credential retirement. Legacy formats remain unchanged; native v3 qualification is pending.

[ADR-134 — Explicit capture continuation](134-explicit-capture-continuation.md)
adds the deliberate same-key `continue_acquisition` branch for browser/MCP and
the console. Accepted replay stays passive; uncertain execution preparation
cannot generate keys again. Component qualification is recorded in
[implementation progress](../implementation-progress.md).

[ADR-132 — Capture-intent writer lifecycle](132-capture-intent-writer-lifecycle.md)
adds atomic per-workload audit reservations, irreversible write/read attempts
and separate read-only reuse of completed acknowledgements. SQL52 is integrated;
real-service qualification, protected backing provisioning and public runtime
composition remain tracked in [implementation progress](../implementation-progress.md).

[ADR-127 — Current processing decisions and complete native placement](127-current-processing-and-download-placement.md)
adds durable context-processing restrictions, prepaid release decisions and
current client/route checks for metadata and native downloads. SQL50 is
integrated; measured qualification, deployment provisioning and finite history
retirement remain tracked in [implementation progress](../implementation-progress.md).

[ADR-131 — Trusted bootstrap input producer](131-trusted-bootstrap-input-producer.md)
adds static installation inputs, guarded private bootstrap state and generated
preparation projections, plus finite SQL manager creation and retirement.
Command composition, native full bootstrap and final credential-copy deletion
remain tracked in [implementation progress](../implementation-progress.md).

[ADR-126 — Automatic connector process identity and renewal](126-connector-process-identity-and-renewal.md)
adds paired process-owned credentials, stable logical accounting, exact active
leaf lookup and separately acknowledged backing renewal. SQL49 components are
integrated; native qualification, finite retirement and installed connector
composition remain tracked in [implementation progress](../implementation-progress.md).

[ADR-130 — Bounded first-installation schema administration](130-bounded-initial-schema.md)
adds a separate private migration role, the binary's exact embedded migration
bundle and original database-incarnation claim. It grants no recovery or runtime
activation authority. Measured qualification and bootstrap gaps remain in
[implementation progress](../implementation-progress.md).

[ADR-129 — Original installation handover](129-initial-activation-handover.md)
adds one-use Pod launch, a separate passive SQL history login and eight ordered
cleanup acknowledgements. Native qualification remains separately tracked in
[implementation progress](../implementation-progress.md).

[ADR-128 — Original installation provider credentials](128-initial-provider-provisioning.md)
adds one-use scoped issuance and the fixed private installer projection. It does
not ungate the activation Pod or provide recovery authority. Actual qualification
is recorded in [implementation progress](../implementation-progress.md).

[ADR-125 — Prepaid operation certificate verification](125-prepaid-operation-certificate-verification.md)
adds two irreversible verifier attempts before provider reads and requires explicit
version-three history coverage for new admission. Historical uncertain spend is
preserved. Integration qualification is recorded in the implementation progress.

[ADR-122 — Private native owner listener](122-private-native-owner-listener.md)
adds separate bounded HTTP/2 serving and protected native reader composition.
Combined code/contracts and selected real listener/SQL-role qualification pass;
installed connector/public composition remains pending.

[ADR-124 — Prepaid Stop retirement](124-prepaid-stop-retirement.md) adds positive
writer closure, prepaid independent verification and backed finite cleanup.
Selected real SQL/provider qualification passes; protected runtime composition
remains pending. See [implementation progress](../implementation-progress.md).

[ADR-119 — Public context downloads and prepaid Stop](119-public-context-download-and-prepaid-stop.md)
adds shared browser/MCP controls, POST-owned refresh and independent restrictive
cancellation capacity. Combined code/console gates and the selected real
PostgreSQL/S3 Stop case pass; full runtime composition and finite retirement
remain pending. See [implementation progress](../implementation-progress.md).

[ADR-123 — Typed initial installation inputs](123-typed-initial-installation-inputs.md)
adds the fixed public-input producer with original object identities and bounded
policy compilation waiting. The [private probe continuation](../architecture/initial-private-probe.md)
retains one original issuance and protected state; private providers and guarded
activation remain pending.

[ADR-121 — Native acquisition worker startup](121-native-worker-startup.md)
adds explicit v2 configuration, scoped storage projection and joined credential/
transfer supervision. [ADR-116 — Context native exchange](116-context-native-exchange.md)
provides the separate bounded transfer channel and SQL45 ownership/key accounting.
The deployed worker passes startup and idle supervision. The strict selected
real-service transfer now passes exact native bytes plus three positively joined
worker conversations; full installed transfer qualification remains pending.

[ADR-120 — Gated installation preparation](120-gated-installation-preparation.md)
adds the exact inert Pod, bounded original CREATE ownership and one original
credential interval. The integrated component passes selected native qualification;
complete guarded activation remains pending.

[ADR-118 — Retained private installation state](118-retained-private-installation-state.md)
adds exact private material reconstruction and a separately authorized historical
result reader; issuing and recovery composition remain pending.

[ADR-117 — Resumable initial preparation](117-resumable-initial-preparation.md)
permits exact repeated creation of nine fixed declarative resources while their
identities remain protected and occupied. Credentials and activation retain their
separate uncertainty rules; native qualification and complete installation remain
pending.

[ADR-115 — Overdue operation audit erasure](115-overdue-operation-audit-erasure.md)
adds a preauthorized no-certificate terminal branch for positively closed
originals, preserving independent absence verification and missed-window reporting.
Selected native cleanup and full custody regressions pass; runtime supervision,
historical reconciliation and actual backup-profile qualification remain pending.

[ADR-114 — Browser refresh owned by an active download](114-download-owned-browser-refresh.md)
is superseded and removed by ADR-224.

[ADR-113 — Whole native responses with bounded accounting windows](113-large-native-response-accounting.md)
separates long HTTP responses, prepaid 64 MiB accounting windows and five-second
current-authority leases with at-most-1 MiB writes. Implementation and native
large-file qualification remain in progress.

[ADR-112 — Healthy operation audit retirement and backed history](112-healthy-operation-audit-retirement.md)
adds positive producer completion, independent finite cleanup and conservative
backup-history accounting. Native qualification and outage/recovery paths remain
required before runtime enablement.

[ADR-111 — Positive context writer completion and audited deletion](111-positive-context-writer-deletion.md)
requires joined successful writes and an independently acknowledged purge record
before releasing evidence storage. Unknown writes and metadata retirement remain open.

[ADR-110 — Bounded public operation audit](110-bounded-public-operation-audit.md)
records encrypted intent and outcome for the six implemented context operations,
with separate ordinary and request-resolution budgets and irreversible write attempts.
Protected provisioning, ingress rejection coverage and audit retirement remain open.

[ADR-109 — Published context case navigation](109-published-context-case-navigation.md)
derives immutable case routing from verified publication and applies current
ordinary access, original audience and retention checks before metadata delivery.

[ADR-108 — Backed context control capacity](108-backed-context-control-capacity.md)
reserves workload-specific metadata capacity, retains uncertain spend and allows
revisioned renewal and safe quota adjustments. Finite retirement remains open.

[ADR-107 — Atomic context request resolution](107-atomic-context-request-resolution.md)
resolves accepted work or closes the original unaccepted review under the same
admission lock, without starting or cancelling capture.

[ADR-106 — Regional API context start](106-regional-api-context-start.md)
binds dedicated executor identity, the local start journal and immutable
completion provenance to existing verification and publication.

[ADR-105 — Durable context progress](105-durable-context-progress.md) adds current authorized progress, monotonic revisions and bounded deadline observation without claiming unknown executions failed or refunding their reservations.

[ADR-104 — Regional Kubernetes API context execution](104-regional-api-context-execution.md)
separates API-only Pod status from node acquisition, preserving historical node
scope and supporting unscheduled Pods without Node or exec access.

[ADR-103 — Durable manual context previews](103-durable-context-previews.md) separates human review lifetime from fresh authority and resolves accepted retries before preview expiry checks. Evidence retention begins at submission preparation, not preview creation.

[ADR-102 — Initial preparation journal](102-initial-preparation-journal.md) persists bounded create intent and exact receipts under native staging protection; uncertain outcomes never grant another create attempt.

[ADR-101 — Installation namespace staging](101-installation-namespace-staging.md) supplies protection before final workload identities exist, with separate preparation/final probes and an explicitly pending guarded handover supervisor.

[ADR-100 — Temporary initial-installation SQL credentials](100-temporary-initial-sql-credentials.md) adds random expiring purpose roles, exact replay and privilege retirement. Protected persistence and provider orchestration remain separately qualified.

[ADR-099 — Protected initial-installer execution](099-protected-initial-installer.md) adds a private finite executable, exact Pod-bound proof and inert Restricted Pod generation. Production provisioning and restore remain separate requirements.

[ADR-098 — First-installation activation](098-first-installation-activation.md) composes the one-use witness, locked eligible-database checks and independently verified encrypted audit. Restore and installer deployment remain separate requirements.

[ADR-097 — One-use installation witness](097-one-use-installation-witness.md) adds a protected irreversible Kubernetes record outside SQL. Record qualification does not complete installer provisioning or initial/restore activation.

[ADR-096 — Database incarnation fence](096-database-incarnation-fence.md) prevents restored enabled flags from authorizing a changed PostgreSQL process/database. Migration 00031 adds effective trust reads and preserves the separate, still-pending initial/restore activation protocol. See the [verification record](../implementation-progress.md).

[ADR-095 — Hub workload garbage collection](095-hub-workload-garbage-collection.md) preserves foreground deletion with bounded controller metadata maintenance and assigned-node terminal Pod removal.

[ADR-094 — Native hub-worker projections](094-native-hub-worker-projections.md) supplies an inert Restricted workload and Pod-bound process API credentials; qualification and installer boundaries remain in the progress record.

[ADR-093 — Bounded hub scheduling permission](093-bounded-hub-scheduling-permission.md) permits an installer-selected account to update only its named scheduling Lease inside the private namespace.

[ADR-092 — Independent source admission probes](092-independent-source-admission-probes.md) makes source enforcement observable beside namespace protection through exact nonpersistent probes.

[ADR-091 — Protected configuration reconciliation](091-protected-configuration-reconciliation.md) supplies native fleet-source protection and a separately scoped, lease-scheduled hub worker without recovery activation privileges.

[ADR-090 — Protected owner deployment](090-protected-owner-deployment.md) defines fixed installation inputs, scoped provider composition, credential rotation and the private hub entry point.

[ADR-089 — Multi-cluster worker routing](089-multicluster-worker-routing.md) replaces the owner runtime's single worker profile with installation-bound SQL reads and exact control-digest issuer selection.

[ADR-088 — Owner startup readiness and runtime composition](088-owner-startup-readiness.md) separates protected pre-Ready identity from request admission and joins renewal, listening, forwarding, expiring readiness and shutdown.

[ADR-087 — Live owner cancellation through worker delivery](087-live-owner-delivery.md) replaces the finite private reply with a bounded open certificate stream. The original owner remains attached through the final worker response; EOF or loss cancels delivery, without a renewed lease.

[ADR-086 — Outbound owner enrollment transfer](086-outbound-owner-enrollment.md) selects exact process/locator verification before token transmission, one-use non-replayable HTTP and independent result validation. ADR-087 supplies live downstream control ownership through the retained connection.

[ADR-085 — Private owner enrollment receiver](085-private-owner-enrollment-receiver.md) adds bounded mutual-TLS HTTP, distinct local serving checks, exact request-owner lookup and response-time revalidation. Outbound forwarding and protected installation remain pending.

[ADR-084 — Process-owned hub credentials](084-process-owned-owner-credentials.md) adds separate server/client process keys, audited enrollment verification, TLS signer lifetime and bounded paired renewal. Protected startup, actual transport and forwarding remain required.

[ADR-083 — Current hub peer authentication](083-current-owner-authentication.md) joins actual TLS/current roots, exact active registration, native workload protection and Ready routing while retaining original deadlines. It does not replace request/developer authority or implement forwarding.

[ADR-082 — Durable hub owner enrollment](082-durable-owner-enrollment.md) adds migration 30 registration, encrypted enrollment/certificate audit, irreversible signing spend, separate activation/current registry and bounded history/retirement. Actual qualification is recorded in [implementation progress](../implementation-progress.md).

[ADR-081 — Pre-Ready hub owner enrollment proof](081-hub-owner-enrollment-proof.md) binds online Pod-token/CSR verification to exact live workload membership, accepted configuration and current namespace protection. Proof retains original deadlines and is separate from durable registration, signing and activation.

[ADR-080 — Private hub workload protection](080-private-hub-workload-protection.md) adds native namespace mutation protection and independent dry-run enforcement proof. This is a prerequisite, not historical workload integrity or owner enrollment. Actual qualification is tracked in [implementation progress](../implementation-progress.md).

[ADR-079 — Hub owner certificate issuance](079-owner-certificate-issuance.md) adds purpose-separated OpenBao leaf signing, current-root/CSR verification and renewable fixed periods. Issuance is distinct from the still-pending durable enrollment/activation and forwarding lifecycle. [Results](../implementation-progress.md) retain the real provider field-type defect and corrected qualification.

[ADR-078 — Durable owner configuration acceptance](078-owner-configuration-acceptance.md) adds migration 29 source/revision fencing, separate encrypted audit acknowledgement and current recovery-bound reads. Provider qualification is recorded in [implementation progress](../implementation-progress.md); issuer activation and forwarding remain pending.

[ADR-077 — Protected hub owner configuration](077-protected-owner-configuration.md) adds a private Kubernetes pool/public-root contract, reusable admission proof and current route composition. Observations do not provide durable acceptance, certificate activation or evidence authority.

[ADR-076 — Exact hub owner discovery and TLS identity](076-hub-owner-discovery.md) supplies bounded Kubernetes routing observations and exact process certificate verification for the shared request locator. Protected bootstrap, issuer activation and forwarding remain required; actual qualification is tracked separately.

Accepted identity decision: [ADR-059](059-unattended-policy-authority.md) separates standard human OIDC sessions from independently delegated recurring team-policy authority. Policies survive creator departure while that person loses current rights. No mandatory directory reader or personal offline credentials; implementation and runtime qualification are recorded separately.

Latest source-selection refinement: [ADR-057](057-retention-topology-pins.md) fixes exact immutable installation topology for the initial retention reader, with explicit local-source absence and no request-controlled fallback.

Latest completeness refinement: [ADR-056](056-retention-watch-watermark.md) requires durable watch progress through the full LIST watermark before current source availability, including policies created and deleted between lists.

Latest retention refinement: [ADR-055](055-retained-evidence-cutoffs.md) preserves original provenance while shortening effective cutoffs immediately and appending a signed encrypted lifecycle journal.

Native transfer correction: [ADR-054](054-native-download-protocol.md) uses standard If-Match resume checks and truthful Preparing metadata; the prior If-Range mismatch rule was nonstandard.

Latest provider refinement: [ADR-053 — Explicit Keycloak access profile](053-keycloak-access-profile.md) adds a configured provider adapter and built-in stable-group mapping; no automatic profile guessing or mandatory identity service. Actual fixture qualification is recorded separately from the decision.

Date: 2026-10-10. "Accepted" means explicitly directed by the user or binding brief; "Proposed" means an engineering recommendation awaiting plan review.

Latest internal refinement: [ADR-051 — initial peer certificate profile](051-peer-certificate-profile.md) selects standard-library TLS/X.509 with a bounded installation-specific SPIFFE URI and current registration checks. Component tests do not establish enrollment, issuance or node attestation.

Latest implementation refinement: **ADR-049 — Initial identity profile selected for qualification under the maintainer's continuation:** reuse go-oidc/go-jose with a bounded RFC 9068/RS256 access-token adapter, fixed trusted HTTPS key endpoint, finite key snapshots, explicit organization/client policy and current retained-audience evaluation. Additional profile constraints are one resource audience, complete stable group assertions and qualified separate human/workload client classes. These bounds describe an internal first adapter, not a requirement that all production IdPs change their token layout. Actual provider/discovery/group/session and Kubernetes authority integration remains pending; no ID-token fallback, new permission API, public effect or audit bypass is introduced. See [contract](../architecture/identity-eligibility.md) and [component results](../research/identity-foundation.md).

**ADR-048 — Artifact format selected for implementation under the maintainer's continuation:** use `asservat-framed/v1`, fixed 8 MiB native frames, complete library-managed Tink streams, a paged encrypted index and separately keyed detailed manifest. Native files are unchanged. Freeze the versioned layout and commit contract; backend/multipart/custody/authorization qualification remains open. Wrap-only collectors use explicit KMS sealing without Tink's decrypt self-check. Four immutable attempt objects are charged before writing and are not visible until verified hub commit. This resolves ADR-047's pre-implementation format gate without claiming S-01/S-02 complete. See [format and commit boundary](../architecture/artifact-format.md) and [implementation evidence](../research/artifact-foundation.md).

The initial SQL custody continuation implements part of ADR-023/048 through protected storage backing, unpublished copy receipts and fenced deletion. It does not change the accepted authorization/publication boundary. See [transaction scope](../architecture/custody-transactions.md) and [verification](../research/custody-foundation.md).

The next continuation implements complete manifest/envelope/native validation for bounded pod-status evidence under the same ADR-048 format. This is an incremental implementation, not a new storage or authorization decision. Results remain unpublished while trusted execution, durable audit and catalog publication are pending. See [verification contract](../architecture/manifest-verification.md) and [measured results](../research/manifest-foundation.md).

The [permission observation continuation](../research/permission-foundation.md) implements part of ADR-017/018/023: Kubernetes source reads, selected namespace metadata and unaccepted mapping proposals. It also enforces the existing five-second deny requirement explicitly. Protected acceptance, source qualification and persistent assignment continuity remain pending; no new permission store, trust decision or collection authority is introduced.

| ID | Status | Decision and consequence |
| --- | --- | --- |
| ADR-001 | Accepted | Preserve Asservat identifiers, no embedded AI/harness, MCP tools first, content-free CloudEvents, node-side encryption, Inspektor Gadget, own crash agent, restricted workload namespaces and no call-home. |
| ADR-002 | Accepted by user | Central multi-cluster management in the first release. Use outbound cluster connectors, globally unique identities and per-cluster data locality. A single-cluster-only first production release is insufficient. |
| ADR-003 | Accepted by user | Allow reviewed, expiring policy grants for automatic intrusive actions; keep per-execution approval for ad hoc actions. This explicitly supersedes the brief's per-execution requirement for every live dump. |
| ADR-004 | Superseded by ADR-023 | No mandatory PostgreSQL/database/broker. Use Kubernetes for bounded control state and object storage for durable records. Search caches are disposable. Scale limits must be demonstrated. |
| ADR-005 | Accepted by user | Explicit sharing may expand access to otherwise ineligible users/groups **within the organization**. No anonymous sharing or sharing across installations. Sharing and raw-operation grants remain independent. The earlier same-tenant wording is superseded by ADR-016. |
| ADR-006 | Proposed | Go for services; small static Rust core-pipe helper. Rust is selected for a narrow native helper with no service runtime; comparative kernel-path behavior remains to be measured and it adds a second build toolchain. Prototype a Go helper only if Rust maintenance proves disproportionate, without changing behavior. |
| ADR-007 | Proposed | Modular Markdown + scenarios + JSON Schema + ADRs + traceability, no mandatory spec-framework CLI. Rationale: [format research](../specification-format.md). |
| ADR-008 | Proposed | Original three CRDs for the user collection model (extended by CaptureProfile in ADR-032): `DebugPolicy`, `EvidenceRecipe`, `DebugCapture`; reusable policies specify triggers, recipes specify actions, captures bind an immutable execution. Separate cluster administration and grants. |
| ADR-009 | Refined by ADR-063 | OpenBao, Keycloak and Ceph RGW remain external reference integrations. The external-only assumption is superseded by planned internal/bundled alternatives; no mandatory storage operator. |
| ADR-010 | Proposed | Real header sanitization before retention. Fixed snaplen alone is never described as payload-free. Unknown packet formats are dropped from the default ring with explicit loss accounting. |
| ADR-011 | Proposed | Trusted analyzer images plus exact target root filesystems as inert data. Never execute an application image's entrypoint to analyze evidence. Separate acquisition and offline analysis Jobs. |
| ADR-012 | Proposed | Structured debugger operations, no free-form debugger shell. Raw memory and pcap content remain bounded queries; no presigned evidence URLs. |
| ADR-013 | Proposed | Apache-2.0 for Asservat-owned code and documentation; DCO contributions, transparent maintainer review, security reporting and SBOMs. Dependency notices remain separate. Do not publish a licence under an assumed copyright holder. |
| ADR-014 | Proposed | Air-gap, identity, authorization, audit, retention and sharing are part of the first vertical slice, not final hardening phases. |
| ADR-015 | Accepted by user | Pprof and similar runtime profiles are first-class evidence. Capture, store, analyze, share and expose bounded profile comparisons through MCP; no continuous-profiling service is required. |
| ADR-016 | Accepted by user | One organization per installation; remove the unnecessary multi-tenancy requirement. Keep central multi-cluster management, team/workload ACLs and explicit sharing within the organization. No tenant entities, IDs, provisioning, routing or per-tenant storage/quota hierarchy. Unrelated organizations use separate installations. This supersedes the initial architectural assumption and clarifies ADR-005. |
| ADR-017 | User-requested capability; mechanism proposed | Automate permission management with protected Kubernetes resources and automatic permission sources. The initially proposed duplicate HTTP CRUD interface is superseded by ADR-018. Support configurable inheritance from administrator-managed namespace metadata and existing Kubernetes permissions, including pod exec. Use exact access reviews and qualified identity/admission mappings; preserve intrusive-action approval and local ceilings. See [permission research](../research/permission-automation.md). |
| ADR-018 | Accepted by user | Kubernetes CRDs/API are the only public permission-configuration CRUD surface. Keep effective-access explanation/preview in the existing browser query service; evidence, approvals, MCP and connector HTTP remain. Native RBAC does not replace custom-resource admission or execution authorization. |
| ADR-019 | User priority; workflow proposed | Minimize recurring administrator/developer work with versioned presets, resolved defaults, inherited permissions, actionable capability checks, shared UI/GitOps semantics and bundled approvals. Preserve explicit high-impact approvals. See [ergonomics review](../ergonomics-review.md). |
| ADR-020 | User-required capability; controls proposed | Enforce finite administrator retention maxima by privacy class, evidence type and workload scope. Derived data inherits deadlines; ordinary holds cannot bypass maxima. Privacy controls support operator obligations, not a blanket GDPR-compliance claim. See [privacy specification](../../specs/privacy.md). |
| ADR-021 | User-required protection; mechanism proposed | Workload-wide storm and impact budgets, reserve capacity before acquisition, fair uploads/analysis, and unborrowable protected storage plus separate shared burst. Hub SQL transactions and local CAS/prepaid slices enforce bounded quota state (ADR-023 supersedes the original hub CAS mechanism); backend quota statistics alone are insufficient. Default full accounts preserve prior evidence and reject new expensive capture. See [capacity isolation](../../specs/capacity.md). |
| ADR-022 | Accepted by user; contracts proposed | Owners may attach sharing to a capture request. Offer recurring-policy sharing only as an explicit reviewed revision with expiry and capture limit. A service-owned SharingIntent pins recipients/outputs and authorizes concrete EvidenceShare snapshot revisions after commit/provenance checks; raw-sharing and recipient raw-query approvals remain separate. Stop drains registered captures; revoke denies dependent shares. See [sharing requirements](../../specs/authorization.md#req-shr-004--share-results-when-requesting-collection). |
| ADR-023 | Accepted by user; implementation pending | PostgreSQL is required for hub transactional state and catalog indexes; Kubernetes remains authoritative for declarative configuration and local control, with object storage for evidence/audit. Supersedes ADR-004; preserves ADR-018. See [persistence](../../specs/persistence.md) and [reassessment](../../specs/changes/postgresql-hub-state/proposal.md). |
| ADR-024 | Accepted by user; contracts proposed | Separate immutable createdBy from one or more managing owner teams. Current group membership and pinned owner assignments govern management; changing managers never silently exposes historical evidence. See REQ-SHR-008. |
| ADR-025 | Accepted by user; qualification pending | Add checked pcap expressions, live Service/Deployment/StatefulSet peers, segmented bounded rings and protocol profiles. HTTP headers require bounded parsing and projection, not a safe snaplen claim. Keep the Gadget engine and record update/loss limitations. See [packets](../../specs/packets.md). |

## Reconsideration triggers

- ADR-023: SQL contention, recovery safety or database operations cannot meet the qualified envelope. Reassess with measured evidence; do not introduce a second runtime backend or broker implicitly.
- ADR-006: helper syscall/library footprint or cross-compilation testing defeats its operational benefits.
- ADR-009: a reference backend fails multipart/checksum/conditional-write/retention qualification or changes licence/call-home behavior.
- ADR-010: Inspektor Gadget cannot provide suitable bounded node-local streams; first investigate its documented Go API or an upstream contribution. Changing the packet engine requires maintainer review.
- ADR-011: a runtime requires privileged/native execution that cannot be isolated. Mark that recipe unsupported or require an explicitly qualified sandbox; do not weaken every analyzer.

The brief's domain-registration and trademark work remains a maintainer-owned publication prerequisite. DNS absence is not evidence of domain availability, and no registration or legal clearance occurred in this work.

## Full design review decisions

- **ADR-026 — Accepted by user:** observe all authorized replicas within administrator limits by default; cap collection separately and prioritize contributing pods, including unready replicas.
- **ADR-027 — Accepted by user:** permit administrator-configured finite approval periods for stable automatic policies. Retain short permits, current authorization, independent review, nonrenewing budgets and immediate connected revocation; sharing expiry remains independent.
- **ADR-028 — Accepted by user:** the pod is the smallest public configuration, permission and filtering unit. Remove container selectors/ACLs/pickers; preserve runtime container/process identity internally for attribution and anti-reuse. Pod-wide fanout is bounded, and host namespaces never imply node-wide authority.
- **ADR-029 — Proposed mechanism, integrated for review:** separate authenticated submission, collection execution scope and sharing instruction digests. Add bounded MCP discovery/preview/status/cancellation; use storage-aware backup/index expiry and explicit temporal trigger semantics. See the [review](../reviews/design-review.md).

- **ADR-030 — User-requested capability; mechanism proposed and integrated for review:** make goal-oriented diagnostic assistance first release. Use existing capture primitives for finite process/network/protocol discovery, deterministic local recommendation rules and shared browser/MCP plan handles. Provide filter/selector/ring recommendations with confidence and explicit limits; retain ordinary authorization, observation approvals, quotas and privacy. No embedded LLM or separate survey execution API. See [guidance](../../specs/guidance.md) and [feasibility evidence](../research/guided-diagnostics.md).

- **ADR-031 — User-requested capability; mechanism proposed and integrated for review:** retain bounded, selector-scoped capture history and immutable encrypted parameter snapshots. Repeat restores settings into a new request with current checks, its own identity/approval and ordinary quota charges. Namespace/workload UIDs separate reincarnations; metadata versus evidence-derived parameter retention remains explicit. Reuse SQL/object storage and existing preview/submission; add no history CRD or execution API. See [capture history](../../specs/capture-history.md).

- **ADR-032 — Accepted recommendation; implementation/qualification pending:** reusable capture profiles are first-release, versioned data-only CaptureProfile CRDs in explicit builtin/organization/namespace catalogs. Finite typed edits and flat composition compile into the existing bounded recipe, approvals, quotas, history and MCP preview. Ship process/network/HTTP1/Go CPU/syscall metadata definitions; permit authorized publication of materialized derivatives. No template language, nested executable profiles or new configuration service. See [capture profiles](../../specs/capture-profiles.md).
- **ADR-033 — Accepted capability; adapter proposed:** add bounded syscall activity across current/new pod processes using the selected Gadget engine family. Metadata avoids user-memory reads; sensitive arguments/buffers require explicit reviewed acquisition and independent raw analysis/sharing. Traceloop is a feasibility candidate, not yet a qualified production implementation. See [syscalls](../../specs/syscalls.md) and [source evidence](../research/capture-profile-feasibility.md).

- **ADR-034 — User-required distinction; lifecycle contracts integrated for review:** separate onTrigger actions from ongoing recording saved on trigger. Packet/syscall actions default ongoing; explicit onTrigger variants require zero lookback. Arm sources with authority/capacity across observation pods, reserve saves separately, and keep source identities/timeouts apart from incident jobs. Natural cores remain crash-event acquisitions with prepared interception; manual sessions remain finite. See [action lifecycles](../../specs/action-lifecycle.md).

- **ADR-035 — User-required disclosure; assessment contracts integrated for review:** assess the combined selected capture mechanisms, expected workload effects and uncertainty before collection/arming. Show possible sensitive contents, effective automatic-deletion ages and handling guidance in browser/MCP/GitOps and scoped artifact views. Reuse the planner, capability rules, admission and privacy services; no embedded classifier, trial capture, generic consent checkbox or new approval role. Limits are not measured predictions, and managed deletion cannot recall external-agent copies. See [capture assessment](../../specs/capture-assessment.md) and [source research](../research/capture-assessment.md).

- **ADR-036 — Accepted by maintainer; implementation/qualification pending:** require an operator-provided qualified encrypted scratch StorageClass for first-release offline analysis using separate acquisition/analyzer/publication Jobs. Per-analysis input/output PVCs need encryption, fenced nonoverlapping writers/read-only handoff, bounded capacity and verified copy-ledger cleanup. Job-private tmpfs is allowed within one phase; no cross-Job emptyDir or ordinary plaintext-PVC fallback. Collection remains usable with analysis explicitly unavailable until scratch is qualified. REQ-EVD-005/008 define isolation and privacy obligations; no particular CSI backend is assumed qualified.

- **ADR-037 — Correctness refinements integrated for review:** bind ad hoc execution digests to explicit pod/node/boot identities; retain stopped recorder contents briefly within existing authority/budgets for delayed exit events; distinguish prehistory from whole-window coverage; close tool-log and hostile-output publication paths. Remove the unimplemented manual policy-detector leaf while preserving DebugCapture. See [final review](../reviews/final-review.md).

- **ADR-038 — Accepted feature; contracts integrated, implementation pending:** add Save existing recordings now as an explicitly enabled and reviewed policy capability. Current maintainers can snapshot only existing ongoing packet/syscall sources, without firing detectors or running onTrigger actions. Reuse policy authority/budgets, capture submission/status/cancellation, privacy and per-capture sharing; add passive inventory/preview MCP tools and a protected typed save scope. Save windows end at first acceptance, with no future acquisition or authority transfer. History repeat requires fresh source selection. See [recording saves](../../specs/recording-saves.md).

- **ADR-039 — User-requested UX/interface/domain design; integrated for review:** originally use one role-aware console with 60 inventoried screens and Go templates/minimal JavaScript; the frontend technology is superseded by accepted ADR-046 and the inventory has since expanded. Define typed domain aggregates separately from SQL rows, CRD spec/status and transport DTOs. Reuse the 40 MCP operation contracts for browser equivalents; add explicit human review/operator boundaries without a second permission-configuration API. Local interactive mockups and schema consistency checks are design evidence only. No new runtime dependency, tenant model, embedded agent or collector implementation is introduced. See [UX](../ux/README.md), [domain](../domain/README.md) and [interfaces](../interfaces/README.md).

- **ADR-040 — User-requested feature and approved content boundary; design integrated, qualification pending:** expose finite live views of existing ongoing packet/syscall sources through the console and five shared browser/MCP tools. The maintainer selected approved projections live, saving before raw inspection. Keep display filters independent from acquisition, preserve source/viewer authority and per-row privacy, use bounded batches with explicit gaps, and shed viewers before protected incident work. LiveWatch is minimized SQL control state; live rows are transient, not artifacts or a durable stream. No live sharing, raw-content grant, new CRD, websocket or mandatory broker. See [live watching](../../specs/live-watch.md) and [research](../research/live-watch.md).

- **ADR-041 — User-requested minimalist GUI overhaul; design artifacts updated, usability qualification pending:** use a light neutral shell, stable section navigation, broad evidence tables, one emphasized next action per context and progressive disclosure for supplementary details. Remove the permanent mockup toolbar and technical screen IDs from ordinary page content. Keep impact, audience, sensitive-data handling, effective deadlines and gaps visible. Apply shared components to all 62 screens; preserve native accessible controls, whole-pod scope and existing browser/MCP/domain boundaries. No new frontend framework or service. See [source research](../ux/web-design-research.md), [design system](../ux/design-system.md) and [REQ-UI-007](../../specs/user-experience.md).

- **ADR-042 — User accepted the implementation-architecture work; detailed design integrated for review:** retain a modular Go hub with separate API/worker roles, per-cluster connector, privileged node collector, minimal Rust host helper and isolated acquire/analyze/publish Jobs. Define a canonical package/dependency graph, component/entity/requirement ownership, named transaction facets, typed adapter ports, runtime failure walkthroughs and end-to-end implementation slices. Place regional evidence-text cache with the connector initially, subject to locality and independent resource bounds. No service per domain entity. See [architecture package](../architecture/README.md).
- **ADR-043 — Internal protocol and effect-boundary refinement selected; qualification pending:** use collector-initiated private mTLS control to the connector and outbound connector polling to the hub, strict versioned purpose-specific JSON, standard JWS with Ed25519, stable effect identities and separate transient live-owner routing. Local start reservation/lookup is a narrow connector port over prepaid Kubernetes CAS state; lease expiry or new delivery fence does not justify repeating an ambiguous start. Keep the prepared natural-core path free of remote waits. Exact Gadget transport, signing-library support, old-process exclusion and fault behavior require the named runtime spikes. See [interfaces](../architecture/interfaces.md) and [research](../architecture/research.md).

- **ADR-044 — Explicit maintainer correction; design integrated, runtime qualification pending:** require authenticated native download for all gathered evidence and saved derivatives, including packet captures for Wireshark and cores plus available exact companions for GDB. Supersede the original raw-file prohibition. Reuse current covering grants; ordinary approved artifacts need no new independent review, while full raw download needs explicit existing-artifact operation coverage. Stream from a separately scoped regional acquisition Job over bounded authenticated relays, preserving managed encryption, quotas/audit and cutoff. No presigned bearer URL, proprietary mandatory decryptor or claim of remotely deleting laptop copies. See [download contract](../../specs/artifact-downloads.md) and [review correction](../reviews/local-investigation.md).

- **ADR-045 — Explicit maintainer selection; contracts and prototype integrated, implementation pending:** one independent human approval may cover a bounded one-off capture and the same developer's selected inspection/download. Bind exact capture/action scope, registered clients, absolute expiry and aggregate disclosure limits; create exact existing-artifact children only after verified commit. Keep acquisition and result counters distinct, current entitlement and parent revocation effective, and later/uncovered requests separately reviewed. This supersedes the separate-review limitation recorded in ADR-044's initial implementation. See [investigation approval](../../specs/investigation-approval.md) and [user-task review](../reviews/user-task-review.md).

- **ADR-046 — Accepted by user:** React and TypeScript for the production console, compiled assets served by Go. This supersedes the Go-rendered templates/minimal-JS implementation choice in ADR-039 and the later visual-design documents; it preserves the minimalist visual system, workflows, same-origin session/API boundary and server authorization. Select unstyled React Aria primitives, library routing and bounded query state as engineering details. No production Node server or mockup rewrite is required by this planning decision. See [technology choices](../technology.md).
- **ADR-047 — Engineering baseline selected for review; qualification pending:** use existing protocol/crypto/storage/diagnostic libraries with explicit Asservat-owned application rules. Native pgxpool + sqlc + SQL/goose migrations refine the earlier database/sql recommendation; Go net/http, official MCP SDK, local JSON Schema validation, explicit Go DTOs and generated TS types implement transport boundaries. Full Go OpenAPI generation is excluded from the baseline after failures on actual contracts. Prefer established, actively maintained dependencies; use Go 1.27 standard-library RFC 8785 canonicalization in place of the external JCS candidate. Real libpcap syntax is compiled through a qualified mechanism adapter; dynamic Gadget map integration and syscall metadata remain substantial implementation work. Keep the persistent large-artifact layout unfrozen until efficient native download/range qualification. See [build/reuse matrix](../architecture/build-or-reuse.md), [research](../research/technology-selection.md) and [experiment results](../../experiments/technology-selection/README.md). Six passing synthetic Go tests and a frontend build are not production qualification.

- **ADR-050 — Engineering refinement under the authorized implementation:** use persistent SQL assignment identities and encrypted authority audit before activating new permissions; immediate deny/retirement remains independent of audit delivery. Native Kubernetes validating admission policies enforce administrator/delegation content boundaries alongside structural CRDs and RBAC. Exact source versions and verified transition continuity govern preservation across controller epochs; ordinary restart alone does not erase unchanged assignments. Qualification and runtime composition are tracked separately. See [permission acceptance](../architecture/permission-acceptance.md).

- **ADR-052 — Enrollment retry and activation refinement:** persist a maximum of two nonrefundable signing attempts per original bootstrap, each with at most five seconds to store its verified result. Require separate encrypted claim and certificate audit, then current atomic registration before delivery. Audit failure reuses the signed result; replay cannot revive revoked registration. See [audited activation](../architecture/enrollment-activation.md).

- **ADR-058 — Accepted by user:** [Official Helm installation](058-official-helm-installation.md), one first-party chart for hub/cluster/combined, explicit CRD upgrades, local archives and OCI distribution; current package is configuration foundation only.

- **ADR-060 — Engineering refinement of accepted ADR-059:** [Bounded browser sessions](060-bounded-browser-sessions.md), standard code/PKCE login, encrypted server credentials, single-use refresh claims and current identity checks. Production bootstrap and public workflow remain pending.

- **ADR-061 — Engineering refinement of ADR-060:** [Current browser configuration](061-current-browser-configuration.md), protected Kubernetes settings, finite SQL projections, monotonic session shortening and logout during settings outages. Bootstrap and restoration qualification remain pending.

- **ADR-062 — Engineering refinement of accepted execution provenance:** [Policy submission signatures](062-policy-submission-signatures.md), exact post-persistence scope binding, dedicated OpenBao Ed25519 signing, current Kubernetes public-key trust and verification deadlines carried into SQL acceptance. Public admission/operation composition remains pending.

- **ADR-063 — Small-deployment requirement and recommendations accepted:** [Internal dependency alternatives](063-small-deployment-alternatives.md), local users/login, purpose-separated static-key services, Helm-provided PostgreSQL and bundled SeaweedFS. Single-instance PostgreSQL/pgBackRest and the other selections still need runtime qualification. Supersedes external-only dependency assumptions; preserves authority, encryption, retention and role isolation.
- **ADR-064 — Local key material and credential provider ports:** [Versioned local keys](064-local-key-material.md), implemented bounded private Secret parsing, installation/purpose/version-bound wrapping and pinned Ed25519 signing, with unchanged artifact/browser envelopes. Root material remains isolated in the pending authenticated key-service runtime; no new dependency or enabled Helm option.
- **ADR-065 — Private local key boundary:** [Local key operations](065-local-key-service-boundary.md), closed mTLS wrap/unwrap/sign RPC, exact current-authority coordination and bounded remote facets. Real TLS/crypto fixtures pass with test-only authority; protected production resolvers, issuer/Secret lifecycle and runtime/chart bootstrap remain pending.
- **ADR-066 — Download-bound local unwrap:** [Current download key authority](066-download-key-authority.md), exact audited SQL batch and acquisition-certificate binding, three irreversible key-role slots and current permission/retention/recovery checks. The initial context reader composes real SQL/TLS/S3 components; protected issuance/lifecycle, other key purposes and public workflow remain pending.

- **ADR-067 — Protected local key lifecycle:** [Source and rotation fencing](067-protected-local-key-lifecycle.md), immutable Secret pins, bounded coalesced observations, durable version history and mandatory configuration checks around key effects. Administrative bootstrap, retirement and operational deployment remain pending.

- **ADR-068 — Kubernetes-bound download worker identity:** [Original worker proofs](068-download-worker-attestation.md), Pod-bound TokenReview plus current pinned namespace/account/Job/Pod observations, exact acquisition-certificate binding and immutable SQL proof deadlines. Protected dispatch, certificate issuance and public runtime remain pending.

- **ADR-069 — Durable download worker dispatch:** [Dispatch and retirement](069-download-worker-dispatch.md), encrypted immutable launch intent, single-use SQL claim, restricted exact Job/Pod template, persistent termination before deletion and no expiry-based capacity refund. Runnable acquisition, issuer, protected profile rollout and full cleanup/fairness qualification remain pending.

- **ADR-070 — Protected worker configuration:** [Configuration and rollout fencing](070-protected-worker-configuration.md), pinned administrator source with native admission proof, immutable audited revision history and original freshness deadlines through dispatch and identity. Bootstrap, issuer, supervised runtime and Helm composition remain pending.

- **ADR-071 — Audited acquisition credentials:** [Worker enrollment and renewal](071-download-worker-enrollment.md), certificate-free Pod/token proof, immutable CSR key, separately audited bounded signing and activation, and finite renewal periods within original worker deadlines. Scoped SQL/S3 and Kubernetes/OpenBao/TLS qualification passes; public runtime, protected bootstrap and the local CA remain unfinished.

- **ADR-072 — Worker credential channel:** [Process-owned credentials and private enrollment](072-worker-credential-channel.md), pinned TLS, request-bound current human authority, closed CSR/certificate wire, bounded renewal with the same process key and cancellation. Runtime routing/bootstrap remain pending.

- **ADR-073 — Pinned acquisition startup:** [Typed worker control and supervision](073-worker-startup.md), exact immutable public configuration, original identity/deadline pins, process-local core protection and bounded renewal independent of logging. Historical cleanup verifies original stored specs across template upgrades; actual native work/relay and public runtime remain pending.

- **ADR-074 — Active worker request ownership:** [Routing and response lifetime](074-worker-request-routing.md), bounded current-owner registration, exact SQL worker scope, independent concurrent tokens and cancellation retained through certificate delivery. Cross-replica/connector routing and public native transfer remain pending.

- **ADR-075 — Shared worker request locator:** [Minimized SQL ownership](075-worker-owner-locator.md), current request/worker claims, immutable finite deadlines, monotonic fences and exact-owner receiving across local replacement. Authenticated process discovery and network forwarding remain pending.

- **ADR-141 — Protected capacity production:** [Automatic exact-workload enrollment and managed renewal](141-protected-capacity-production.md), fixed prepaid root backing, separate capacity/capture purposes, one managed readiness fence and original session retention. Actual SQL and installed multi-cluster/backend qualification remain pending.

- **ADR-146 — Prepaid processing coverage before collection:** [Current root and retained-rule coverage](146-processing-coverage-before-collection.md), bounded preview/new-request reads and atomic managed-admission rejection before charges, unchanged requested retention, passive replay and shared uncertainty-preserving errors. The real PostgreSQL component matrix passes; installed public composition remains pending.

- **ADR-147 — Standard owner provider authentication:** [Purpose-fixed Kubernetes authentication](147-standard-owner-provider-authentication.md), four finite renewable OpenBao service credentials, generated role/policy recipes and explicit scoped S3 credentials. The standalone recipe component passes; provider authentication, credential lifecycle and installed selection remain pending.

- **ADR-148 — Bounded public projection enforcement:** [One publish, original enforcement interval](148-public-projection-enforcement.md), five explicit current pre/post effect boundaries and one independently denied proof retained only within its original deadline. No cross-call proof, deadline increase or runtime enablement; native composed qualification remains pending.

- **ADR-149 — Fresh provider-installed pair:** [Original worker and owner selection](149-fresh-provider-installed-pair.md), purpose-separated Kubernetes provider authentication, fixed audit credential identities, required immutable audit versions and finite original-root input production. Component qualification and the schema gate pass; fresh installed composition, complete version retirement and runtime enablement remain pending.

- **ADR-152 — Current retention audit receipts:** [Indexed immutable receipt validation](152-retention-current-audit-receipts.md), closed pure invoker predicates and invalid-receipt indexes for all retained checkpoints/catch-up decisions; structural restrictive history remains readable. Schema 57 component, real SQL/S3 parser/planner/history and native Kubernetes reconciliation checks pass; installed-runtime qualification remains pending.

- **ADR-151 — Required initial audit versions:** [Installer audit enforcement](151-initial-audit-version-requirement.md), fresh bootstrap v4/service and installer v2 with immutable intent binding, required non-null audit versions for all accepted active installer formats, preserved historical inputs and no fallback. Component regressions and original fresh-bootstrap native qualification pass; complete version retirement and runtime startup remain pending.

- **ADR-150 — Operation-owned native observation:** [Original bounded proof and direct holder routing](150-operation-owned-native-observation-proof.md), independent native boundaries, actual current SQL/TLS checks and one-use local claims. Component checks pass; complete native availability and installed selection remain pending.

- **ADR-153 — Operation-owned connector enrollment:** [Original native admission and signing boundaries](153-operation-owned-connector-enrollment.md), distinct complete initial/final enforcement observations and current intermediate source/token/controller reads inside one original operation. Legacy interfaces, SQL checks and unknown spend remain unchanged; component and native qualification are pending.

- **ADR-155 — Unchanged fleet persistence contention:** [Failed persistence with original expiry](155-unchanged-fleet-persistence-contention.md), exact aborted lock classification, independent before/after source/incarnation checks and unchanged negative fencing. Component races pass (119 top-level / 605 named) and all ten focused native SQL cases pass; [integration evidence](../../test/results/fleet-persistence-contention-integration.json) preserves the original failures. Broad fleet and installed owner qualification remain pending.

- **ADR-157 — Protected observation dial endpoint:** [External connectivity and original serving identity](157-protected-observation-dial-endpoint.md), fixed installation-owned TCP port translation with unchanged original Service/SNI/HTTP authority, current peer checks and no replay. Translated-port TLS components and the [original direct native reference](../../test/results/direct-observation-native-6/result.json) pass with unchanged five-second bounds and positive joins/cleanup. Synthetic setup/issuer roots remain explicit; no installed endpoint producer or runtime selection is enabled.

- **ADR-156 — Finite owner configuration audit epochs:** [Independent full-snapshot acceptance](156-finite-owner-audit-epochs.md), explicit automatic rollover overlap, finite charged capacity and distinct current/admitted dependency values. The [integrated foundation](../../test/results/owner-audit-epoch-integration.json) passes component qualification (144 top-level / 807 named race-test passes plus compilation, vet and canonical gates). The [separate codec](../../test/results/owner-epoch-codec-integration.json) passes 42 top-level / 99 named framed race tests and affected gates. Both remain unselected; current SQL29 v1 configuration receipts and runtime behavior are unchanged. SQL effects, reserve/checkpoint production, complete consumer composition, physical retirement and installed sustainability remain pending.

- [252 — Approved capture acceptance](252-approved-capture-acceptance.md): retain bounded immutable review blueprints and fix a separately bounded capture deadline under the original current grant.

- [ADR-257: preserve authored packet evidence funding](257-approved-recording-funding.md)

- [258 — Native response windows under slow delivery](258-slow-native-response-windows.md): retain one fixed response owner and cursor across fresh short leases, preserve actual credential expiry, and reuse the existing native-owner renewal. Selected SQL/S3/TLS qualification passes; installed aggregate-cost and slower-link qualification remain pending.

- [ADR-260: API target observations after completed authenticated queries](260-api-target-observation-freshness.md)
