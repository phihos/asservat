# Download worker dispatch and cleanup

[ADR-069](../decisions/069-download-worker-dispatch.md) implements the initial dispatch components behind REQ-DLD-003, REQ-DEP-003 and REQ-CAP-003. C-14 owns the worker's lifecycle within `ArtifactDownload`; C-08 owns encrypted intent and acknowledgement ports; C-21 supplies Kubernetes, SQL and object adapters; C-24 supplies pure values. No new public entity, API, container-level permission or application role is introduced.

## Authority and launch

`DownloadDispatcher.Ensure` checks the current human/client download scope, reserves or recovers one immutable intent, publishes its encrypted create-only audit, acknowledges it through a separate SQL role and obtains current authority again. SQL serializes recovery → permission root → session → child transitions, repeats catalog/retention/current-time checks after locks, and commits the single-use launch claim before any Kubernetes write. Unknown outcomes stay claimed. The root/installation lock also serializes capacity admission across replicas.

A retry recovers the same live intent and deadline even if supplied another candidate UUID. Once the separate audit role has acknowledged the exact immutable intent, the dispatcher reads that durable receipt instead of repeating encryption and object-store work on every readiness poll. Missing acknowledgement still requires the complete encrypted audit/readback path; a malformed or substituted receipt denies launch. This historical receipt never replaces the subsequent current-authority checks. The first claimant may call Job creation once. Later calls only inspect the exact deterministic Job name and validate its complete approved template. A changed image, command, environment, extra container/volume, identity or spec is a conflict. Finding no Job after an uncertain create does not authorize another POST. No pending worker has evidence permission merely because it was scheduled.

Record the exact observed Job UID and complete spec digest even after the create lease expires; this is historical effect accounting. Bind the selected Running Pod only with new current download authority, the exact controlling Job and full approved spec. Store that Pod UID/spec once. Replacements cannot rebind the row. Worker clusters remain independent of evidence clusters.

The [ADR-068 proof source](download-worker-attestation.md) now has `NewDispatchedDownloadPeerAttester`. It reads the SQL-bound worker through `DownloadWorkerBindings`, verifies immutable current control/account/namespace sources, then performs the existing TokenReview/live-object checks. Its original observation is capped by the worker's absolute run deadline as well as token/certificate expiry. Dispatch registration is an identity observation, not evidence authority; the key service still consumes the separately audited exact download batch.

## Job profile and admission

The private `DownloadWorkerProfile` is independently configured installation input, never developer request JSON. It fixes installation/worker cluster, namespace and account UIDs, digest-pinned image, immutable control ConfigMap UID/data digest, a named PriorityClass UID, up to four named registry pull Secrets, CPU/memory and a 30-second to eight-hour maximum runtime. The ConfigMap has one bounded `worker.json` value. Its runnable control protocol is still required; [ADR-070 protected profile acceptance](worker-configuration.md) now supplies the enrollment/rollout producer. A constructor argument or digest alone is not administrator acceptance.

`DownloadWorkerJobs` requires the namespace's Pod Security enforcement to be `restricted`, and exact live non-deleting ServiceAccount and immutable ConfigMap identities. It also reads the exact non-deleting PriorityClass: value zero, `globalDefault: false` and `preemptionPolicy: Never`. The template names that class explicitly, preventing a conflicting cluster default or eviction of application pods. An actual API test rejected the earlier template that set `Never` without a matching class; Kubernetes resolves these fields through [PriorityClass admission](https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#non-preempting-priorityclass). The Job has one completion/parallel pod, zero backoff, Never restart, Failed replacement policy and a finite active deadline. A manual selector uses the unique dispatch UUID in a private label. The container command is `/asservat download-worker` with only generated IDs, the original absolute deadline and fixed control/token paths. The production command is not implemented by this adapter.

CPU/memory requests equal limits; ephemeral-storage request/limit is 4 MiB. The process runs as UID/GID 65532 with RuntimeDefault seccomp, no added capabilities or privilege escalation and read-only root. Only the dedicated audience's 600-second projected token and immutable public control config are mounted. No automatic Kubernetes API token, host namespaces, target filesystem, extra writable volume, root key, evidence credential or arbitrary command is permitted. Registry pull Secrets are image-fetch references, never mounted secrets or permission grants.

Actual API responses must match the whole typed specification and its raw canonical digest. Pod observation allows the scheduler's valid node name, resolved zero priority and the two standard 300-second not-ready/unreachable tolerations; other changes fail. Items from the validated `v1/PodList` may omit their redundant per-item kind/version; an explicit foreign kind/version remains invalid. Spec hashes retain the full actual defaults for subsequent attestation. This conservative compatibility rule needs qualification for each supported Kubernetes/admission profile; injected service-mesh sidecars are not implicitly trusted.

Dispatcher RBAC permits Job creation in the protected worker namespace, exact Job get/delete, bounded selector-based Pod lists and named configuration/account/PriorityClass reads. Kubernetes RBAC cannot restrict a create to this template or a list to its label: the protected namespace, independently qualified admission and trusted dispatcher remain required. It receives no Secret read, token issuance, TokenReview or Job/PriorityClass update. Token review/control mediation uses a distinct role. The owned tests exercise these API privileges without qualifying an operator's admission/network policy.

## Capacity, cancellation and cleanup

Migration `00025_download_workers.sql` maintains original dispatch generation, minimized intent/audit, consumed launch, exact Job/Pod binding and two immutable retirement records. It contains no bearer token, raw key, native file or native checksum. Dispatch attempts share the parent session's finite request-limit ceiling; retries preserve the current generation. A new generation is admitted only after retirement. The initial unresolved-worker caps are sixteen per installation and two per workload allocation/principal. Waiting, expired, cancelled and unknown workers count until proven retired; expiry alone cannot create free replacement capacity. Historical records share finite session/audit/backup cleanup obligations, whose full reconciler remains unfinished.

Worker admission does not change the byte-transfer generation, counters or disclosure lease. If intersecting the session, access and profile deadlines leaves less than one second, deny admission without reserving a slot: Kubernetes Job active deadlines require positive whole seconds. Never round the access deadline upward. The Job's active deadline is a Kubernetes cleanup aid, not an authorization timer; the acquisition process and every key/output operation must enforce original absolute deadlines. Current caller cancellation denies further identity use and byte/key operations but does not prove the process stopped. Explicit worker stop/control delivery remains runtime work.

`DownloadDispatcher.Retire` first reads any persisted termination proof. Without one, the driver requires the exact terminal Job and exactly the pinned Pod to have known terminated containers. [ADR-073](worker-startup.md) compares stored original Job/Pod spec digests during cleanup, so a changed startup template does not strand an originally admitted worker. An additional or replacement Pod remains charged for separate orphan reconciliation. When the Job controller itself removed the pinned Pod (for example after `activeDeadlineSeconds`), the exact Job's accounted terminal record is the positive evidence instead: a true `Complete` condition, or `Failed` with reason `DeadlineExceeded`/`BackoffLimitExceeded`, with zero active/ready/terminating Pods, no uncounted terminated Pods and at least one counted Pod. The job-tracking finalizer prevents a Job Pod from disappearing before that accounting. An unknown/lost container, a Pod absent while its Job is not so recorded, or a changed spec cannot establish quiescence. SQL records the original fresh termination observation before deletion. The driver then uses a UID-preconditioned foreground Job delete and confirms both Job and pod-list absence. A fresh final absence proof releases capacity only when its original termination proof matches the stored record.

The production caller is the shared admission-time acquisition cleanup (`ProjectionWorkerCleanup`), which runs at native download preparation and query admission. Besides expired query workers it offers every bound, unretired native download worker of the installation, because those can end before `RunUntil`; each demand makes at most one rotating attempt with the same termination, delete and retirement order. A running worker yields no evidence and stays charged without a failure report; unbound or unclaimed download rows stay charged.

Lost delete responses and reconciler restarts reuse the immutable termination record. Confirmed old termination does not become fresh evidence permission. Missing/unbound/orphan workers and node-loss cases intentionally retain capacity pending a separate qualified cleanup/fencing path. The initial adapter does not force-delete, refund uncertain work, clean an arbitrary caller-selected Job or provide the complete production cleanup lifecycle.

## Qualification boundaries

Pure shape tests reject changed image/command/account, environment injection, sidecars/init containers, host/privileged settings, token-audience changes, secret-volume injection, different owner and unknown spec fields. The SQL/object-store coordinator suite uses explicit simulated Kubernetes jobs for concurrent claims, encrypted audit, lost-create recovery, immutable bindings, held capacity, expiry after locks and restart-safe retirement. The Kubernetes suite uses an owned synthetic executable, actual Job controller, projected token, API RBAC and foreground cleanup. Its human dispatch authority, SQL identity registry and peer certificate remain fixture inputs. Results and source hashes are recorded in [implementation progress](../implementation-progress.md); neither suite is a production installer or complete public investigation.

[ADR-070](worker-configuration.md) now adds protected profile acceptance/rollout fencing, and [ADR-071](worker-enrollment.md) adds audited acquisition credentials and bounded renewal. Still required: globally backed worker allocations and fair scheduling, complete pending/orphan/cancel cleanup, protected issuer bootstrap/local CA, authenticated control relay/token delivery, the acquisition runtime command and end-to-end browser/MCP/native transfer. No collection or disclosure role is enabled by these components alone.

## Bounded foreground retirement observation (2026-10-28)

Paced Native 40756805440 completed the near-full whole transfers but refused the
third worker after `download-delete-proof` and `dispatch/reserve (capacity)`.
The exact deletion subcause was not retained. The existing adapter immediately
checks absence after an acknowledged foreground DELETE, although Kubernetes
can retain the same terminating Job and Pods while garbage collection proceeds,
as described in the [official foreground-deletion contract](https://kubernetes.io/docs/concepts/architecture/garbage-collection/#foreground-cascading-deletion).
A local real-adapter server-authenticated TLS/client-go HTTP regression
reproduced this gap (exit 1, package 0.097s); the other eight original
negative/control cases passed. The synthetic API server presents a CA-verified
certificate; this test supplies no client certificate and does not qualify
mutual TLS or production API authentication.

Complexity gate 1–11: (1) one installed cap refusal, asynchronous-deletion cause
still a candidate; (2) uncertain workers remain charged, existing caps unchanged;
(3) ordinary sequential downloads benefit; (4) Kubernetes foreground deletion is
asynchronous; (5) zero new privileges/credentials; (6) one bounded observation
phase, no fallback or delete retry; (7) zero configuration; (8) existing Kubernetes
GC only; (9) at most 20 observation rounds at 100ms, each at most one Job
GET and one bounded Pod LIST, one synchronous timer at a time, zero goroutines,
SQL/API writes unchanged. Including the initial Job GET and one DELETE, the maximum is 42 requests versus the former four: 38 added reads in the worst case, up to 19 synchronous timers/1.9s intentional waiting, plus request latency. The caller and existing five-second retirement observation
still cap work earlier; (10) no schema/wire migration, rollback restores immediate
refusal; (11) observe the one acknowledged exact deletion rather than raising
worker limits, adding a watcher or replaying reservations. Persisted termination
is historical evidence; it never grants execution or renews a deadline.

Only the exact UID/spec-matching terminating Job and original terminal Pod may
remain pending. Replacement/foreign/mutated objects, request cancellation or an
unavailable read refuse; absence alone without retained termination never frees
capacity. Fixed delete-proof substeps must preserve the existing public cause.
The adapter labels fixed retirement substeps (historical/delete/current/Job or
Pod observation); the coordinator accepts only those finite labels and leaves
uncertain workers charged. Original sentinel causes remain available through
Unwrap. Persisted historical termination remains usable after its observation
expires; no old expiry is imposed retroactively. The new retirement observation
starts once and is not restarted by any GET/LIST.

The actual adapter regression covers one acknowledged asynchronous deletion,
already absent historical objects, cancellation, original caller/retirement
expiry, wrong/replacement Job UID, foreign Pod, denied DELETE and fixed attempt
exhaustion. This is HTTP simulation of GC transitions, not a real controller or
installed-capacity qualification. Existing application coverage checks positive
termination persistence before physical retirement, third-worker slot handling
and closed diagnostics with uncertain charges retained.

The installed fixture now writes and validates the same authenticated PCAPNG
control file before later comparison preparations. Its existing tshark port,
capinfos and packet-overlap checks are unchanged; so are final ranges, owner
and Complete assertions. Format checks occur after the unpaced phase and
before prepare-paced; joined-cleanup no longer includes those earlier checks.
This preserves partial content proof after a late failure without declaring the
whole experiment complete or inventing missing output/drop measurements.

Owned real-controller selection:
`^TestDownloadNativeJobsWithRealKubernetes$`, existing 150s test bound. Its old
outer ten-second retirement loop repeats the adapter call and can mask immediate
foreground-delete refusal. The fixture now uses one adapter call under one original five-second retirement
context and retains its elapsed time/proof. No
new collector, fixture, role, quota or deadline increase is needed. The measured component result below does not establish installed paced
completion.


This single owned selection kept its existing 150-second test context
and one five-second retirement call. The harness's default Go envelope remains
30 minutes; an external 1,100-second timeout followed by a ten-second hard-kill
bounds the complete run below twenty minutes. These three bounds are distinct;
the local gates alone establish no external or real-controller result.


### Owned single-call measurement

One authorized fresh owned selection on immutable
`6e467f360b9d9646d2bc4e5db3b0716e4cecb448` passed:
`^TestDownloadNativeJobsWithRealKubernetes$`. The one retirement call completed
in **115.82032 ms**, with **4.8841782 s** remaining in its original five-second
context. The exact original observed termination remained bound to the fresh retirement
proof; the later deleted-worker peer proof was refused. The selected test took
47.96 s, Go package 49.043 s and complete command 199.314446 s. Actual command,
Go and qualification exits were all zero; no outer retirement retry occurred.

All 3,391 retained qualification-source hashes matched the frozen commit.
`sourceUnchangedDuringTest` was true and cleanup failures were empty. The two
owned clusters, provider containers, networks and worker images were independently
absent. Outputs were archived before restoration; all 35,983 working files then
matched their pre-run hashes and the source tree was clean. No collector or BPF
ran. The fixture uses an actual Restricted product worker, Pod token, TLS/native
idle exchange and foreground Kubernetes deletion. Dispatch/issuer/registry/audit
authority remains synthetic; no native evidence transfer or SQL capacity-row
retirement was qualified by this selection.

The immutable cache archive is
`codex-bf86-resume/native-worker-retirement-owned-1/`.
Its `final-report.json` SHA256 is
`39dc7d1b67dd1dfc0cfae57c4b10d6617f72e0c491817aef1c9d6b08b4235844`;
`artifacts/context-storage-environment.json` SHA256 is
`de8e47bafaa8735c7738336bdbdf2afc76f41f5ec6388a99d8e35da490e5a624`.
The report binds actual commands/exits, all archived source hashes, logs and
owned-resource readback. Original local RED/GREEN and source manifests remain
unchanged. This measures the chosen observation bound on this owned controller;
it neither proves the earlier Native deletion subcause nor completes ranges,
SQL capacity retirement or the installed paced workflow. No limit, quota,
authority or deadline was increased to obtain this result.
