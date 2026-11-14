# UX friction audit: creating captures and policies

Worktree `/home/phil/Projekte/asservat-ux` at `5d4667715` (ADR-330 rewrite). Scope:
specs/execution, actions, action-lifecycle, triggers, targets, capture-assessment,
capture-history, capture-profiles, packets, syscalls, profiles, plus `examples/*.yaml`
(and the schemas/chart files these reference). Known ADR-334 items are not repeated.
Comparisons: Kubeshark, Inspektor Gadget, Retina Capture CRD, Pyroscope/Parca, Grafana,
Prometheus Operator, Kyverno, Argo CD.

## Task walkthroughs (as specified today)

### A. "Capture packets from my Deployment when it restarts"

| Who | Step | Objects / fields |
| --- | --- | --- |
| Admin | Enable collector (`collector.enabled`, disposable-host marker file on every node) | Helm values |
| Admin | Fill `capacity.poolSpec`/`policySpec` (default `{}` ⇒ every capture `CapacityNotAllocated`) | EvidenceStoragePool (~14 numbers) + EvidenceBudgetPolicy (~30 numbers, `scope.clusterID` UUID) |
| Admin | Bind the `automation` ClusterRole in the namespace | RoleBinding |
| Team/admin | AccessBinding with `spec.automation` listing `packetCapture` + 4 limits | AccessBinding (~10 fields) |
| Team | Write DebugPolicy **in `asservat-system`** (admin-only per ADR-328) naming `target.cluster` as a UUID | DebugPolicy: 17 required leaves for expanded form (target 6–7, detector 3, `when`, `recipeRef.name`+**hand-computed SHA-256 digest**, 4 budgets, retention, suspended, `observation.mode` with one allowed value, 3 evaluation) or composition form (component id + 3-part profileRef + required `maxTotalBytes` + `maxDuration`) |
| Team | Call `activate_policy` in browser/MCP (applying YAML does not activate) | — |
| Team | Re-do with a dummy edit after 7 days (grant default), 30 days (envelope), 100 executions, or exhausting `maxObservedBytes` | — |

Result: **4 CRD kinds + Helm values, ~7 steps, ~25 user fields + ~55 admin fields — and it is
then refused anyway**: triggers.md:126-128 rejects every recipe except pod-status at activation.
Kubeshark: `kubeshark tap deploy/checkout` (1 command). Retina: one `Capture` object, ~5 fields.

### B. "Take a goroutine profile now"

| Who | Step |
| --- | --- |
| Admin | Helm `region.executor.profileEndpoints` template + `profileAuthorization` |
| App owner | Add a *named* container port (`diagnostics`) to the Deployment → rollout (profiles.md:157) |
| Admin | Configure `approvals.stepUp` (without it nothing can ever be approved; authorization.md:51) and an `action-approver` binding for a *second* person |
| User | Author a custom recipe/CaptureProfile: builtin `go-cpu/v1` exposes only duration/timeout/bytes (capture-profile-go-cpu.yaml:41-50), so goroutine needs ~15 fields incl. 4 endpointBindings fields and a self-declared `impact: intrusive`; EvidenceRecipe/DebugCapture CRDs are not shipped in the chart |
| User | Preview → request (`reason`, `idempotencyKey`, absolute `deadline` required in CRD form) |
| Approver | Distinct human, fresh step-up login, approves **within the 5-minute capture deadline** |
| User | Summary is readable; raw/native download only if result access was selected in the same review |

Result: **2 humans, ≥6 steps, 3 admin prerequisites incl. an app redeploy.**
Comparable: `kubectl port-forward` + `go tool pprof …/goroutine` (2 commands, 0 approvals);
Pyroscope/Parca: already continuously there.

### C. "Record syscalls for 5 minutes"

Not possible. syscalls.md:19 caps the post-trigger window at 60 s (portable ceiling) and
the shipped profile uses 10 s after; a manual "Collect now" with the default profile has no
prehistory (action-lifecycle.md:500), so it yields ~10 s. The manual capture deadline is
5 minutes (execution.md:185, ergonomics.md:41) including finalization, and the default
Helm `captures: 1` concurrency (values.yaml:243) blocks all other captures in that cluster
meanwhile. Workaround: five back-to-back 60 s captures with gaps, each a separate
preview+request (+ approval each when `requireRecordingApproval` is set), with the
explicit coupled edit `executionMode: onTrigger` + `before: 0s`.
Inspektor Gadget: `kubectl gadget run traceloop --podname x` until Ctrl-C; `strace -f -p`.

Defaults usable? **No** for all three out of the box (capacity `{}`, collector off, no
step-up ⇒ no approvals). Limits sensible? Several are far below normal workflows (below).

## Findings

### UXC-01 — Only pod-status can be triggered (high)
- triggers.md:95-97, 126-128; ADR-228 decision 1.
- Today: any policy whose recipe is not `builtin-pod-status-v1` (packets, syscalls, pprof,
  logs) is "rejected at activation with its field path". Examples policy-composed.yaml,
  policy-pprof.yaml, policy-deployment.yaml, policy-trigger-lifecycles.yaml describe
  policies the normative text forbids.
- Friction: the product's main promise (capture X when Y happens) is specified away by an
  "initial implementation" restriction written as a requirement. Retina/Kubeshark/Pyroscope
  have no equivalent.
- Origin: agent-added (implementation-slice scoping copied into spec). Fix: move the
  restriction to implementation-progress; spec states the general contract; activation
  reports `Unsupported` per action only when a capability is actually missing.

### UXC-02 — Team policies must be written into the admin-only hub namespace (high)
- policy-automation.md:25; policy-restart.yaml:4-10; ADR-228 decision 4 vs ADR-328/329.
- Today: DebugPolicy lives in `asservat-system` and names `target.cluster` by UUID. ADR-328
  makes that namespace administrator-only, so a team cannot `kubectl apply`/GitOps its own
  policy; examples disagree (policy-composed/pprof/statefulset use `namespace: payments`).
- Friction: Prometheus Operator, Kyverno `Policy`, Argo CD apps-in-any-namespace — teams
  put their objects in their own namespace. Maintainer requires "Kubernetes-only permission
  configuration, low-effort operator workflows".
- Origin: agent-added (ADR-228). Fix: same move as ADR-329: DebugPolicy (and DebugCapture,
  CaptureProfile namespace catalog) in the workload namespace of the workload cluster,
  delivered by the connector; drop `target.cluster`/`namespace` (implied by location).

### UXC-03 — Users must hand-compute recipe digests (high)
- policy.schema.json & capture.schema.json: `recipeRef.required: [name, digest]`;
  policy-restart.yaml:30-31, capture-manual.yaml:19-21, policy-pprof.yaml:29-31.
- Contradicts execution.md:192 "clients never compute hashes" and examples/README
  "need no manually calculated recipe digest". Nobody can write an RFC 8785 SHA-256 by hand.
- Comparable: Argo CD/Helm reference by name (+ optional version); controllers pin.
- Origin: agent-added. Fix: `recipeRef: {name}` (optional `version`); controller resolves
  and reports the pinned digest in `status`; approval binds the resolved digest.

### UXC-04 — No defaults: everything is required (medium)
- policy.schema.json required `budgets` (4 fields), `retention`, `suspended`,
  `observation.mode` (const `allAuthorized` — a required field with one legal value),
  `evaluation.*` (3); target.schema.json requires `maxPods`, `selection`, `adoption`,
  `workloadRef.apiVersion` (derivable from kind); capture-composition requires
  `maxTotalBytes`/`maxDuration` (capture-profiles.md:41 says the browser computes them);
  recipe actions carry an authored `impact` that may never differ from the derived one
  (recipe-packets-next.yaml:48, capture-profiles.md:29).
- Friction: specs state defaults (targets.md:45 `maxPods: 1, triggeringPod`; triggers.md:55
  budgets; ergonomics 5-min deadline) but the schemas force users to restate them.
  Kyverno/Prometheus rules need only the semantic fields.
- Origin: agent-added. Fix: make all of these optional with the documented defaults; drop
  `observation.mode`, `suspended` default false, derive apiVersion and `impact`.

### UXC-05 — DebugCapture CRD needs `reason`, `idempotencyKey` and an absolute `deadline` (medium)
- capture.schema.json required `[…, reason, idempotencyKey, deadline]` (`date-time`);
  capture-manual.yaml:22-25.
- Today a kubectl user writes a free-text reason, invents a key and types a timestamp ≤5 min
  in the future; a GitOps sync after that minute applies an already-expired capture.
  ergonomics.md:41 itself says operation identity derives from UID/generation and the
  deadline defaults to 5 min.
- Comparable: Velero `Backup`, Retina `Capture`, Kubernetes Jobs: no idempotency key, relative
  `ttl`/`activeDeadlineSeconds`, no mandatory reason.
- Origin: agent-added (reason required nowhere in AGENTS.md). Fix: drop `idempotencyKey`
  (UID+generation), relative optional `timeout`, optional `reason`. Also: chart ships no
  `debugcaptures`/`evidencerecipes` CRDs although examples present them as kubectl resources.

### UXC-06 — Approval must arrive within the 5-minute capture deadline and needs configured step-up (high)
- execution.md:185 (`approvedAcceptance`: one capture deadline within five minutes),
  execution.md:226, actions.md:402, authorization.md:51 ("Without configured step-up
  nothing can be approved"; approval lasts one hour).
- Today: an intrusive/sensitive manual capture is skipped with `ApprovalDeadlineExpired`
  unless a distinct `action-approver` re-authenticates with an `acr` step-up within
  5 minutes. A default install has no step-up ⇒ no profile, dump, HTTP-header or raw capture
  is ever possible.
- Comparable: GitHub environment approvals/Argo CD sync windows wait hours to days;
  Teleport access requests default to hours; step-up is optional everywhere.
- Origin: the independent approval is a MAINTAINER decision (investigation-approval.md
  intro); the 5-minute window, mandatory step-up and 1-hour lifetime are agent-added.
  Least friction: pending approval waits for a configurable time (default 1 h, max 24 h)
  and the capture deadline starts at approval; step-up optional (off by default, ordinary
  OIDC session suffices); show pending requests in the approver's console/MCP list.

### UXC-07 — Any pprof GET is "intrusive" and needs a second human (high)
- profiles.md:188 ("intrusive … even if the mechanism is an HTTP GET"), profiles.md:331,
  357 (`liveProfile` requires raw approval regardless of settings), actions.md:284.
- A goroutine/heap(no GC)/allocs/mutex snapshot is a read the app already serves; Pyroscope,
  Parca, Grafana Pyroscope scrape these continuously without approvals. Only forced GC,
  changed sampling rates and long CPU/trace intervals have meaningful impact.
- Origin: agent-added; maintainer only required "first-class pprof/similar runtime
  profiles". Fix: classify snapshot/cumulative Go profiles and ≤10 s CPU as `observe`
  under ordinary maintainer rights; keep approval only for forceGC, sampling changes,
  traces and external profilers, or behind an opt-in `approvals.requireProfileApproval`.

### UXC-08 — Every policy-captured profile needs a per-artifact human raw approval to download (high)
- profiles.md:345-349 ("current human raw approval must independently cover the exact
  published artifact"); investigation-approval.md REQ-INV-002 excludes automatic policies.
- Today: a CPU-spike policy collects profiles at night; in the morning each one needs a
  separate review before the team can open it in `go tool pprof`.
- Comparable: Sentry/Pyroscope: the owning team sees what its rules captured.
- Origin: agent-added. Maintainer required native download of all evidence and team
  ownership. Fix: artifacts captured by an approved team policy are downloadable by the
  policy's audience under ordinary rights; raw approval only where the data class is raw
  user memory (cores/heap dumps), decided once at policy approval (extend resultAccess to
  policies).

### UXC-09 — Recording windows far too short for "record for N minutes" (high)
- syscalls.md:19 (post-trigger max 60 s; shipped 10 s), actions.md:385 (packets 30 s after,
  admin max 300 s), execution.md:185 / ergonomics.md:41 (5-min capture deadline),
  action-lifecycle.md:500 (manual default yields no history ⇒ only `after`).
- A 5-minute syscall or packet recording is impossible; a default manual "capture packets
  now" records 10 s.
- Comparable: Kubeshark/tcpdump/traceloop run until stopped or a size cap; Retina Capture
  `duration` up to hours with `maxCaptureSize`.
- Origin: agent-added numbers. Fix: manual finite recording = `duration` (default 60 s,
  admin max e.g. 1 h) bounded by bytes/events, with Stop (ADR-313 already exists); capture
  deadline = duration + finalization margin, not a fixed 5 min.

### UXC-10 — Manual "Collect now" with a shipped recorder profile needs a coupled two-field edit (medium)
- action-lifecycle.md:444, 500; capture-profiles.md:37, 95; packets.md:287.
- The shipped network/syscall profiles default to `ongoing, before: 30s`; manually they
  return "no prehistory" and 10 s; to record forward the user must switch
  `executionMode: onTrigger` **and** set `before: 0s` or get a validation error.
- Origin: agent-added. Fix: for manual captures normalize ongoing recorders to a forward
  recording of `duration` automatically (manual has no trigger, so "before" is meaningless);
  drop the onTrigger/before:0 coupling from the user surface.

### UXC-11 — Every DebugPolicy expires and dies on cumulative counters (high)
- execution.md:188 (`policyAuthority` mandatory for every DebugPolicy, original expiry,
  "no renewal by login, reapply, restart or retry"); approval-policy.yaml (default 7 d, max
  30 d); access-binding-automation.yaml:25-28 (`maxLifetimeSeconds` 30 d, `maxExecutions`
  100, `maxObservedBytes`); policy-automation.md:21; triggers.md:156-161 (reactivating the
  unchanged revision is refused).
- Today: even a restart→pod-status or sanitized packet policy stops after ≤30 days or 100
  occurrences; reapplying the same YAML is refused; the owner must make a dummy edit and
  activate again.
- Comparable: PrometheusRule, Kyverno policies, Alertmanager routes: no expiry; rate limits,
  not lifetime totals.
- Origin: MAINTAINER decision is "expiring policy grants for **automatic intrusive
  actions**". Extending expiry and lifetime counters to non-intrusive policies is
  agent-added. Least friction: non-intrusive policies don't expire and use rate budgets
  only; intrusive grants expire but can be renewed in place by an approver (one click, no
  new generation, counters continue), with notice before expiry (renewalNoticeSeconds
  already exists).

### UXC-12 — Cumulative observed-byte budget silently kills always-on sanitized recorders (high)
- action-lifecycle.md:490 (wire bytes before filtering, charged by consumption),
  capacity.md:140 (zero cumulative credit denies acquisition), access-binding-automation.yaml:28.
- 20 replicas at 10 MB/s each exhaust 1 TiB in ~1.4 h; the policy's packet/syscall
  rings then stop for good ("restarts never refill").
- Comparable: Hubble/Kubeshark/Pyroscope cap rate and memory, never a lifetime total.
- Origin: agent-added for sanitized sources (AUT-006 targets raw/HTTP). Fix: sanitized
  network-header/syscall-metadata rings use rate + memory ceilings only; cumulative budgets
  only for raw payload/argument sessions.

### UXC-13 — Sensitive sessions max 1 hour; policy sources never re-armed (high)
- authorization.md:207 (`maxSessionSeconds` ≤ 1 h), action-lifecycle.md:474, 490
  ("runs until its accepted hard end … It is not renewed"), grant-packet-observation.yaml:28
  (30 s).
- An approved HTTP-header policy records for at most an hour, then the ring is gone until a
  new approval; any policy's recorder ends at the admin session ceiling with no specified
  re-arm.
- Origin: agent-added. Fix: a policy source is re-armed automatically for the policy's
  approved lifetime (per-session caps limit memory, not authority); state that explicitly.

### UXC-14 — Capacity disabled by default; per-workload protected slots (high)
- values.yaml:129-131 (`capacity: {}`), capacity.md:55 (no match ⇒ `CapacityNotAllocated`),
  budget-policy.yaml (`maxWorkloadAccounts: 4`, ~30 byte/rate fields), storage-pool.yaml
  (`workloadSlots: 4`, `protectedPerWorkload` 16 GiB, no overcommit), budget-policy scope
  `clusterID` UUID.
- Today nothing can be captured until an admin writes two CRDs with ~45 byte counts; the
  example permits 4 capturing workloads per namespace, and protected no-overcommit
  allocations make 100 workloads need 1.6 TiB reserved.
- Comparable: Loki/Mimir per-tenant limits with working defaults; ResourceQuota is optional.
- Origin: storm/cross-workload protection is a MAINTAINER requirement; reserved slots and
  mandatory configuration are agent-added. Least friction: chart renders a default pool
  sized from the object store plus a default per-workload hard limit (fair share, e.g.
  min(10 GiB, 5 % of pool)) and storm rate; no slots, no reservation; budget policies only
  to override.

### UXC-15 — One concurrent capture per cluster, 16 policies per cluster (high)
- values.yaml:117, 243 (`captures: 1`), ADR-228:71 ("At most 16 active policies per
  workload cluster"), trigger defaults triggers.md:55/121 (1 occurrence per workload per
  5 min shared by all policies).
- One running 60 s recording blocks every other user's and every policy's capture in that
  cluster; a platform with 30 teams cannot give each team one policy.
- Origin: agent-added. Fix: default concurrency derived from collector/connector capacity
  (e.g. 16), no fixed policy count (cost scales with watched workloads, already bounded by
  informers); keep the shared per-workload storm budget only for expensive actions.

### UXC-16 — Workload recreation stops policies (`adoption: pinUID` required) (medium)
- targets.md:5, SC-TGT-001; target.schema.json `adoption` required; history keys
  capture-history.md:172.
- Argo CD "Replace", `helm uninstall/install`, blue/green recreate ⇒ `TargetReplaced`;
  the team must edit and re-activate (and re-approve).
- Comparable: PodMonitor/Kyverno/Pyroscope select by name/labels and follow recreation.
- Origin: agent-added. Fix: default follows the same name in the same namespace (record
  the new UID in status/provenance); `pinUID` opt-in.

### UXC-17 — Too many overlapping "profile/preset/recipe" concepts (medium)
- capture-profiles.md:3-5, 41; ergonomics.md:25-37; profiles.md:157 (`source.profileRef`
  = endpoint profile); actions.md:392 ("evidence profiles"); triggers/packets "engine profile".
- A user must distinguish presets (`presetRef`, not composable, pod-status special-cased),
  EvidenceRecipe (`recipeRef`+digest), CaptureProfile composition (third form), diagnostic
  handles, runtime *profile* artifacts, endpoint *profiles*, engine/impact/storage profiles.
- Comparable: Kubeshark/Retina have one capture object with a filter; Pyroscope one
  scrape config.
- Origin: agent-added (CaptureProfiles are a maintainer requirement; the rest is not). Fix:
  presets become builtin CaptureProfiles; one authoring form `profiles: [...]` + optional
  inline actions; rename endpoint profiles to `endpoints`.

### UXC-18 — Goroutine profiles need a custom recipe and a named port (medium)
- capture-profile-go-cpu.yaml:41-50 (type not editable), profiles.md:157 (template binding
  requires `portName`), recipe-pprof-template.yaml:58-62.
- Fix: ship `builtin/go-profile/v1` with editable `type`; allow a numeric port within the
  template's range (already allowed for admin profiles, profiles.md:304-305) so apps need no
  redeploy; optionally detect `:6060`.

### UXC-19 — Alert trigger ignores workload-level alerts; manual Secret copy (medium)
- triggers.md:201-214.
- Alerts without a `pod` label (most service-level rules, e.g. HighErrorRate by `job`/
  `service`) are dropped; the operator copies a Helm-generated bearer Secret into
  Alertmanager config by hand.
- Fix: map `deployment`/`statefulset`/`service` labels to the workload and select the pod
  by the existing deterministic `selection`; let the chart reference an existing Secret the
  Alertmanager already mounts (or same-cluster ServiceAccount token, as ADR-334).

### UXC-20 — Examples contradict the normative limits (medium)
- policy-composed.yaml:20 `stream: stderr` (rejected, triggers.md:242); policy-composed:30,
  policy-pprof.yaml:23 `sampleInterval: 5s` (minimum 30 s, triggers.md:282);
  REQ-TRG-001 default "5-second metric interval" vs 15 s/30 s in the resource section.
- Users copying examples get admission errors. Fix: run every example through the same
  admission validator in `make spec-check`; reconcile the interval text.

### UXC-21 — Capture history parameters expire after 7 days (low)
- capture-history.md:208, 210.
- "Repeat capture" from last month's incident is unavailable by default. Grafana/Kibana
  saved queries persist. Fix: pure configuration snapshots default to the evidence
  retention maximum or 90 days; only discovery-derived values keep the source deadline.

### UXC-22 — Port names refused in pcap filters (low)
- packets.md:104, SC-NET-007 (`tcp port https` refused).
- Fix: map the fixed IANA well-known names from a static table (no resolution) or show the
  numeric rewrite as a one-click fix.

### UXC-23 — Small per-node ceilings (low)
- values.yaml:202-203 (`maxActiveSources: 16`, 16 MiB/s input per node), triggers.md:55
  (two artifact streams per node).
- With packet + syscall per pod, only 8 recorded pods per node. Fix: size from node
  allocatable/collector limits; document as tuning, not a hard cap.

### UXC-24 — Stale objects contradict ADR-330 D8 (low)
- charts/asservat/crds/capacityreservations.yaml still shipped; D8 removes CapacityReservation CRDs.
- Fix: delete the CRD with the D8 slice.

## Counts

24 findings: 12 high (UXC-01, 02, 03, 06, 07, 08, 09, 11, 12, 13, 14, 15),
8 medium (04, 05, 10, 16, 17, 18, 19, 20), 4 low (21, 22, 23, 24).
Maintainer-rooted (honor with less friction): 06 (independent approval), 11 (expiring
intrusive grants), 14 (storm/cross-workload protection), 17 (capture profiles exist).
All others agent-added.
