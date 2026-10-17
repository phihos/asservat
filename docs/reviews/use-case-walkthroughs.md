# Use-case tabletop walkthroughs

These are design simulations performed on 2026-10-09, not executed product tests. Each trace follows authorization, identity, budgets, progress and retention through the written contracts. Findings refer to the [ranked review](design-review.md). A design-consistent outcome is not proof the future implementation achieves it.

## UC-01 — Administrator provisions the platform once

**Setup:** an existing IdP, PostgreSQL service, S3/KMS and administrator-managed namespace annotations.

**Trace:** configure protected policies and Secret references → inspect per-feature readiness → qualify the shared namespace source → provision an eligible namespace normally → its group discovers workloads without an Asservat ticket. Read-only inspection says deletion/failover is configured, not tested; a separately selected synthetic qualification verifies behavior.

**Outcome:** no per-application permission YAML on the inherited path. An unavailable kernel core adapter leaves context available. F18 corrected an overclaim; EXP-10/16/17 still need real systems and unfamiliar participants.

## UC-02 — Replica 17 fails in a 20-pod Deployment

**Setup:** all replicas authorized, sensor capacity for 20, capture maxPods 1, no ring unless explicitly enabled.

**Trace:** all 20 arm → pod 17 logs a panic and becomes unready → its pod-scoped trigger qualifies → workload cooldown/capacity admits one context capture → collection pins pod 17. A rolling replacement does not become the incident target.

**Outcome:** the failing replica is no longer invisible behind a three-healthy-pod sample. If it dies first, retained logs/status and TargetGone are useful partial evidence. F01; SC-TGT-005.

## UC-03 — Autoscaling exceeds observation capacity

**Setup:** 10 admitted pods, administrator observation ceiling 10, Deployment grows to 20.

**Trace:** retain the eligible armed set → report CoverageLimited 10/20 → list only authorized skipped pods → preserve workload dump counters and existing rings. A freed slot is filled deterministically; no hidden rotation implying full coverage. Larger ring/parser requirements can independently limit network observation.

**Outcome:** the UI distinguishes saved, partially monitored and fully monitored. No dump-rate multiplication on scale-out. A maintainer can narrow the workload or an administrator can back a larger sensor profile; this is explicit friction caused by finite resources, not a false green state.

## UC-04 — App, sidecar and ephemeral debugger in one pod

**Setup:** whole-pod authorization; a service mesh sidecar and a temporary debugging container coexist with the app.

**Trace:** collect available pod logs/files/process context → attribute each source internally → capture the pod netns once → all outputs share action/recipe limits. Completed init-container files may be unavailable, while retained logs may still exist. No container picker, owner map or traffic selector is offered.

**Outcome:** the pod is the product boundary. A source that grants exec into only one container cannot authorize it; explicit whole-pod eligibility is the remedy. hostNetwork does not mean host-wide packet authority. F05; SC-TGT-006.

## UC-05 — Context now, dump approval later

**Setup:** a five-minute manual capture, logs allowed, a required live dump awaiting distinct-human review.

**Trace:** allocate capture UID → freeze the scope and prepare its ad hoc grant → independently collect logs once → publish the partial case while the dump waits. At minute six approval arrives: the request deadline has already ended, so no dump starts and no scarce node slot was held for those six minutes.

**Outcome:** usable context survives; status explains Partial/ApprovalDeadlineExpired and offers a fresh explicit request. Grant scope contains this capture UID, not a fabricated policy digest. F02/F14; SC-EXE-001/002. Approval waiting remains an intentional requirement.

## UC-06 — Stable policy renewal and recipient change

**Setup:** administrator maximum 30 days, seven-day default; a reviewed stable policy requests 30 days, bounded starts/bytes, short local permits.

**Trace:** approver reviews expiry/scope once → automatic incidents spend the budget → owner edits only recipients → new sharing intent is reviewed/resolved independently while collection scope stays unchanged → later renewal attaches a new matching grant through an audited binding.

**Outcome:** no weekly approval ticket merely from a hardcoded maximum and no digest self-dependency. A changed executable selector/action/target does require review. Future sharing still expires within its separate seven-day maximum and must not silently inherit 30 days. F03/F16; SC-EXE-001.

## UC-07 — A worker reloads and its PID changes

**Setup:** liveCore matchedProcesses selects exact executable path /app/bin/worker within pinned pod UID; process resolves at dispatch.

**Trace:** preview sees PID 420 → app reloads to 621 before dispatch → fresh resolution selects 621 → reserve and pin its start time/node/runtime identity → if 621 exits before attach, mark TargetGone. PID reuse cannot redirect the pinned attempt.

**Outcome:** logical selectors handle reloads without editing policy; selectedPID remains available when exact identity is desired. Reload after batch resolution does not create a silent replacement attempt. F04; SC-ACT-008.

## UC-08 — Two workers need dumps, then a third appears

**Setup:** explicit two-process batch, 256 MiB per process, 512 MiB action cap, 10-second per-process and 20-second total stop budget; administrator permits two starts in one episode.

**Trace:** resolve/deduplicate two matching roots/descendants → reserve both grant starts and total storage/impact → dump sequentially, each separately attributed. If three match before dispatch, refuse the batch before any stop. If another appears later, it is outside the frozen set. An uncertain second start is charged and not retried.

**Outcome:** multiple processes are supported with bounded cost; snapshots have distinct times and are not called simultaneous. The ordinary one-process profile requires a reviewed larger batch profile. F04/F17; EXP-05/19.

## UC-09 — Pprof on a shared localhost endpoint

**Setup:** reusable administrator template, an unambiguous pod port name, already exposed pprof and a valid profiling grant.

**Trace:** resolve pod address/port and template → validate credential/TLS audience against pod workload identity → acquire locally into encryption → record actual serving-process identity only if proved. Duplicate port resolution or an unqualified credential target is refused; a sidecar's presence does not trigger container ACL configuration.

**Outcome:** pod-wide authority is clear, named ports do not falsely prove process identity, and profile absence/busy state is actionable. No pprof injection, forced GC or collector-localhost fallback. F05; EXP-15.

## UC-10 — An agent requests its first capture

**Setup:** an approved client has collection enabled and current whole-pod maintainership.

**Trace:** list_targets → list_diagnostics → preview_capture with a handle/preset → request_capture with preview_id and idempotency key → get_capture shows context/approval status → get_case when available. A network timeout causes the same-key retry; even after preview expiry it returns the existing accepted capture. cancel_capture stops remaining work if authorized.

**Outcome:** no manually entered recipe digest, orphaned capture or implicit approval. A shared recipient cannot discover workloads or collect. Cancellation does not revoke already created shares. F06; SC-MCP-005 and EXP-09/17.

## UC-11 — Log and high memory belong to different replicas

**Setup:** all(log-error, memory-high for 20s), default pod correlation.

**Trace:** A logs an error while B exceeds memory threshold → no pod satisfies both → no combined dump. A later has both within the event window and continuous hold → one occurrence. Repeated true samples do not count as new events; a missing sample resets the hold and Unknown is not recovery.

**Outcome:** default correlation cannot mix replicas. An explicit workload-level policy can combine them, retains all contributors and still selects bounded contributing pods. Sidecar/app signals in the same pod intentionally correlate; the UI does not claim same-process causation. F07; SC-TRG-007.

## UC-12 — Baseline schedule resumes after downtime or DST

**Setup:** five-field cron, explicit zone, deterministic jitter and an approved profiling policy.

**Trace:** connector misses two hours → reconnects → records missed slots and waits for the next eligible slot, without a backlog of profiles. A repeated local DST minute is deduplicated; a nonexistent minute is skipped. Normal grant/capacity limits apply.

**Outcome:** no catch-up dump storm or host-timezone surprise. Baseline coverage gaps remain visible. F08; scheduler qualification remains required.

## UC-13 — A JVM heap file looks stable but is incomplete

**Setup:** artifactCollect watches a confined runtime-output path with settleFor and finite size/deadline.

**Trace:** writer pauses → size/mtime appear stable → collector opens a pinned file identity and captures bounded bytes → qualified format/producer checks fail → evidence is Partial, not a complete heap. Path replacement during acquisition cannot redirect the descriptor; application-owned files are not deleted.

**Outcome:** users see readiness basis and missing completeness rather than an unusable “successful” dump. F08; SC-ACT-007 and runtime pack qualification.

## UC-14 — Raw ring observes far more than it retains

**Setup:** 16 MiB ring, 1 GiB cumulative sensitive observation budget, finite session/rate and current short permit.

**Trace:** high traffic repeatedly overwrites the ring → wire bytes entering sensitive inspection consume the grant even without a trigger → the grant's byte/session limit is reached → sensitive observation stops and reports exhaustion. Restarting does not reset counters; cheap allowed sensors remain active.

**Outcome:** retained ring size is no longer mistaken for sensitive acquisition volume. F09; SC-AUT-006/EXP-19.

## UC-15 — Capture only the next 30 seconds

**Setup:** before 0s, after 30s, bounded staging ring and output reservation.

**Trace:** validate capability/approval → begin at acceptance/dispatch → rotate bounded segments → finalize within the action deadline → report actual start/end and packet loss. If a different request asks for 30 seconds of previous history with no armed sensor, achieved history remains zero.

**Outcome:** the API represents forward-only and already-armed retrospective capture directly. HTTP headers remain a structured projection, not a snaplen trick. F10; SC-NET-006.

## UC-16 — Live Service peers change; then the watch stalls

**Setup:** healthy pod capture, Service backends in follow mode, qualified CNI and progress mechanism.

**Trace:** update membership generation on existing hooks without ring reset → exclude known reassigned/deleted addresses → preserve prior evidence with its old generation. No changes for a minute is not automatically a stale watch. Failed progress/continuity closes affected membership by the freshness deadline; consistent relist establishes a fresh generation.

**Outcome:** continuity is conditional and measurable, not promised from a CLI filter flag. API verification load and packet loss remain EXP-02 gates. F11.

## UC-17 — Deployment A storms while B needs its first dump

**Setup:** the documented 128 GiB pool, separate 16 GiB protected workload allocations and 40 GiB shared burst; A emits 10,000 matches/minute across 20 replicas.

**Trace:** aggregate signals → enforce A's episode/individual-start/hourly-byte budgets → bounded suppression records → A reaches its own hard cap and is refused before acquisition. B reserves within its remaining protected allocation; fair upload scheduling supplies its eligible service. Unknown multipart attempts remain charged.

**Outcome:** neither A's flood nor a policy recreation consumes B's unused protected storage. An actually failed/full shared physical backend remains a limitation. Existing SC-CAP-001–006 survive the new monitoring and batch design; EXP-19 must measure fairness.

## UC-18 — Two owner teams, departure and historical handover

**Setup:** a future-sharing intent has two valid pinned managing team assignments and approved extract selection.

**Trace:** creator leaves → another current member can stop/revoke → one assignment disappears, the other remains valid → publication continues within original scope. A new namespace owner arrives: it gets future evidence, not old cores. Explicit historical transfer/share can grant retained artifacts without resetting counters/deadlines or altering immutable creator provenance.

**Outcome:** no per-share reassignment after staff departure, no hidden transfer of historical user data and no recipient reshare. Existing SC-SHR-008/SC-PER-008 remain required; EXP-12 must verify atomic transfer lineage.

## UC-19 — Six-hour evidence, short-lived indexes and older SQL backups

**Setup:** core acquired at 12:00, six-hour cap and five-minute deletion budget; separate 90-day control metadata maximum and seven-day residual backup horizon.

**Trace:** derived stack at 17:50 inherits the core clock → no read at 17:55 → all evidence/index cohorts due gone by 18:00. Offline spool acknowledgement missing means DeletionOverdue, not DeletedVerified. Control identities leave live storage by day 83 minus cleanup margin; backup/WAL chains expire by day 90. Restore denies expired evidence before serving traffic.

**Outcome:** neither an index delete flag nor a database row DELETE is confused with deletion of every copy. A lock/backup profile that cannot meet the cap is incompatible; the product reports unavoidable late deletion instead of claiming absolute physical erasure. F12/F13; EXP-18.

## UC-20 — Mounted binary and missing air-gapped symbols

**Setup:** a core from a process whose executable differs from its OCI image; the pod is later deleted.

**Trace:** collection records mapping/build identity and optionally captures an approved bounded companion → analyzer stages exact private inputs → mismatched image-only symbols yield BinaryMismatch/partial frames → supplying approved exact symbols allows analysis-only retry while evidence remains retained.

**Outcome:** no latest-tag/public-symbol fallback, reexecution of the workload or second dump for an analysis failure. Captured executable data inherits evidence privacy rather than an unlimited symbol-cache policy. F15; EXP-06/07.

## UC-21 — Requested baseline has expired

**Setup:** incident CPU profile remains readable; the previously bookmarked baseline expired under its own limit.

**Trace:** authorize both before comparison → report baseline unavailable without exposing a hidden baseline → offer currently authorized compatible profiles or a new explicit baseline request. Different sample units/builds are explained; bookmark/pin does not extend retention.

**Outcome:** a helpful recovery path without a hidden retention exception or false regression claim. F18; SC-PRF-005 and EXP-17.

## UC-22 — Hub/SQL fails or restores behind a revocation

**Setup:** a short prepaid local permit exists, some work may already have started, and a share has been revoked after the last backup.

**Trace:** hub outage denies fresh central authority/disclosure → current local work proceeds only within original permits and privacy deadlines → later restore starts RecoveryBlocked → fence old epochs, reconcile current configuration/deny checkpoints and unknown spend → missing completeness forces authority invalidation, not replay.

**Outcome:** longer reviewed policy lifetime does not weaken short disconnected authority. Existing artifacts remain charged and inaccessible until current authorization is established. A SQL transaction does not make an external dump exactly-once. EXP-11/19 remain unrun.

## UC-23 — Revocation races with an agent query

**Setup:** a recipient has a concrete share and a principal/client-bound raw query grant; an offline analysis has started.

**Trace:** manager revokes parent sharing intent → authoritative denial commits before cleanup → analyzer finishes → publisher rechecks parent, share, grant, expiry and durable audit → delivery is denied. Cursor reuse cannot bypass it.

**Outcome:** no new disclosure from a stale result. Previously delivered bytes cannot be recalled from the agent's history; that is explicit, not an Asservat deletion claim. Existing SC-AUT-004/SC-SHR-007/SC-PRV-007 remain required.

## Review conclusion

The revised design has a written path through each journey and explicit failure outcomes. Runtime proof remains missing for every trace. Prioritize pod identity, grant-scope normalization, temporal evaluation, accounting and copy expiry before building the more expensive collectors; otherwise an attractive UI would conceal unreliable incident behavior.

## UC-24 — Maintainer does not know which worker to dump

**Trace:** choose hang → inspect processes once → review exact executable matches and descendants → see two-process serial stop/byte budget → select suggested diagnostic → preview → ordinary ad hoc approval → dispatch resolves current matching identities.

**Outcome:** reload-safe selection without hand-entering PIDs. Indistinguishable interpreters yield an ambiguity and exact-current-process option; an incomplete process inventory cannot assert a complete match set. SC-GDE-001/002/006, EXP-20; tabletop only.

## UC-25 — Agent needs a useful network capture

**Trace:** list target → recommend network diagnostics with missing observations → preview/request ten-second discovery → get_capture and approved discovery projection → optionally focus on a flow → recommend a Service-follow filter and bounded ring → preview the returned diagnostic handle → request capture.

**Outcome:** no invented BPF or size arithmetic required from the agent. TLS, two-Service backend ambiguity and shared sockets stay explicit. Sensitive protocol reconnaissance waits for its individual grant; header survey remains useful without it. SC-GDE-003/004/006, EXP-20; tabletop only.

## UC-26 — Idle sample or capture too large

**Trace:** request 30 seconds of history under a 16 MiB limit → a useful sample estimates 36 MiB → offer an explicit 12-second setting or narrower peer scope. If the sample was idle, show unknown rate and a bounded default with missing-confidence explanation. A later burst reduces reported coverage without raising limits.

**Outcome:** storage limits remain real, sparse observations do not become false guarantees, and repeated discovery from several agents shares workload admission. SC-GDE-003/005, EXP-19/20; tabletop only.

## UC-27 — Repeat last week's useful diagnostic

**Trace:** open the same workload's Recent captures → choose a retained configuration with the desired packet/process settings → Repeat capture restores it → review current differences → Collect again allocates a new request and obtains any required approval. An ordinary replica roll refreshes pod identities without redefining settings; old exact PID or recreated workload requires explicit selection/adoption.

**Outcome:** no copied hashes or rebuilt parameters. Retained configuration can remain useful after evidence expires only within its own approved lifetime. A changed recipe name does not silently select its latest version; double-click retries do not acquire twice. SC-HIS-001/002/004, EXP-11/17/19; tabletop only.

## UC-28 — A shared case and expired parameters

**Trace:** a colleague receives an evidence extract but no workload history authority → history/settings lookup stays unavailable. An authorized maintainer later opens a history summary after its evidence-derived parameters expired → Parameters expired is shown with current catalog choices; no audit/backup fallback restores the old values.

**Outcome:** history helps authorized repeat investigations without extending evidence retention or turning a snapshot share into collection rights. SC-HIS-003/004, EXP-12/18; tabletop only.

## UC-29 — Compose evidence for an intermittent stall

**Trace:** select a Deployment → add HTTP/1 headers, syscall activity and process context → narrow HTTP peers/filter → preview one bounded plan → obtain required HTTP observation approval → collect → inspect gaps and approved summaries through MCP.

**Outcome:** no hand-written DAG or hashes; metadata context can progress independently while a sensitive action awaits review. HTTP encryption gaps, syscall event loss and combined ring/parser costs stay visible. SC-CPR-002/003/004/005, EXP-21/22; tabletop only.

## UC-30 — Publish once and repeat after an upgrade

**Trace:** an authorized maintainer saves a materialized namespace profile → teammates select v1 → v2 is published → history restores v1 and its overrides → an administrator disables v1 → new starts block with an explicit upgrade/customize remedy.

**Outcome:** no silent version substitution or publisher-grant inheritance. Another namespace cannot shadow builtin entries; saving never preserves evidence-derived parameters beyond their deadline. SC-CPR-001/005, EXP-12/18/21; tabletop only.

## UC-31 — Duplicate profilers and busy syscall workers

**Trace:** add the same CPU profiler twice through differently named cards → preview identifies the duplicate underlying endpoint and offers removing it. Then collect syscall metadata on a pod forking many workers → rate/map/ring caps produce visible dropped/unmatched events; another workload retains its protected allocation.

**Outcome:** composition cannot hide duplicate expensive work, and “all processes” does not promise lossless or unbounded coverage. Switching to arguments requires an explicit sensitive variant and pre-read grant; ordinary event queries do not expose buffers. SC-CPR-003, SC-SYS-001/002/003, EXP-19/21/22; tabletop only.

## UC-32 — Preserve the cause before dumping the process

**Trace:** enable a mixed policy → arm bounded packet/syscall rings across authorized replicas → one replica fails a probe → immediately preserve its admitted before/after windows and dispatch the independently approved live dump → a burst of duplicate signals is suppressed while the same recorders continue.

**Outcome:** pre-trigger evidence exists because recording preceded the failure; dump approval/finalization cannot postpone pinning it. Active ring resources and per-incident frozen/output resources are charged separately. Missing history or source loss is explicit. SC-LIF-001–004, EXP-02/19/22; tabletop only.

## UC-33 — Collect now without leaving a recorder behind

**Trace:** repeat a packet/syscall profile manually → preview shows finite manual activation and no existing history → collect the remaining bounded future window → complete/cancel the capture → its session stops. Separately cancelling one policy incident leaves that policy's still-authorized recorders running.

**Outcome:** history restores configuration, never a prior source session or approval; a one-off diagnostic cannot turn into persistent monitoring. Natural cores need a real crash and prepared interception, while live cores require explicit action approval. SC-LIF-001/005, EXP-17/21/22; tabletop only.

## UC-34 — A reasonable-looking combination may disrupt production

**Trace:** a maintainer adds packet and syscall recorders plus a live dump for a 20-replica Deployment → preview distinguishes steady recording on 20 pods from one incident pod and a bounded serial process batch → known pause risk is high, combined overhead/headroom is unknown → declared memory-ring/frozen limits are shown with excluded overhead → a future-only or narrower alternative states the lost pre-trigger coverage → maintainer chooses and uses ordinary approval/submission.

**Expected:** no invented percentage/stop-time prediction, secret trial capture or silent removal of useful evidence. A known profiler conflict or resource breach blocks dispatch. A new material interactive warning refreshes the preview; normal metric refresh of an unchanged authorized policy does not cause approval spam. **Spec path:** REQ-ASM-001/002/005, REQ-CAP-002/003, REQ-LIF-002. **Remaining evidence:** qualified combination benchmarks and participant comprehension, NOT RUN.

## UC-35 — User data, mixed retention and an external agent

**Trace:** a maintainer selects a raw core and Go allocation profile → preview describes memory/credential risk for the core and sampled allocation/label/path risk for pprof → existing policy caps the core at six hours with access ending five minutes earlier → acquisition anchors actual timestamps → owner shares only an approved extract → the recipient/agent sees only that extract's sensitivity/deletion notice and handling guidance → source expiry denies new reads → an unavailable copy makes deletion overdue instead of verified.

**Expected:** relative preview ages become real artifact deadlines; mixed profiles keep their own applicable maxima and derived extracts inherit earlier parent deadlines. A clean scanner or extract access class cannot assert anonymity. Direct evidence queries remind the agent of managed-copy deletion and external-copy limits; Asservat cannot recall previously delivered data. Hidden core categories/counts are absent from the recipient projection. **Spec path:** REQ-ASM-003–005, REQ-PRV-003/004/007, REQ-SHR-001. **Remaining evidence:** privacy/shared-view integration and comprehension, NOT RUN.

## UC-36 — A crash event arrives after the source stops

**Trace:** a probe incident at t0 selects an armed source → pod exits at t0+2 seconds → the exit observation arrives five seconds later → admission saves the old source's retained history during its finite grace → a replacement pod starts its own empty source. Repeat with revocation, exhausted capacity, expiry and node loss.

**Expected:** original pod/session attribution; full prehistory but partial ten-second post-window; no reuse by the replacement; no new snapshot after revocation/grace; bounded retired bytes/session count and explicit loss. **Spec path:** REQ-LIF-003/004/006. Contract fixture passes; runtime tests NOT RUN.

## UC-37 — Approval outlives a rolling replacement

**Trace:** accept a manual core for pod A on node boot N → wait for individual approval → Deployment replaces A with B, or the node restarts → approver accepts the old request → dispatcher compares concrete bindings.

**Expected:** no dump of B and no restarted-node fallback. Authorized context already collected remains accessible; the request becomes partial/failed with a fresh-capture link. A recurring policy still follows replicas under its own dynamic scope and current grants. **Spec path:** REQ-EXE-002, REQ-TGT-005/006. Digest/schema negatives pass; dispatch race tests NOT RUN.

## UC-38 — Analysis fails while handling user memory

**Trace:** acquisition stages an encrypted core into qualified scratch → old writer exits and unmounts → analyzer emits an error containing user data, creates a link and crashes → publisher/cleanup reconcile under an early parent expiry. Repeat with node loss and retained CSI snapshots.

**Expected:** user bytes never enter CRI logs or termination messages; no uncontrolled worker core; hostile outputs cannot become extracts; publication cannot start while a writer is uncertain; deletion remains overdue/charged while backend copies are unverified. Without qualified scratch, analysis is unavailable but encrypted collection remains usable. **Spec path:** REQ-EVD-005/008, REQ-PRV-003/008. Prerequisite ADR-036 accepted; all runtime tests NOT RUN.

## UC-39 — The same alert fails again tomorrow

**Trace:** standard webhook sends one firing alert → HA/retry sends it again with a changed endsAt → resolved arrives → an old firing retry arrives → next day the same fingerprint fires with a new startsAt. Separately reset a CPU/PSI counter during a hold.

**Expected:** one transition for the first episode, no revival after resolution, a distinct later episode eligible under normal rearm/cooldown, and no fake recovery from counter reset. Truncated batches and source/receipt delay remain visible; receivers do not fetch supplied URLs. **Spec path:** REQ-TRG-002/004/006/007. Schema bounds checked; evaluator/receiver tests NOT RUN.

## UC-40 — An operator stops a costly policy

**Trace:** health explains a policy's observations, captures and suppression → operator suspends it or applies a scoped emergency deny → connected nodes acknowledge stops → one disconnected node reaches its finite authority deadline → uploaded evidence remains accessible under existing rights and expires normally.

**Expected:** no new intrusive start or stopped-ring save after applicable denial, bounded disconnected behavior, no capacity refund before termination/reconciliation, and no disabled deletion worker. UI states actual acknowledgment/expiry rather than instantaneous global success. **Spec path:** REQ-TRG-005, REQ-LIF-004/006, capacity/federation rules. Tabletop only; cancellation/watchdog and participant tests NOT RUN.

## UC-41 — Save the recording without dumping production

**Trace:** a policy with packet/syscall rings and liveCore explicitly enables reviewed manual saves → a maintainer sees a latency spike before the detector fires → selects the current pod's sources → preview shows incremental copy/encryption/upload cost, sensitivity and source-aged deletion → submit once → preserve the admitted lookback ending at acceptance → poll the normal capture view. An optional per-capture sharing declaration is evaluated independently.

**Expected:** no detector injection, core/command, new recorder, future window or policy SharingIntent inheritance; original policy executor and current caller rights are both checked. Source audience and retention remain authoritative. Client retry returns the same capture/t0; an extract-only recipient cannot request it. **Spec path:** REQ-SAV-001–004. Synthetic scopes/MCP/lifecycle/manifest checks only; runtime/authorization/usability NOT RUN.

## UC-42 — Ring changes between preview and save

**Trace:** preview two recording sources → one restarts and the other remains ready → submit with the old handles → refresh selection if change is known before acceptance; otherwise report the failed old source alongside any admitted useful output → rapid clicks encounter shared cooldown/quota → cancel one active save → repeat its history entry later.

**Expected:** no replacement source or silently newer window, bounded partial outcomes and charges, no retry queued after cooldown to create a later capture. Cancellation leaves independently authorized recorders running. History repeat discovers fresh sources and preserves only selected action/lookback preferences; the old policy's dump actions, grants and sharing do not follow. **Spec path:** REQ-SAV-002–004, REQ-LIF-006. Offline boundary checks pass; node/SQL/ring race tests NOT RUN.

## UC-43 — Collection works before encrypted analysis storage is ready

**Trace:** administrator enrolls a region with object/KMS storage but no qualified encrypted scratch class → maintainers collect and save authorized recordings → case shows evidence stored and analysis unavailable → administrator configures and qualifies bounded encrypted input/output PVCs with cleanup/fencing evidence → analysis becomes eligible while source evidence still exists.

**Expected:** no default plaintext PVC or shared-emptyDir fallback, no lost collection, clear AnalysisScratchUnavailable remedy, no retroactive extension of source retention. Admission reserves analysis memory/scratch and checks expiry before staging. Node loss/failed backend deletion remains overdue and charged. **Spec path:** accepted ADR-036, REQ-EVD-005/008, privacy copy-ledger requirements. Runtime storage/isolation/deletion tests NOT RUN.

## UC-44 — Complete an investigation in a local tool

Added after the maintainer exposed a missed elementary workflow. Earlier simulations stopped at Asservat queries. A regular developer must download a saved PCAPNG and open Wireshark, or download a native core plus available exact companions and open compatible GDB. Apply the same completion criterion to every gathered kind and derivative; check missing authority, interrupted large files and external-copy handling. The [correction and test matrix](local-investigation.md) supersede the blanket export ban. Runtime/user qualification remains NOT RUN.
