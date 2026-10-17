# Capture impact and sensitive-data assessment

Every capture/policy preview MUST help a maintainer judge the **combined effect on the workload**, the data that may be observed or retained, and how that data expires. The assessment is a deterministic, explainable projection of the effective plan and available authorized context. It uses the existing planner, admission and privacy services; it is not an embedded AI, a new permission system or a guarantee of harmless collection.

The initial runtime [pod-status assessment](../docs/architecture/context-assessment.md)
implements this contract for `builtin-pod-status-v1` only. Other mechanisms and
public workflow composition remain pending; its configured output ceiling is not
a measured overhead result.

## REQ-ASM-001 — Assess each mechanism using current evidence

Resolve a versioned rule for every action/adapter/runtime, its execution mode, parameters, process/pod fanout and data representation. Use qualified capability/benchmark records and already authorized, timestamped workload/node metrics where available. Pin rule/capability digests and identify the observation age, applicable environment and missing inputs. Preview MUST NOT run a trial profiler, attach a debugger, read application memory/files, inspect packet payload or execute a command to discover whether the planned capture is safe. An optional survey remains an explicitly selected ordinary capture.

The assessment names the relevant effects: application pauses/GC, application CPU/allocation, kernel/node/collector CPU, ring/parser/scratch memory, storage/I/O/upload contention, altered application state, and diagnostic interference. Describe where the work happens; limiting the collector pod does not bound work performed inside the application or kernel. Existing `impact: observe|sensitiveRead|intrusive` remains an authorization classification, not a quantitative performance forecast.

For each action return a qualitative level (`low`, `moderate`, `high`, `unknown`), a hasUnknowns flag, effect codes, concise explanation and typed quantities when supported. Distinguish **configured limits**, **qualified measurements** and **model estimates**. Every quantity identifies its coverage and exclusions: ring/parser allocations are not total collector memory, and payload output caps exclude object/encryption overhead. Disk-backed rings use storage quantities, not memory quantities. Every estimate/measurement has a pinned evidence reference; a measurement also states sample/environment applicability. No universal CPU percentage, expected dump size, latency increase or pause duration may be invented from action name, eBPF branding, successful schema validation or output byte cap. Limits are shown as limits: a 10-second stop budget is not a predicted 10-second pause or proof that every blocked-kernel operation can be cancelled within it.

Missing/stale metrics, an unmatched runtime/kernel/CNI, sparse discovery, an arbitrary command/file, unqualified adapter or interaction produces explicit uncertainty. Unknown does not mean low impact or zero user data. Protected qualification/rules may establish known effects without exact numerical estimates. Publisher descriptions and user annotations cannot replace these rules or suppress warnings. A reviewed declarative application classification may make the assessment stricter; lowering it follows existing administrator qualification/privacy rules.

### SC-ASM-001

Given a live dump with a configured stop budget, an unqualified CPU profiler and stale pressure metrics, when previewed, then the user sees possible pauses, the separate stop limit, missing measurements and the current uncertainty. No estimated percentage or test capture is fabricated, and selecting a profile cannot hide these effects behind its friendly title.

## REQ-ASM-002 — Explain the combined plan and offer alternatives

Assess the normalized recipe after allowed context deduplication, with its actual execution schedule and lifecycle. Report steady observation cost across observation pods separately from incident acquisition/frozen snapshots across selected pods. Include additional active collectors against the same workload/node through authorized aggregate pressure/accounting, without exposing another team's targets, parameters or evidence. A one-pod dump cap must not make 100 continuously recorded replicas look cheap.

Aggregate compatible **reservations/limits** with their units, phase and scope. Sum independent concurrent allocations and retained/frozen copies; use peak simultaneous allocations for validated serial schedules and cumulative I/O/stop budgets where appropriate. Never sum percentages with different denominators, multiply a per-node shared buffer per pod, treat output maxima as expected sizes, or add individual latency estimates to claim a measured combined latency. If the schedule, overhead or interaction is not qualified, show the unknown and the known conservative reservations separately.

Flag profiler conflicts, measurement distortion, overlapping high-rate hooks, limited application/node headroom, dump/snapshot bursts and low effective upload service. Known hard conflicts or violated ceilings remain blocked by ordinary admission; displaying a warning cannot waive them. The combined level cannot be below any known component level; hasUnknowns is true if any component, required input or interaction remains unknown. Display a known level with uncertainty as a known minimum, not a confident total estimate. Return bounded, actionable alternatives: narrower peers/syscalls/processes, shorter windows/lower sampling, fewer incident pods, metadata projections, serial compatible collection or removing an expensive action. Explain what diagnostic coverage each alternative loses; never silently apply it or stop an application to benchmark it.

Re-evaluate at preview, submission, source arming and intrusive dispatch. Assessment identity binds the execution plan, rule/capability revisions and freshness window; it does not grant authority. Initial preview validity is at most five minutes, bounded by the preview handle; metrics are fresh only up to 60 seconds old or a stricter applicable capability limit. Future timestamps are invalid. These are maximum planning ages, not execution-permit lifetimes; local dispatch uses current admission health. A changed plan or newly discovered material warning in an interactive preview requires refreshing that preview, not a new generic consent dialog. Routine metric refreshes do not force repeated approval for unchanged reviewed policies. Runtime admission/circuit breakers still enforce current ceilings; report changed conditions and measured collector impact, without claiming that observed latency correlation proves capture caused it.

### SC-ASM-002

Given two individually permitted recorders, a dump and 20 observed replicas but one incident pod, when compiled together, then steady costs cover 20 pods and dump/frozen costs cover the admitted incident. Missing coexistence measurements stay explicit; incompatible profilers or insufficient memory remain blocked. An offered future-only/narrower alternative states the history or traffic it will miss.

## REQ-ASM-003 — State what sensitive data may be observed and saved

For every mechanism and the combined plan, expose the existing privacy classification plus bounded categories that **may be retained** and that may be **inspected transiently but excluded from the declared retained representation**. Categories include user content, credentials/tokens, personal identifiers, addresses, paths, profile labels and unknown application data. “May contain” is a conservative mechanism assessment, not a claim that a person's data was found. Protected workload classification, actual action mode and the reviewed transform determine it; a clean pattern scan does not prove absence.

| Mechanism | Initial assessment guidance |
| --- | --- |
| Core/full runtime heap dump | Memory may include user objects, secrets and credentials; raw binary redaction is not assumed complete |
| Go pprof CPU/heap/counter profile | Describe sampled stacks/allocations, labels and paths as applicable; a Go heap allocation profile is not a full object heap dump, but identifiers/labels can still be sensitive |
| Raw packets or syscall arguments/buffers | Payload/argument data may contain user content, credentials, paths and identifiers within configured capture bounds |
| HTTP-header projection | Trusted parser may inspect bodies/unapproved headers transiently; stored allowlisted fields can still identify users; clearly state excluded fields and unsupported encrypted protocols |
| Network headers or syscall metadata | Do not retain application payload/user-memory arguments under the qualified mode; addresses, timing and process context still receive conservative privacy controls |
| Logs, arbitrary files and command output | May include user data/secrets; unknown formats remain unknown, not safe because the output is short or read-only |

Encryption, metadata/extract access class, header-only capture and redaction are not proof of anonymity. Pre-collection classification never creates verifiedNonPersonal by itself; only an existing reviewed transform assessment can support that classification. Show raw-source risk separately from the projection a recipient will receive. Generic assessment text must not itself reveal a discovered secret, file value, unapproved header, user identifier or another team's configuration.

### SC-ASM-003

Given HTTP projected headers plus a raw core, when the plan is reviewed, then the parser's transient inspection and the core's retained-memory risk are both visible. Sharing only a safe projection does not relabel the core as harmless. A pprof heap profile is described as sampled allocation data, and an unknown custom command retains unknown-content warnings despite a clean scanner result.

## REQ-ASM-004 — Explain automatic deletion and handling boundaries

Before collection show effective per-action **access age** and **deletion due age**, the administrator's maximum age, applicable policy references and the age anchor. The contract distinguishes accessAgeSeconds, deleteAgeSeconds and maximumAgeSeconds: a shorter requested lifetime also brings deletion forward; the hard cap is not the default storage promise. Use relative durations for future evidence; do not promise an absolute timestamp from preview time or reset the clock at a future trigger/upload. After acquisition, show actual expiresAt and deleteBy for each authorized artifact, including the earliest retained ring/source/parent anchor. Mixed plans may have different deadlines; show the earliest prominently with per-artifact details. Explain clamped requests and that derived copies/shares do not renew retention.

The exact manual `pod-status/v1` preset uses `anchorRule: submissionPreparation`: its first admitted registration starts the interval at submission preparation, and waiting for collection consumes that lifetime. Accepted retries keep the original anchor and deadlines. It does not use preview creation or reset at acquisition. Other mechanisms retain `firstAcquisitionOrEarlierSource` where qualified; the pod-status rule does not reinterpret ongoing recordings, older sources or derived evidence. Browser and MCP must convey the same typed anchor before submission.

Describe automatic deletion as applying to **Asservat-managed copies**. Access cutoff, deletion scheduled/in progress, deletion verified, overdue/unknown and restricted preservation are distinct visible states. Never show “deleted” merely because access expired or an object-store delete marker exists. Show active configured preservation decisions and their authority only to eligible viewers; never promise unconditional deletion where an approved exception applies. Overdue cleanup remains a visible incident with ordinary collection restrictions; no countdown can conceal a missed deadline. No prediction or notice grants permission to extend retention.

Provide concise contextual handling guidance before capture and again at evidence viewing, sharing and AI handoff: collect the smallest useful scope, prefer approved extracts, review recipients/content before disclosure, and use organization-approved clients. Explicitly state that already delivered data may remain in users' or external agents' logs/history and **cannot be recalled by Asservat's automatic deletion**. Link the administrator's approved handling policy through an authenticated, authorized reference. Do not create public downloads, outbound notifications or an external service dependency.

These notices support informed operational decisions. They do not establish a legal basis, constitute data-subject consent, determine GDPR compliance or replace the operator's existing processing arrangements. No per-capture legal questionnaire is required.

### SC-ASM-004

Given a six-hour core maximum with a five-minute deletion budget and a pre-trigger source, when previewed, then the relative ages start at acquisition/earlier source, not the future upload. After acquisition at 12:00, ordinary access ends no later than 17:55 and deletion is due by 18:00. An outage after 18:00 shows overdue with access denied; an external-agent copy is not claimed deleted. A mixed 24-hour context artifact retains its own stricter applicable lineage deadline.

## REQ-ASM-005 — Shared, concise user and agent experience

The normal capture/policy preview contains one **Workload impact and data handling** panel: a plain-language combined effect with uncertainty, compact action rows, ongoing versus incident costs, likely sensitive contents, automatic-deletion ages and the handling reminder. Put the consequential warnings next to Collect/Enable and existing approval review. Expand evidence, environment assumptions and quantities on demand; do not make users decode numeric scores or dismiss one generic warning per action. Selection/override/profile composition edits update this panel; history repeat recomputes it under current conditions, without inheriting an old “safe” verdict.

No new confirmation checkbox or assessment-approval role is introduced. The ordinary explicit submission and existing sensitive/intrusive approval provide the decision points. Kubernetes/GitOps submissions compute and publish the same assessment in protected status/query projections before starting, without requiring a browser visit or a second human for already authorized automation. Accepted records retain assessment identity/rule digests and the bounded content-minimized explanation under control-data privacy limits; live metrics/evidence-derived details follow their own shorter expiry and do not enter long-lived audit.

MCP preview_capture includes capture_assessment with plan binding, generated/valid-until times, per-action effects/data/retention, combined impact, quantities and alternatives. Derive the combined data warning from the visible action categories; list mixed retention ages rather than inventing one uniform lifetime. It uses the same deterministic service as browser/GitOps and stays within ordinary result limits; a response must not silently omit the most consequential warnings to fit. A result that cannot fit returns a bounded error with authenticated navigation. get_case/list_artifacts return scoped sensitivity/deletion notices alongside visible artifact descriptors, never hidden artifacts' categories/counts/deadlines. Direct evidence-query results also include a concise sensitive-data/managed-deletion/external-copy reminder in the existing warnings envelope, even if the client never opens a case. Do not attach hidden parent notices or suppress these warnings because the output is an extract. Client software is responsible for displaying these notices; the server cannot prove an external agent's human saw them.

Rules and supporting benchmarks ship offline as reviewed versioned capability data, with qualified administrator additions through existing protected configuration. Do not add executable publisher rules, a new assessment CRD/database, mandatory telemetry, an LLM classifier or a background scan of captured user data. [Research and validation gates](../docs/research/capture-assessment.md) separate known mechanisms from unmeasured estimates.

### SC-ASM-005

Given the same target and composed plan in browser, MCP and GitOps, when assessed, then the same current warnings and retention rules apply. Changing a ring, process batch or data mode updates them; repeated context capture needs no new generic consent. A shared-artifact reader sees only that artifact's handling/deletion notice. A stale assessment or unavailable measurement cannot be reused as proof of low impact.

## Existing-recording saves

For operation=recordingSave, the same assessment service binds the recording-save/v1 scope digest. Selected actions remain executionMode=ongoing, but the preview context expressly describes **saving existing recordings**: no new observation pods or recorder attachment is requested. scope.observationPods counts distinct selected source pods already recording, separately from snapshot incident pods; do not label it new arming. Assess incremental frozen-buffer/encryption/upload/analysis costs, with any continuing-recorder baseline explicitly identified. No application-pause estimate is invented from an unrelated liveCore action in the policy. Sensitivity and automatic-deletion ages come from original source acquisition and earliest source/parent ceilings, with actual remaining time/coverage refreshed before pinning. Existing disclosure rules remain mandatory.
