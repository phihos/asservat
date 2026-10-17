# Ergonomics review

Reviewed 2026-10-09 across product journeys, architecture, targets, triggers, actions, profiles, authorization, permission inheritance, sharing, evidence lifecycle, MCP, federation, APIs, packaging and recovery. This is a design review; no usability study or working UI exists. Normative outcomes are in [workflow requirements](../specs/ergonomics.md); privacy defaults are in [privacy requirements](../specs/privacy.md).

## Main findings and revisions

| Journey | Friction or ambiguity in the earlier design | Specified revision | Priority / verification |
| --- | --- | --- | --- |
| Permission automation | Separate OAuth CRUD API duplicated Kubernetes state, authentication and conflict handling | Kubernetes CRDs/API only; kubectl/GitOps examples, protected status and effective-access explanation | First slice; SC-PER-002 |
| First installation | Many external references and privilege requirements without a single diagnostic path | Hub + repeatable cluster enrollment; secret references; read-only prerequisite report with remedy/owner | First slice; SC-UX-001 |
| Everyday namespace provisioning | Potential Asservat registration ticket per team/application | Reuse one qualified namespace/exec permission source and collection ceiling; new eligible namespaces inherit automatically | First slice; SC-PER-003/004 |
| Starting collection | Expanded YAML required hashes, target settings, budgets, retention and request plumbing | Versioned presets in the existing DebugPolicy/DebugCapture kinds; controller-owned resolution and explicit short examples | First slice; SC-UX-002 |
| GitOps | Controller defaulting could fight field ownership; write success could look like monitoring | Preserve authored spec; store resolved execution separately; generation-aware readiness and field-level conflicts | First slice; SC-PER-002, SC-UX-002 |
| Container/replica choice | “Application containers” and selecting a Deployment could imply broader coverage than delivered | Use whole-pod scope without a container picker; expose available/unavailable sources and monitored/eligible pod counts | First slice; SC-UX-002 |
| Trigger authoring | Powerful expression language required for simple incidents | Workload-failure preset, optional log match, advanced editor for compound logic; preview never collects | First slice; SC-UX-002 |
| Trigger troubleshooting | No match could mean quiet app, missing source, cooldown or unarmed generation | Display last observation, Unknown/gaps, history coverage, cooldown and activation state with practical remedies | First slice; SC-UX-004 |
| Runtime preparation | Per-application administrator endpoint setup risks making pprof burdensome | Reusable administrator endpoint templates; maintainer supplies a permitted named pod port within that template's fixed path policy; no per-app admin approval for an allowed binding | Profiles gate; SC-PRF-001 |
| Dumps and custom commands | Developers might need to understand ptrace/namespace adapters and discover missing tools during incidents | Capability-aware diagnostics catalog, validated endpoint/runtime hints, exact unsupported explanation; no tool injection by default | Action gates; SC-ACT-003/006 |
| Intrusive approvals | Repeated forms and manual grant references | Resolve grants, reuse pending requests, bundle a reviewed recipe, show remaining quotas; preserve individual ad hoc approvals | Grant gate; SC-UX-003 |
| Routine policy editing | Wording implied every edit needed fresh approval | Metadata-only edits preserve normalized plan; execution-spec changes still require review | Grant gate; SC-UX-003 |
| Partial collection | Costly optional evidence could hide or delay useful context | Show available evidence immediately; optional approval/failure does not discard context; safe retry only for proven retryable operations | First slice; SC-UX-003/004 |
| Evidence navigation | Users might copy low-level artifact IDs to compare profiles or hand off to an agent | Stable case page, authorized baseline choices, one MCP endpoint and copyable case reference | MCP gate; SC-UX-005 |
| Sharing | Stable group IDs and layered grants could become multiple manual workflows | Authorized name search resolves IDs; explicit artifact snapshot and recipient-view preview; coordinated raw share/grant review | Sharing gate; SC-UX-003/005 |
| Sharing before evidence exists | Waiting for upload/analysis forced the owner to return and share manually | Optional capture-time recipients with approved extracts by default; explicit bounded recurring sharing; separate collection/sharing progress and Stop/Revoke | Sharing gate; SC-SHR-004 through SC-SHR-007 |
| Ownership transfer | Historical-evidence safety could strand legitimate new maintainers | One scoped bulk transfer/share review for selected retained artifacts; explain why history needs approval | Permission gate; SC-PER-008 |
| Privacy setup | Maintainers would have to choose retention/legal settings repeatedly | Administrator policy inherited automatically; effective deadline and limiting rule visible; no incident-by-incident legal questionnaire | First slice; SC-PRV-001/002 |
| Retention changes | Defaults, holds, copies and backups could contradict “maximum retention” | Minimum of administrator limits, lineage deadlines, copy inventory, deletion budget within maximum, impact preview | Storage gate; SC-PRV-002/004/005 |
| Deletion operations | Manual cleanup tickets after failed delete or restore | Automated retries/reconciliation; one actionable overdue condition; restore gate; distinguish inaccessible from deleted | Storage gate; SC-PRV-004 |
| Air gaps and upgrades | Repeated manual image/symbol chasing | Complete pinned bundle and machine-readable mirror manifest; upgrade preflight, canary and capability diff | Packaging gate; SC-UX-001 |
| Accessibility and user effort | No measurable acceptance criteria | Keyboard/screen-reader checks and timed task study with unfamiliar participants | Release gate; SC-UX-006 |

## Basic workflows after these changes

Administrator setup is a reusable infrastructure task: configure identity/storage/KMS, enroll a cluster, choose eligible namespaces and a permission source, set collection/privacy ceilings, then review the capability report. Source qualification can cover a trusted namespace-provisioning boundary once; it is not repeated for every application. A kernel-global core-handler change still requires a deliberate decision because a convenience default could disrupt another collector.

A maintainer selects a workload and starts with “Incident context” or “Monitor workload failures.” The UI shows the resolved scope, data collected, budget and expiry. A short declarative form offers the same path in GitOps. Advanced settings appear when the maintainer needs additional triggers or evidence. Live profiling/dumps add a clear approval step; a reusable automatic policy grant avoids asking a human during each short-lived incident.

Investigation starts from available evidence in a case. A missing core, partial log window or unavailable symbols is shown beside the evidence it affects, with an explanation and the person who can fix it. Connecting an existing agent requires the installation's MCP endpoint and case reference. Sharing an extract requires selecting the recipient and visible artifacts, without giving that person Kubernetes permissions. An owner can also choose recipients during capture; approved projections become shared automatically when ready. Recurring-policy sharing explicitly shows count and expiry. Neither path requires entering a projection hash, creating a SharingIntent manually, or returning after analysis to repeat the same decision.

Retention is inherited. The maintainer sees “readable until” and “deletion due by,” and can shorten the request. Administrators can inspect which policy constrained it and whether every copy was deleted. Nobody computes expiry from YAML or cleans up core versions manually during normal operation.

## Remaining design tradeoffs

- The first authorization model deliberately keeps second-person approval for ad hoc intrusive work. Combining forms reduces effort; removing that approval would change a confirmed security decision.
- Kubernetes configuration needs management-cluster access for administrators/GitOps. Developers investigating through the hub do not need it. Read-only explanation cannot impersonate unrestricted Kubernetes administrators.
- Expiring policy grants need reviewed renewals. The UI can copy scope and highlight differences, but cannot turn renewal into permanent authority.
- Exec-based inheritance cannot safely enumerate everyone who could have executed into an old pod. Shared team evidence works most naturally with a protected owner-group source; exec inheritance remains useful for immediate individual access. Historic handover stays explicit.
- Capable presets do not eliminate application prerequisites such as exposing pprof or supplying symbols. Report exactly what is missing and permit approved reusable endpoint templates.
- Optional CLI convenience can follow demonstrated demand. Kubectl/GitOps and the browser are sufficient initial authoring surfaces; installing another mandatory CLI is not part of the plan.

The acceptance study, including first-capture/share/agent-handoff time goals, is specified in [validation](validation.md). The targets are not yet measured.

## Follow-up review: accepted team, packet and persistence changes

| Journey | Minimum work | Advanced control / failure remedy |
| --- | --- | --- |
| Share capture results | Select recipients; review resolved extract scope and managing teams | Personal or multiple eligible owner teams; historical transfer explicit; no new group-management subsystem |
| Staff departure | IdP membership update | Team-managed shares remain manageable; invalid last assignment suspends with a scoped recovery path |
| Capture peer traffic | Choose network/HTTP/raw profile and Service/workload peer | Pcap expression, follow/frozen, ring segments/size, parser/output caps; capability mismatch names the missing adapter |
| Install hub | Connect a qualified existing PostgreSQL service once | Dedicated role/TLS/backup/failover checks and RecoveryBlocked runbook; no mandatory database operator |
| Maintain permissions | Existing CRD/GitOps or trusted namespace workflow | SQL projection lag visible in generation-aware status; no competing permission HTTP interface |

EXP-17 now covers these journeys. These are specified reductions in user work, not measured usability results.

The full follow-up review is in [design review](reviews/design-review.md), with [tabletop journeys](reviews/use-case-walkthroughs.md). Pod-wide defaults, all-replica observation, configurable policy approval lifetime and reload-safe process selectors supersede the earlier selection assumptions.

## Guided selection follow-up

The remaining burden was knowing *which* diagnostic to choose and translating live observations into process selectors or packet settings. [Guidance](../specs/guidance.md) now specifies goal-first playbooks, optional one-action process/traffic discovery, visible match sets, protocol/Service/PID uncertainty and desired-history-based ring sizing. The same recommendations are previewable from an external agent. Existing authority handles sensitive surveys without a second approval subsystem; ordinary identity/header inspection acquires no new second-person requirement.

EXP-17 must include an unfamiliar maintainer choosing evidence for CPU, memory and latency without knowing PID/BPF/snaplen syntax, and an agent completing the same workflow without hand-built hashes. EXP-20 checks whether the assistance is technically correct. These remain unmeasured acceptance targets.

## History and repeat follow-up

Repeated investigations previously required reconstructing request parameters. REQ-HIS-001–004 now add selector-scoped Recent captures and a restore → review → collect flow with current differences. Preserve fully expanded settings so mutable recipe updates cannot silently alter a repeat. Show parameter expiry separately from evidence expiry, and stale exact-process/manual-pod choices without discarding the other settings. Existing approvals, storm limits and idempotency remain in force. EXP-17 target: an eligible maintainer reaches a repeated context preview within 30 seconds of active effort, without copying a hash or YAML; measure approval/capture waiting separately. This is an unmeasured target.

## Reusable profile workflow review

**Friction addressed:** rebuilding multi-action recipes, guessing valid override paths, manually combining limits, recomputing hashes, profile version drift and repeatedly configuring syscall/process selection. The proposed catalog/card editor uses defaults and typed controls, a single combined preview, clear conflict remedies, namespace Save as profile and history repeats with pinned versions. Publication is optional for collection; administrators need not approve each composition that fits existing rights and grants. Syscall arguments and live CPU profiles retain their ordinary approvals.

**Pending validation:** in EXP-17/21, unfamiliar maintainers compose HTTP headers plus syscall metadata and context, narrow peers, fix one budget conflict, save a permitted namespace version and repeat it via MCP. Target median active composition effort under two minutes excluding external approval waits, with no YAML/hashes required for the browser path; measure correction errors and discoverability. No participant study has run.

## Impact and sensitive-data decisions

Previously a preview could expose budgets and approval needs without explaining whether a combination might disrupt the application or include user data. [REQ-ASM-001–005](../specs/capture-assessment.md) add one concise panel at collection/enable/review, updated as cards change, with known effects, uncertainty, alternatives, sensitive categories and access/deletion ages. Evidence/sharing/AI views repeat a scoped handling notice. No new checkbox or per-action warning modal is added. EXP-17 now checks comprehension of the consequential distinctions and EXP-18 checks deletion/shared-view accuracy; both remain unmeasured.

## Preserve current recordings without rebuilding a capture

The authorized policy/workload view offers Save existing recordings now with current pod/source coverage, last metadata observation, saved lookback, possible sensitive content, remaining retention and incremental cost. Default to the selected pod's eligible sources and existing configured lookback; allow shortening. The authoring draft visibly enables reviewed manual saves for ongoing profiles; existing policies show the one-time policy-review remedy if disabled. Saves do not trigger a dump or ask for another approval when covered. Handle expiry/source change refreshes selection with a reason, while quota/cooldown explains why it cannot save immediately. Shared recipients see no live-source discovery.

Use the same progress/cancel and optional Share results section as other captures. Label history Saved existing recordings; Repeat requires current source selection. Do not silently create a recorder to replace missing history. Installation diagnostics distinguish collection availability from analysis requiring qualified encrypted scratch; give a concrete administrator remedy without making maintainers choose StorageClasses.
