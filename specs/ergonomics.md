# Operator and maintainer workflows

This is a first-release requirement, not a later UI polish phase. Read the [review](../docs/ergonomics-review.md) for coverage and rationale. Proposed interfaces below are not implemented commands or installable resources.

## REQ-UX-001 — Configure infrastructure once

Installation MUST offer one documented hub path and one repeatable cluster enrollment path, with an evaluation `combined` mode. Reuse configured IdP, storage, KMS, image mirrors, ownership sources, collection ceilings and retention defaults across workloads. Generate bootstrap credentials, IDs and example configuration without displaying secrets in rendered manifests or logs. Support secret references and declarative reconciliation; do not require a portal action after each GitOps sync.

Helm is the officially supported installation method under [ADR-058](../docs/decisions/058-official-helm-installation.md), with one first-party chart and explicit topology modes. Support local chart archives and OCI distribution, canonical CRD upgrade ordering and nonsecret values. [ADR-063](../docs/decisions/063-small-deployment-alternatives.md) adds independently selectable internal/bundled dependencies and local login under [deployment profiles](deployment-profiles.md); selecting a small profile must not require administrators to assemble a separate IdP/KMS/database/store installation. Keycloak remains the first tested external provider. Clearly distinguish installed configuration from runtime readiness; a development package cannot claim a working platform or enable unqualified collection. Uninstall and rollback MUST preserve custody, retention and durable execution obligations. See the [installation guide](../docs/installation/helm.md).

A read-only installation/capability report MUST identify each missing prerequisite, its effect, responsible role and exact remedy. Inspect API reachability, identity mapping, declared deletion/versioning policy, encryption, region, metadata protection and node capabilities independently. Distinguish configured/inspected from actively verified; a read-only check cannot prove a DELETE, failover or runtime capture works. Offer a separate synthetic qualification action with bounded cleanup. Never exercise a live dump/custom command to prove basic readiness. Active synthetic diagnostics require explicit selection. Report support per action/node pool; unavailable kernel cores must not disable logs or profiles. Core-handler takeover remains an explicit administrator decision once per qualified node-pool configuration.

Regional context-executor installation MUST require the operator-managed local
start API before creating installation resources. Missing or conflicting
served `CapacityReservation` discovery must identify the chart CRD prerequisite,
preserve original caller cancellation/deadlines, and create no namespace or
runtime objects. Discovery establishes availability only; it does not replace
schema qualification, RBAC, protected admission or current execution authority.
The installer must not create or adopt the cluster-scoped CRD.

Source trust and retention-purpose setup belongs to administrators. Newly provisioned namespaces matching an approved source/ceiling inherit it automatically. No per-workload AccessBinding or consent checkbox is required in that path. Reusable budget profiles automatically allocate protected storage from the namespace envelope; show CapacityNotAllocated before arming if it cannot be backed, rather than requesting quota YAML from every maintainer. Application maintainers need no hub kubeconfig, node access, private registry credentials or separate per-cluster account to investigate already authorized evidence.

### SC-UX-001

Given a configured hub and qualified namespace source, when the normal provisioner creates an eligible application namespace, then its maintainers can select that workload without an Asservat administrator ticket. On a node pool without core support, context capture remains available and the report names the missing core prerequisite.

## REQ-UX-002 — Presets and progressive configuration

The browser MUST offer select cluster/namespace/workload → choose a diagnostic goal or diagnostic → inspect concise effective plan → collect or enable. [Guided selection](guidance.md) supplies optional process/traffic discovery and ranked, editable recommendations; keep the direct diagnostic path available. Pods are the public unit; regular containers, sidecars and available init/ephemeral sources are included without a container picker. Advanced action DAGs, detector expressions and pod/budget controls remain optional. Preview explains unavailable sources and internal fanout without asking maintainers to classify sidecars.

`DebugPolicy` and `DebugCapture` accept the preset authoring form in their schemas alongside the expanded form. The preset form adds no resource kind or configuration service; reusable building blocks use the separate CaptureProfile configuration CRD. The browser writes equivalent resources using its authenticated submission path. `metadata.namespace` supplies namespace; the controller resolves cluster, workload UID, container identity, immutable preset/recipe digest, bounded defaults, current privacy policy, execution identity and action capability. A preset is an immutable, shipped catalog entry `(name, version)` containing actions, limits, optionality and supported overrides. An administrator can disable entries. Custom recipes use the expanded form; reusable, parameterized building blocks use [capture profiles](capture-profiles.md) and the third composition authoring form. Unknown or unavailable preset versions fail clearly; a software upgrade does not silently change a pinned preset.

Initial presets:

| Preset | Purpose | Defaults |
| --- | --- | --- |
| `workload-failure/v1` | Automatic incident context on a restart or observed liveness failure, optionally an additional log match | All authorized replicas under administrator observation ceilings; one contributing pod collected per incident by default, including unready pods; context actions below; existing 5-minute cooldown/burst 2 ceilings |
| `incident-context/v1` | One manual context capture | One selected pod; sanitized Kubernetes state, bounded recent logs, allowlisted process and network counters; no command, memory dump, arbitrary files, profiler, payload or packet ring |
| `pod-status/v1` | One bounded pod-status snapshot | Exactly one eligible pod, including an unhealthy or unscheduled pod with a qualified API reader; phase/readiness and aggregate runtime/restart counts; fixed 4,096-byte native projection and five-second action deadline; no logs, commands, process inspection, file reads or network capture |

The `workload-failure/v1` and `incident-context/v1` presets use the same context actions and bounds as the shipped `basic-context` recipe ([example](../examples/recipe-basic-context.yaml)); a new packaged preset version is required if that recipe changes. Optional log matching adds an OR branch to the policy's fixed restart/probe expression. A missing probe source is Unknown, not successful monitoring. Show monitored/eligible pod counts, pod-wide scope, evidence classes, maximum bytes, potential impact, approval requirement and effective expiry. A cap below replica count is conspicuous; selecting a workload never implies every replica is monitored. Rings and expensive diagnostics are separate explicit additions. Preview never collects, enables sampling or runs commands.

`pod-status/v1` maps only to the immutable `builtin-pod-status-v1` recipe ([definition](../examples/recipe-pod-status.json)) and its qualified `asservat-pod-status/v1` projection. It is a shipped preset for one request, not a `CaptureProfile` CRD, runtime profile artifact or custom composition. Its action/output/fanout limits have no user override; the existing requested retention remains subject to administrator maxima. It does not make `incident-context/v1`, profile composition, recurring policy execution, sharing, raw-result access or free-text reason storage available. Unsupported runtime branches fail explicitly rather than being discarded or downgraded to pod status.

The fixed preset accepts an explicit Deployment, StatefulSet or Pod. A workload resolves one scheduled, non-deleting pod in deterministic name order after verifying its actual controller chain. A direct Pod retains its real Deployment/StatefulSet owner for permission and workload budgets. Preview names that exact selected pod; it never claims all-replica monitoring, a healthy-pod selection or a live status sample. Request freezes its UID/owner/node scope and requires a new preview if the reviewed identity changes. Preview metadata is disclosed only after current target eligibility. The 4,096-byte limit covers saved native status, not transient Kubernetes responses, encryption/object overhead or collector memory.

Resolution produces a service-owned immutable accepted plan and digest without rewriting GitOps-owned spec fields. Admission authenticates the submitted authoring spec; controller acceptance additionally binds resolved plan/preset digests under REQ-PER-007. Manual captures resolve once and default to a five-minute acceptance deadline with operation identity derived from resource UID/generation; recreated objects are new requests. Browser retries reuse their original request ID. Policies pin workload UID and preset after acceptance. Replacement workloads need explicit re-adoption; normal pod rolls under that workload need no user edits. Optional retention requests are clamped to administrator maxima with a visible explanation, never treated as a limit override.

The [capture assessment](capture-assessment.md) supplies one **Workload impact and data handling** panel beside Collect/Enable, shared with approval review. Show known effects and unknown cost, ongoing versus incident scope, likely sensitive content and effective access/deletion ages. Numbers distinguish declared caps from measured estimates. Offer specific alternatives with their lost coverage; recompute when cards/settings change. Details expand on demand, with no extra consent checkbox or repeated modal. Example for an unmeasured mixed plan: “Records traffic and syscalls on 20 pods while armed. A triggered dump may pause selected processes on one pod; combined overhead is unknown. The core may contain user data and credentials. Under the current policy, access ends within 5 h 55 min of acquisition and managed deletion is due within 6 h.” Other artifact deadlines remain separately visible.

### SC-UX-002

Given the [short policy example](../examples/policy-preset.yaml) and an eligible multi-container pod, when accepted, then the controller fills the execution plan without a user computing hashes, UIDs or grant names. An unknown preset, unresolved pod or unavailable required capability yields a specific field-level condition. Reapplying the same accepted capture cannot collect twice.

## REQ-UX-003 — Approvals without repeated form filling

Resolve existing grants and pending requests before offering a new approval request. Show one reviewable plan with exact target, intrusive actions, maximum total cost, duration, privacy/retention and approved executor. Policy grants may cover bounded repeated executions; show remaining executions/bytes and expiry before exhaustion. A renewal copies the still-valid scope into a new reviewed request; never renew authority silently. Ad hoc intrusive capture still needs its individual approval.

Raw analysis grants cover a bounded set of operations and cumulative budget, allowing several MCP queries without a click per call. Combine related raw-share and recipient-grant review in one browser journey while persisting distinct decisions and validating the appropriate approver authority for each. Reuse a sufficiently recent step-up session under the IdP policy; do not demand a new login for every screen. Self-approval remains forbidden. Approval links carry navigation state, not authority or credentials.

Metadata-only edits that do not alter the normalized execution spec need no new intrusive approval. Target, executor, trigger, recipe, evidence sensitivity and budget changes invalidate approval as before. Do not infer general subset safety for arbitrary edits. Authorized independent context actions may proceed while optional intrusive actions await approval; never rerun that context automatically when the approval arrives. A required unapproved action is explicit in the plan: useful context can be published while it waits, but the capture cannot be called fully successful. Its original deadline ends waiting; terminal status is Partial when usable evidence exists, otherwise Failed/Cancelled as applicable.

### SC-UX-003

Given a case needing three bounded raw queries, when one suitable grant is approved, then the same principal/client uses it within quota without three approval forms. Changing only a display label preserves the normalized plan; adding a dump invalidates approval. Waiting for optional profiling does not lose already authorized logs.

## REQ-UX-004 — Useful status and recovery

The browser and CRD Conditions MUST distinguish saved, validating, awaiting selection/approval, arming, monitored, degraded, partial and expired. Report desired/observed generation, last fresh observation, actual history coverage and next eligible capture time. Each blocked/partial item gives a stable reason, practical remedy, responsible role, and retryability without exposing unauthorized inventory. Examples: missing endpoint → app maintainer; blocked collection ceiling → cluster admin; expired raw grant → requester/approver; expired evidence → unavailable, not retryable.

Preserve drafts after validation errors. A failed optional action never hides successful evidence. A reconnect/refresh recovers the existing operation. Cancellation stops future work with its limitations; an ambiguous invasive action is never presented as a safe Retry button. Capability failures do not demand the user decode controller logs. Incident pages put available evidence and missing coverage before collector implementation details. Provide bounded support diagnostics with versions, capability/condition codes and opaque IDs; exclude evidence, tokens, argv values and user labels.

### SC-UX-004

Given an upload succeeded but symbol acquisition failed, when the user opens the case, then available context is immediately readable, symbolized analysis is marked incomplete with a remedy, and retrying analysis cannot trigger another dump. A disconnected cluster cannot appear freshly monitored.

## REQ-UX-005 — Evidence, sharing and AI handoff

Use one stable case URL and one MCP endpoint per installation. After organization login, present authorized cases across clusters with shared-with-me, workload, time and capability filters. Configure an AI client's registration once per installation/client profile; ordinary investigation starts with read scope only. The case page supplies the endpoint and case reference, never a token or evidence download URL. Summaries and profile comparisons show actual collection interval, gaps, symbols and expiry. Offer compatible authorized baselines; do not require copying artifact digests by hand.

Sharing starts from selected visible artifacts/extracts or the optional “Share results with…” section of a capture request. The latter defaults to pinned approved extracts, resolves IDs/projection versions automatically, and shows collection and sharing progress separately. A monitoring policy offers a separate explicit “Share future captures” option requiring a maximum count and expiry; show remaining captures and distinguish Stop from Revoke. Pending raw-sharing approval must not block already approved extracts. No second manual share step is required when selected outputs become ready. Resolve searchable permitted directory display names to stable IDs; show selected scope, operations and effective expiry, with extracts as the default. No requirement for the recipient to gain cluster access. Provide copy-link and a recipient-view preview computed through the authorization evaluator without granting a new identity. Hidden artifacts remain hidden. Ownership transfer may batch an explicit selected historical snapshot into one audited review; it never silently backdates access.

Each raw disclosure flow states which registered client receives the evidence and links the installation's data-handling policy. Registration does not prove where an external agent forwards data. Missing scope/approval errors lead to the exact existing request page and preserve context. No automatic external notifications, agent-driven approvals or embedded LLM are introduced.

Evidence views, recipient previews and AI handoff repeat the scoped sensitivity and automatic-deletion notice. Expired access and verified deletion have different labels. Recommend minimal approved extracts and approved clients; state that Asservat cannot recall data already copied into a user's or agent's history. Shared views never reveal notices for hidden artifacts.

### SC-UX-005

Given an extract shared with a colleague lacking workload access, when they open the link or connect their approved agent, then one organization login exposes only that snapshot. They do not need kubectl, artifact hashes, another cluster login or a raw grant to read the shared extract.

## REQ-UX-006 — Measure effort before release

Run the task-based study in [validation](../docs/validation.md) with administrators and app maintainers unfamiliar with the implementation. Observe successful completion, active user time, steps, errors, help requests and ability to explain scope/expiry. Do not substitute developer walkthroughs or screenshots for that evidence. Keyboard navigation, labeled controls, focus/error handling, readable contrast, non-color-only states and screen-reader status updates are acceptance criteria.

Release goals after infrastructure setup: eligible maintainer first context capture within 3 minutes active effort; existing-case agent handoff and extract share each within 2 minutes; no administrator interaction per eligible new workload; no manually entered hash/UID on basic paths. Exclude asynchronous collection time and human approval waiting from active time but report them separately. Targets are hypotheses to test, not measured claims. Record failures and fix mandatory workflow blockers before declaring the production UX complete.

### SC-UX-006

Given a fresh maintainer account and a synthetic eligible workload, when a participant collects context, finds a partial-result explanation and shares an extract, then task metrics and authorization understanding are recorded. A keyboard-only participant can complete the same workflow. Manual digest copying or an unnecessary admin ticket fails the basic-path criterion.

## Accepted workflow refinements

The normal “Share results with…” flow defaults to approved extracts and the submitter's eligible owner teams, previews creator/managers/recipients separately, and exposes advanced manager selection only when needed. Existing bound teams keep managing after staff changes. Personal management remains available. Stop, Revoke and historical ownership transfer have distinct visible effects; recipients are never asked to manage collection.

Packet presets expose readable profile names and a Kubernetes peer picker (Service/Deployment/StatefulSet/labels/IP), with live following visible. Advanced pcap expression, segments/bytes/time and protocol budgets are optional. Preview distinguishes network headers, structured HTTP/1 headers and raw prefixes, and reports effective capacity, missing capabilities and achievable history.

PostgreSQL adds one administrator prerequisite, not a developer step. The hub setup accepts an existing service and validates its readiness/backup/failover profile. Permission automation still uses kubectl/GitOps and protected metadata; maintainers and MCP clients need neither SQL credentials nor a management-cluster kubeconfig.

Policy approval validity defaults to seven days, with an administrator-configurable finite maximum and default under ADR-027; installations can allow longer reviewed periods without weekly tickets. Show upcoming expiry once per policy and offer an unchanged-scope renewal with its current budget, never automatic renewal. Collection approval and sharing intent expiry are separate: a 30-day collection approval does not extend a seven-day future-sharing instruction. MCP uses the discovery → preview → request → status flow in REQ-MCP-005; no basic path requires copying a digest.

## Repeat without rebuilding the request

[Capture history](capture-history.md) adds Recent captures on each workload/selector and Repeat capture on an authorized request. Restore the retained settings, show differences from current limits/capabilities, and submit a new request after review. The ordinary manual path needs no copying YAML, hashes or grant IDs. Offer manual/policy/discovery filters and retain failed/partial requests. Parameter expiry, stale exact processes and missing pinned versions produce concrete recovery options. Repeating collection and retrying existing analysis remain distinct actions; repeated submission of the same new request stays idempotent.

## Compose and reuse capture settings

Offer **Add capture profile** alongside the direct diagnostic/goal path. The catalog explains purpose, publisher/version, current capability, impact and approval before selection. Multiple cards form one preview with defaults, editable peer/process/window/ring controls, combined cost and field-level conflict remedies. Users see friendly component/action names; generated IDs stay in provenance. Keep all advanced bounds visible on demand and summarize them before collection. A selected unavailable profile stays visible with its remedy; never substitute a different action silently.

**Save as profile** materializes a reviewed recipe, proposes editable fields and a new version, and publishes through the authenticated Kubernetes configuration path when the caller has namespace or organization publication rights. Otherwise offer the equivalent configuration for an authorized publisher; collecting an allowed composition never requires profile-publication rights. GitOps-managed entries show their source and an exportable change rather than overwriting them. Catalog publication, ordinary collection, sensitive acquisition, raw access and sharing remain separate permissions. Repeat capture restores component pins and overrides, highlights changed prerequisites and offers an explicit version upgrade. No extra approval for harmless catalog browsing or compilation.

## Explain what runs before an incident

Group every plan into **Runs on trigger** and **Records while armed; saves on trigger**. Keep useful kind-based defaults instead of requiring a timing choice for each card. Show ongoing pod coverage, ring/CPU cost and approval before Enable policy; show incident fanout, dump/snapshot cost and post-window separately. Warming/missing history must be visible even when detectors are ready. An explicit future-only recorder variant warns that earlier traffic/syscalls will be unavailable. Manual Collect now is finite, reports missing prehistory and stops its own sources on completion/cancellation. See [action lifecycles](action-lifecycle.md).

## Finishing the investigation

Selected profiles determine which optional configuration links are offered. Context-only captures proceed directly to review; process rules appear for applicable process collectors and traffic controls for packet profiles. Useful defaults remain editable without mandatory extra pages; review summarizes the effective settings. Removing a profile removes its inactive settings from compilation instead of retaining hidden effects. One-off result access can join the same independent review under [REQ-INV-001](investigation-approval.md); standalone later reviews remain available.

Immediate saving of already approved displayed recording defaults follows [REQ-SAV-001](recording-saves.md): one click, no repeated human review, fresh backend admission. Track completed diagnostic outcomes and total elapsed time alongside active effort under the user-outcome protocol in [validation](../docs/validation.md).
