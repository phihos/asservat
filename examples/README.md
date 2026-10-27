# Synthetic contract examples

[retention-topology.json](retention-topology.json) shows the exact hub/local source set stored in an immutable installation ConfigMap. Protected enrollment supplies its accepted identity/content pins; capture callers never select or omit sources.

These files illustrate the proposed API. CRD examples cannot be installed until controllers exist. Grant/share/SharingIntent examples are hub runtime DTOs with schemaVersion/id, never kubectl resources. Names, hashes, wrapped keys, timestamps and evidence are synthetic; they are not verification results or live credentials.

| Example | Demonstrates |
| --- | --- |
| [Preset policy](policy-preset.yaml) | Minimal workload-failure monitoring; controller resolves identities, recipe, defaults and retention |
| [Preset capture](capture-preset.yaml) | One manual context capture without hashes, request plumbing or a separate CLI |
| [Capture with sharing](capture-with-sharing.yaml) | Add recipients at capture time; approved extracts and finite expiry resolved automatically |
| [Policy with sharing](policy-with-sharing.yaml) | Explicit ten-capture recurring instruction with absolute expiry |
| [Capture with raw sharing](capture-with-raw-sharing.yaml) | Separate pinned stack/raw selections; collection and raw-sharing approvals remain required |
| [Two owner teams](access-binding-owners.yaml) | Separate evidence-owner binding; collection rights remain separate |
| [HTTP-header recipe](recipe-http-headers.yaml) | Follow Service/StatefulSet peers, pcap syntax, four bounded segments and plain HTTP/1 projection |
| [Raw-packet recipe](recipe-packets-raw.yaml) | Explicit sensitive capture with default/transport-specific snaplen limits |
| [Resolved sharing intent](sharing-intent.yaml) | SQL-backed DTO: immutable creator, two managing teams, extract approved, raw pending, one registered capture |
| [Materialized capture share](share-from-capture.yaml) | Concrete stack snapshot with immutable intent/capture/selection origin |
| [MCP sharing request](mcp-capture-sharing-input.json) / [response](mcp-capture-sharing-result.json) | Optional instruction on request_capture and separate sharing navigation |
| [Core manifest](manifest-core.json) | Synthetic acquisition origin/parent for the derived stack; no core bytes |
| [Basic context recipe](recipe-basic-context.yaml) | Context actions backing both v1 presets, with no packet ring |
| [Storage pool](storage-pool.yaml) | Protected allocations, shared burst, system reserve and safety headroom with no overcommit |
| [Budget profile](budget-policy.yaml) | Automatic workload quotas, dump storms, fair upload limits, bounded queues and context reserve |
| [Administrator retention policy](retention-policy.yaml) | Global 24-hour evidence maximum, 6-hour core/heap cap and cleanup budget inside the limit |
| [Explicit permission binding](access-binding.yaml) | Scoped group permissions managed through Kubernetes API or GitOps |
| [Namespace permission source](permission-source-namespace.yaml) | One trusted annotation rule automatically covers provisioned namespaces |
| [Namespace ownership metadata](namespace-permissions.yaml) | Existing namespace metadata reused by the source; not a new Asservat namespace type |
| [Exec permission source](permission-source-exec.yaml) | Opt-in named-pod exec inheritance with declared identity/admission qualification |
| [Protected workload source](permission-source-workload.yaml) | Shared namespace ownership under an enforcing metadata guard |
| [Generic RBAC source](permission-source-rbac.yaml) | Optional exact workload-patch inheritance; disabled until its adapter is qualified |
| [Context recipe](recipe-context.yaml) | Logs, target `/proc/self/status`, network context and header capture to label-selected database peers |
| [Deployment policy](policy-deployment.yaml) | Any of a log pattern, sustained high memory, or liveness failure triggers that recipe |
| [Intrusive recipe](recipe-intrusive.yaml) | Typed runtime diagnostic, argv-based custom command and a dependent live core |
| [Pprof recipe](recipe-pprof.yaml) | Go CPU, heap and mutex profiles from a named container-local endpoint, without forced GC |
| [Pprof template binding](recipe-pprof-template.yaml) | Reuse an administrator endpoint template with an app-declared named port |
| [Pprof policy](policy-pprof.yaml) | Sustained CPU quota use triggers profiling; its separate policy grant must be approved before execution |
| [Profile metadata](profile-metadata.json) | Original format, sample types/units, duration, period and symbol coverage |
| [MCP HTTP headers](mcp-http-headers-result.json) | Bounded allowlisted HTTP response fields, no body, incomplete-flow coverage |
| [MCP profile result](mcp-profile-result.json) | Bounded CPU hotspots with explicit units and incomplete-symbol warnings |
| [StatefulSet policy](policy-statefulset.yaml) | Ordinal-scoped sustained-memory trigger with a policy grant |
| [Approved policy grant](grant-policy.yaml) | Second-person approval bound to resolved collection/recipe digests and an aggregate budget |
| [Manual capture](capture-manual.yaml) | Separate ad hoc request referencing a required individual grant; its supplied pending grant cannot authorize execution |
| [Extract share](share-extract.yaml) | Otherwise ineligible group within the organization gets a snapshot of existing extracts; no future artifacts or re-sharing |
| [Pending raw grant](grant-raw-pending.yaml) | A raw request does not grant access; the extract share above does not cover its separate core artifact |
| [Manifest](manifest.json) | Detailed encrypted-manifest plaintext shape, access/privacy provenance, inherited expiry/deletion deadlines and explicit completeness |
| [MCP result](mcp-backtrace-result.json) | Structured bounded backtrace result with provenance |
| [CloudEvent](case-event.json) | Identifier-only notification with authenticated evidence URI |

The validator recomputes recipe digests and explicit resolved collection-scope digests from compact JSON with sorted keys and UTF-8 encoding. Submission, collection and sharing identities are distinct under [execution identity](../specs/execution.md). Production canonicalization must additionally normalize defaults and Kubernetes quantities before hashing; quantities in these portable examples are already explicit integer bytes/duration strings.

Permission-source review, guard and identity-mapping references are synthetic placeholders; setting `enabled: true` does not make them qualified. The Namespace example validates only a bounded metadata shape, not the full Kubernetes API. Generated CRDs/admission/status and preset resolution remain implementation deliverables. Permission configuration has no separate HTTP CRUD API. Preset examples pin catalog versions; they need no manually calculated recipe digest.

The intrusive recipe is deliberately illustrative. It is not recommended as a universal default: tools may be absent, dumps may pause a process, and a .NET diagnostic port requires a qualified adapter. Each action must pass local capability checks.

The sharing examples illustrate successive states, not a completed execution. The manual request still needs its ad hoc action grant; the MCP response shows that pending state. The later SharingIntent/share/manifest fixtures assume authorized collection occurred, without an approved grant or any evidence bytes. The intent is generated by the service, never applied by a workload user. Team assignment IDs are synthetic resolved authority; the owner binding alone does not prove runtime group membership, retained access or permission to delegate management to the second team. Default selection resolves approved projections without user-entered hashes; explicit selections use immutable catalog name/version. Plan/request hashes are recomputed for the explicit synthetic request, and the validator checks child origin, class, projection, parent lineage, approver and expiry. Production also needs authoritative admission, projection qualification, SQL transaction/local CAS/replay and live permission tests in EXP-12.

Review fixtures: [approval settings](approval-policy.yaml), [pending ad hoc grant](grant-ad-hoc.yaml), [resolved policy scope](resolved-policy-scope.json), [resolved capture scope](resolved-capture-scope.json), [resolved sharing capture scope](resolved-sharing-capture-scope.json), [exact process recipe](recipe-selected-process.yaml), [reload-safe worker batch](recipe-worker-pool.yaml), [next-interval packets](recipe-packets-next.yaml), and [sensitive observation budget](grant-packet-observation.yaml). The worker example needs an administrator maxProcessesPerEpisode of at least two; the default single-process profile deliberately refuses it. The packet grant's execution digest is an illustrative placeholder for a separately accepted request, not a runnable authorization.

The [MCP preview input](mcp-preview-input.json), [preview result](mcp-preview-result.json), [capture from preview](mcp-preview-capture-input.json), [capture progress](mcp-capture-status-result.json) and [cancel request](mcp-cancel-input.json) describe independent synthetic workflow states. Preview/status hashes and action IDs do not imply these fixtures executed the intrusive recipe. Scope dependency hashes other than linked recipe/retention examples are synthetic configuration references; production acceptance must resolve and verify them.

## Guided selection fixtures

[Process discovery](recipe-inspect-processes.yaml), [network-header survey](recipe-inspect-network.yaml) and [sensitive protocol survey](recipe-inspect-protocols.yaml) are finite recipes backing the proposed diagnostic catalog. The all-address peer scope in the packet examples means traffic of the selected authorized pod, including IPv6 where qualified; it never means node-wide capture. Protocol discovery requires its ordinary reviewed observation grant.

[MCP discovery request](mcp-discovery-input.json), [process projection](mcp-discovery-processes-result.json) and [flow projection](mcp-discovery-flows-result.json) show reload-safe suggestions and ambiguous TLS/Service/process attribution. [Recommendation request](mcp-recommend-input.json) and [result](mcp-recommend-result.json) show a diagnostic handle usable by preview_capture and a nine-segment / 36 MiB sizing estimate. All observations, confidence and sizes are synthetic, not measured results.

The [worker dump recommendation](mcp-recommend-processes-result.json) includes the selector, complete match count, serial batch limits and an explicit default-budget blocker. Selecting two workers does not silently raise the administrator's one-process episode ceiling.

## Capture history fixtures

The [history request](mcp-history-input.json) and [page](mcp-history-result.json) show a previous manual request whose evidence has expired while approved pure-configuration settings remain available. The [settings request](mcp-capture-settings-input.json) and [projection](mcp-capture-settings-result.json) retain a target, expanded recipe and dependency pins without old grants, recipients or reason. A [repeat preview request](mcp-repeat-preview-input.json) restores by source reference; its [response](mcp-repeat-preview-result.json) includes non-authorizing lineage. Submission uses ordinary request_capture with the preview ID and a fresh idempotency key. Dates, IDs and privacy assumptions are synthetic.

## Reusable capture profiles

| Example | Demonstrates |
| --- | --- |
| [Process context](capture-profile-process-context.yaml) | Shipped process/socket context with exposed output controls |
| [Transport traffic](capture-profile-network-connections.yaml) | Both directions, sanitized network headers, 16 MiB/30 s preset ring, editable peers/filter/ring; embedded in the release (ADR-243) |
| [HTTP/1 headers](capture-profile-http-headers.yaml) | Shipped plain HTTP/1 header projection; sensitive observation |
| [Go CPU](capture-profile-go-cpu.yaml) | Ten-second profile with named endpoint template and typed duration |
| [Syscall activity](capture-profile-syscall-activity.yaml) | All current/new pod processes, finite metadata interval and event/ring limits |
| [Administrator argument profile](capture-profile-io-arguments.yaml) | Explicit sensitive I/O arguments/buffers with exposed typed bounds |
| [Namespace profile](capture-profile-ledger-stall.yaml) | Materialized derived recipe, no nested executable references |
| [Composed capture](capture-composed.yaml) / [policy](policy-composed.yaml) | Three reusable building blocks, one aggregate budget, ordinary approval required |
| [Expanded fixture](recipe-composed-expanded.yaml) | Deterministic generated action IDs and exact final recipe |
| [MCP catalog](mcp-profiles-result.json) / [definition](mcp-profile-definition-result.json) | Bounded catalog summary versus protected definition projection |
| [MCP composition request](mcp-composition-preview-input.json) / [preview](mcp-composition-preview-result.json) | Typed edits, pinned definitions and component/action provenance |
| [Resolved composition scope](resolved-composition-scope.json) / [history settings](mcp-composed-settings-result.json) | Exact source identities, execution digest and repeatable version/override provenance |
| [Reviewed recorder plan](resolved-recorder-preview.json) | ADR-243 plan-only packet preview: embedded builtin, hub-compiled libpcap program and digest, lifecycle, no acceptance |
| [Syscall summary](mcp-syscall-summary-result.json) / [events](mcp-syscall-events-result.json) | No argument strings; explicit loss and paired durations |
| [Raw syscall query](mcp-syscall-query-input.json) / [result](mcp-syscall-query-result.json) | Separate raw grant and bounded recorded argument projection |

These remain synthetic contracts. Catalog namespaces and endpoint capabilities are fixture choices, not live installations. The fixture compiler does not qualify Kubernetes admission, actual engine behavior, production scheduling or privacy isolation.

## Action lifecycle examples

| Example | Demonstrates |
| --- | --- |
| [Mixed recipe](recipe-trigger-lifecycles.yaml) / [policy](policy-trigger-lifecycles.yaml) | Packets/syscalls record while armed; bounded worker dumps run on trigger |
| [Policy lifecycle plan](lifecycle-plan-policy.json) | Ongoing activation across observation pods, separate incident actions |
| [Manual lifecycle plan](lifecycle-plan-manual.json) | Finite manual-session activation for the same mixed recipe |
| [Future-only recipe](recipe-post-trigger-only.yaml) / [plan](lifecycle-plan-post-trigger.json) | Explicit onTrigger packet/syscall windows with zero lookback |
| [Snapshot provenance](lifecycle-snapshot.json) | Source session/start, incident time, snapshot identity and history coverage |

The source/session scheduler is unimplemented; these are synthetic planning and provenance contracts.

## Impact and handling assessment examples

| Fixture | Purpose |
| --- | --- |
| [Mixed policy](assessment-mixed-policy.json) | 20 observed pods versus one incident pod, known dump pause risk and unknown combined overhead |
| [Unknown command](assessment-unknown-command.json) | Unknown application effects/content remain explicit |
| [Go profile assessment](assessment-go-profile.json) | Sampled profiles differ from object heap dumps; labels/paths can remain sensitive |
| [Artifact notice](artifact-handling-notice.json) / [overdue deletion](artifact-deletion-overdue.json) | Separate access cutoff, deletion deadline and managed-copy state |
| [Artifact inventory](mcp-artifact-notices-result.json) / [shared case](mcp-shared-case-notice-result.json) | Scoped notices without disclosing hidden raw parents |

Normal, repeat and composition preview fixtures now include capture_assessment. Numbers in these reports are declared limits with coverage labels, not measured Asservat overhead. Rule/capability references, subjects, clocks and environment records are synthetic. Runtime prediction/comprehension qualification remains pending. See [capture assessment](../specs/capture-assessment.md).

Final review fixtures pin concrete pod/node/boot identities in manual resolved scopes and their referenced digests. manifest-pod.json is a Kubernetes context snapshot; core manifests require process identity and new acquisitions require actionLifecycle. lifecycle-snapshot-retired.json shows full prehistory but partial post-trigger coverage after source exit. These are synthetic contract examples, not measured collections.

The recording-save examples link an explicitly enabled mixed policy to a protected resolved policy/save scope, passive MCP inventory/preview, existing request_capture submission, history/settings, acquisition provenance and a saved packet manifest. Lookback is narrowed to 20 seconds, after is zero, and the original ring age starts retention. Optional per-capture sharing reuses the normal declaration. Synthetic source/actor identities do not represent live authorization; no full-recipe execution is implied.

Live-watch examples cover finite open/read/update/close requests, source inventory, syscall/packet/HTTP approved projections, paused batches and source-time/expiry provenance. They are registered in specs/examples.yaml and use [live-watch.schema.json](../specs/contracts/live-watch.schema.json). All rows are synthetic. `make live-check` adds negative shape/timeline cases; it does not establish runtime projection, authorization or performance support.

## Internal control examples

The seven `internal-*.json` work fixtures cover arming a source, running an action, saving a recording, scheduling an analysis stage, erasing a copy and requesting an approved live projection. [internal-receipt.json](internal-receipt.json) illustrates the separate bounded acknowledgement. These are unsigned synthetic decoded DTOs under [internal-work.schema.json](../specs/contracts/internal-work.schema.json), not executable grants or signed messages. Protected references and digests are fixture identities. `make architecture-check` checks their shapes and selected scope/deadline/retry rules; production JWS, current authorization, budget admission and receiver persistence are separate qualification gates in the [internal interface contract](../docs/architecture/interfaces.md).

Native-download examples illustrate prepare/status/cancel and a synthetic 4 GiB core. They transfer no bytes and prove no GDB/Wireshark compatibility. Internal downloadArtifact work is a separate control purpose. See [downloads](../specs/artifact-downloads.md).


The combined-review examples are [capture-investigation.yaml](capture-investigation.yaml), [grant-investigation.yaml](grant-investigation.yaml) and [grant-investigation-result.yaml](grant-investigation-result.yaml). The parent binds one capture and selected output scope; the child names an existing exact artifact for the same human/client. [investigation-preview.json](investigation-preview.json) illustrates the MCP instruction. These are synthetic contracts, not issued permissions. `make investigation-check` validates the paired scopes.

## Framed storage contract

[Framed manifest](manifest-framed.json), [encrypted index page plaintext](framed-index-page.json) and [minimal commit envelope](framed-commit.json) illustrate ADR-048. Digests, sizes, ETags, versions and wrapped keys are synthetic shape examples, not actual related ciphertext. The codec and integration tests produce and verify real synthetic ciphertext separately. A storage envelope alone never makes an artifact discoverable.

[Team automation binding](access-binding-automation.yaml) is administrator configuration for bounded recurring policies. Its presence is not runtime acceptance or an intrusive-action approval.
