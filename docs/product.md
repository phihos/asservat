# Product definition

Status: proposed baseline, 2026-10-09. User decisions are recorded in [decisions](decisions/README.md).

## Outcome

When an intermittent Kubernetes failure disappears before an engineer can inspect it, Asservat should preserve enough bounded context to investigate what happened, where it happened, and what evidence is missing. Developers should start with a compact timeline and structured findings, then obtain approved access to deeper evidence. Their existing AI agent connects through MCP; Asservat neither runs that agent nor decides the root cause.

"As much information as possible" means a comprehensive, configurable catalogue with explicit budgets and permissions. An unbounded collector can worsen the incident, exhaust a node, or expose unrelated workloads. Every collection therefore has a target identity, time window, byte limit, sensitivity, and impact classification. Workload-wide storm limits, pre-acquisition resource reservations, fair scheduling and protected storage prevent a noisy deployment consuming another workload's capacity; see [capacity isolation](../specs/capacity.md).

## Personas and complete journeys

1. **Platform administrator:** enrolls clusters into the installation, configures PostgreSQL/storage/KMS/identity, selects supported node pools, configures explicit access or automatic inheritance from trusted namespace metadata/existing Kubernetes rights, and defines collection/privacy ceilings and reusable defaults. The administrator sees capability and connectivity gaps before enabling a policy.
2. **Service owner:** selects a Deployment or StatefulSet and a versioned preset, previews scope/budgets/expiry and enables it. Advanced recipes and log/resource/probe expressions remain available. Intrusive actions require approval; changes to the normalized execution spec invalidate its grant.
3. **On-call developer:** receives a content-free event, opens a case, sees the failure timeline and action outcomes, compares recurrences, and requests an additional capture if the process still exists. Partial evidence remains usable.
4. **AI-agent user:** authenticates to the central MCP endpoint, lists authorized cases, obtains structured extracts, and narrows queries. The agent may request a grant but cannot approve one or acquire cluster-execution privileges through evidence tools.
5. **Approver:** sees the exact operation, workload identities, byte/time/impact ceilings, requester, purpose, and expiry; approves a single execution or a versioned policy. The decision is independent of the requester's agent UI.
6. **Evidence owner:** shares specific existing evidence, or selects “Share results with…” while requesting capture, with named users/groups within the organization even if they lack ordinary workload access. Approved extracts are the default. Recurring sharing requires an explicit policy option, capture limit and expiry. Several owner teams may manage an instruction; the creating actor remains immutable. Any currently authorized manager can stop future registration or revoke the instruction and its shares. Revocation stops subsequent access, including through already issued cursors. Raw access still needs its own approval.
7. **Recipient:** sees only the shared case shell and allowed artifacts/extracts. No neighboring cases, hidden artifact counts, unrelated workload inventory, or unselected future recurrences become visible. A reviewed recurring instruction grants only concrete outputs from its registered captures.

8. **Privacy/retention operator:** sets finite retention maxima once, reviews their impact, handles restricted-processing/erasure requests and investigates overdue deletion across all managed copies. Application maintainers inherit those settings.

First-release effort targets and task acceptance are defined in [ergonomics](../specs/ergonomics.md); the comprehensive [review](ergonomics-review.md) records revisions across these journeys.

## Product boundaries

| Included | Excluded |
| --- | --- |
| Multiple enrolled Linux Kubernetes clusters through one hub | Cluster provisioning or node repair |
| Deployment/StatefulSet owner tracking and pod/container identity | Windows collection in the initial product |
| Dynamic, declarative trigger/action policies | Arbitrary executable plugins uploaded through MCP |
| Live and pre-trigger evidence, where a sensor is already armed | Reconstructing evidence that was never observed |
| Native/runtime dumps, profiles, files, logs, packet context | Guaranteed recovery of a core after SIGKILL or node loss |
| Encrypted retention, audit, grants, sharing within the organization | Hosting unrelated organizations in one hub, anonymous links, sharing across installations, anonymous or presigned bearer download URLs |
| Minimal case/approval/sharing browser | General observability dashboard or issue tracker |
| Deterministic pre-analysis and similarity | LLM inference, embedding services or autonomous remediation |

## First production release versus later coverage

The first production release includes the **whole path**: central multi-cluster enrollment, workload policies, log/cgroup/probe/external triggers, files/logs/process/network metadata, Go pprof CPU/heap profiles and bounded profile comparisons, bounded custom commands, Inspektor Gadget packet collection with pcap filters, live Kubernetes peers, segmented rings and qualified plain HTTP/1 header projections, PostgreSQL hub state, encrypted storage, deterministic analysis, MCP extracts, policy/individual grants, Kubernetes-based permission administration and metadata/exec inheritance, sharing within the organization including capture-time and bounded recurring-policy instructions, preset workflows, administrator retention maxima and privacy lifecycle controls, storm/resource protection and storage quotas, audit and offline installation. Native Linux core collection and C/C++/Rust/Go analysis are part of this first production gate after a separate kernel spike.

.NET integration follows in the same delivery sequence if its namespace/diagnostic-port tests pass. JVM, Node.js, Python and GPU-specific recipes are independent capability packs; the platform reports unsupported recipes explicitly until qualified. GPU support is an experimental integration with operator-provided NVIDIA infrastructure, not a claim that every GPU runtime component is open source. Deep raw queries are gated separately from the first useful extract interface.

## Non-functional objectives

These are acceptance **targets**, not measured performance claims. Test hardware, workload, traffic and exact images must accompany results.

| Area | Initial target |
| --- | --- |
| Enrollment scale | 10 clusters, 100 nodes total, 1,000 observed pod runtime sources, 200 policies |
| Incident rate | 1 sustained occurrence/second across the hub; burst 100 over 10 seconds, with per-workload limits |
| Local detection | Log match to durable occurrence acknowledgement p95 < 2 seconds under the reference load; cgroup sampling every 5 seconds |
| Action start | p95 < 5 seconds after an already authorized local trigger; no promise across a disconnected control plane |
| Hub visibility | p95 < 10 seconds after a durable local manifest when connected |
| Evidence queries | Indexed case list p95 < 2 seconds; simple extracts p95 < 3 seconds; expensive queries use explicit jobs |
| Idle node overhead | <= 100 millicores and 128 MiB excluding explicitly reserved rings and Inspektor Gadget; measure separately |
| Default packet overhead | No throughput claim until measured at 1/10 Gbit/s; packet loss counters always exposed |
| Authorization | Every operation checks identity eligibility, principal, current permissions, expiry and budget; no stale cache may extend a grant |
| Availability | Two hub/controller replicas supported; fail closed for new sensitive actions if authoritative authorization is unavailable |
| Evidence integrity | No artifact reported complete before upload finalization and manifest commit; incomplete evidence labeled explicitly |

Use Kubernetes for configuration/local control, PostgreSQL for hub transactional state, and object storage for evidence/audit. If the measured envelope fails, optimize batching/indexing or revise supported limits with the maintainer; no alternate database backend or broker is implied.

## Success examples

- A payments Deployment logs a panic pattern; Asservat freezes up to the configured 30 seconds of network headers and logs, reporting achieved coverage, snapshots selected `/proc` files, and records image digest, restart and probe history.
- A StatefulSet container exceeds 85% of its memory limit for 20 seconds; a reviewed policy collects stack summaries and a bounded heap diagnostic before an OOM, with no guarantee it finishes before the kill.
- A liveness failure opens a case containing probe events, recent cgroup pressure, socket state and a targeted capture of traffic to pods selected by label.
- A developer shares the resulting stack and timeline with an incident-response group outside the workload's normal ACL. A recipient's raw-memory request is denied until both share coverage and raw approval exist.

## Help choosing useful evidence

First-release [guided selection](../specs/guidance.md) starts with the maintainer's question: crashes, memory growth, CPU, latency, hangs, network/DNS or failed probes. Optional process inspection and short traffic reconnaissance lead to suggested stable process selectors, peer filters, evidence formats, history windows and ring sizes. The UI explains usefulness, cost, uncertainty, privacy and prerequisites. External agents receive the same assistance and executable plan handles through MCP. Users can skip guidance and edit advanced settings.

## Reuse previous diagnostics

[Capture history](../specs/capture-history.md) keeps accepted requests discoverable under their workload or authored pod selector. Maintainers and agents can restore a prior configuration and repeat it under current permissions and limits, including after an ordinary pod rollout. History includes failed/partial attempts, separates manual requests from automatic/discovery noise, and explains when saved parameters have expired. Evidence, history and parameter retention remain independent under their applicable privacy ceilings.

## Reusable capture building blocks

Maintainers can combine shipped or administrator-published capture profiles, adapt their exposed settings and save a derived namespace version when authorized. The initial catalog covers process/socket context, transport headers, plain HTTP/1 headers in both directions, Go CPU profiling and syscall activity across all pod processes. One preview explains the combined limits, conflicts, privacy and approval requirements; guidance, browser, GitOps and MCP use the same plan. History preserves the selected versions and edits. See [capture profiles](../specs/capture-profiles.md) and [syscalls](../specs/syscalls.md). Integration remains unimplemented.

## Two action lifecycles

The product separates **on-trigger collection** (dumps, commands, file/context reads and live profiles) from **ongoing recording, saved on trigger** (packets and syscalls by default). Ongoing sources are armed with finite authority and bounded buffers before incidents, then preserve the relevant window without restarting for each trigger. Manual sessions and explicit post-trigger-only variants remain finite. [Action lifecycles](../specs/action-lifecycle.md) defines costs, approvals, source readiness and missing-history behavior.

## Informed capture decisions

Before collection or enabling a policy, show combined workload effects, known pauses/CPU/I/O pressure, uncertainty and less disruptive alternatives. Explain possible user data/secrets, transient inspection versus retained contents, effective automatic-deletion ages and careful sharing/AI handling. Reuse the same assessment in normal previews/approvals and notices in evidence views, without another approval ceremony. [Capture assessment](../specs/capture-assessment.md) defines the contracts and boundaries.

## Save existing recordings

Maintainers can preserve current packet/syscall recordings from an explicitly authorized policy without waiting for its trigger or running its dumps/commands. Select the pod and existing sources, optionally shorten the lookback, review impact/data handling, and save under existing policy/workload limits. Progress, cancellation, capture-time sharing and history use the familiar capture flow. Repeating a saved-recording request selects current recordings; it cannot reconstruct expired history. Offline analysis requires operator-qualified encrypted scratch storage; collection can remain available while that prerequisite is unmet.

## Watch ongoing evidence live

Maintainers can inspect approved packet/flow metadata, HTTP headers and syscall metadata while existing sources record. A live view offers source selection, narrow display filters, pause/resume from now, bounded rows, loss/lag and expiry indicators, and the same finite workflow through MCP. View filters do not change acquisition; no collector starts from a passive page or read. Raw packet bodies/bytes and syscall arguments are inspected only after saving under the existing approval model, as explicitly selected by the maintainer.

Live rows are transient and may include user information. Saving current policy recordings is a separate admitted capture; it may not preserve a row that already rotated out. Manual sources keep their original finite capture lifetime. Neither a share nor an owner-manager role grants live access. See [live-watch behavior](../specs/live-watch.md).

## Local investigation is a first-class outcome

Every gathered artifact and saved derivative is downloadable in its native representation for local tools: Wireshark, GDB, profilers, editors and scripts. The same current authorization and applicable raw-download grant apply; there is no requirement to use Asservat's query sandbox. Offer available exact executable/symbol companions and disclose incomplete coverage. Local copies are outside managed automatic deletion. See [download contract](../specs/artifact-downloads.md).
