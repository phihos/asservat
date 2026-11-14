# Capture impact and sensitive-data assessment

Every capture and policy preview shows one **Workload impact and data handling** panel: what the plan may do to the workload, what data it may observe or keep, and when that data is deleted. The panel is a deterministic projection of the compiled plan ([contract](contracts/capture-assessment.schema.json)). It adds no approval step, permission or AI, and it never promises harmless collection. The [pod-status assessment](../docs/architecture/context-assessment.md) and the `recorder-assessment/v2` rules ([ADR-243](../docs/decisions/243-packet-syscall-plans-in-preview.md)) apply it to the first plans.

## REQ-ASM-001 — Effects per action

Each action gets a level (`low`, `moderate`, `high`, `unknown`), a `hasUnknowns` flag, effect codes and one short explanation: pauses or GC, application CPU or allocation, kernel/collector CPU, ring memory, storage and upload contention, changed application state. The text says where the work happens; a collector limit does not bound work inside the application or kernel. `impact: observe|sensitiveRead|intrusive` stays the authorization class, not a performance forecast.

Quantities are labelled as **configured limits**, **measurements** (with their environment) or **estimates** (with their source). Nothing else is shown: no CPU percentage, dump size, latency or pause length is invented from an action name or output cap, and a 10-second stop limit is shown as a limit, not a predicted pause. Missing or stale metrics (older than twice their source's sample interval), unknown runtimes, unqualified adapters, arbitrary commands and files are `unknown`, which never means low impact or no user data. The preview never runs a trial, attaches, reads memory or payload, or executes a command.

### SC-ASM-001

Given a live dump with a stop limit, an unqualified CPU profiler and stale metrics, when previewed, then the user sees possible pauses, the stop limit, the missing measurements and the uncertainty. No percentage or test capture is fabricated, and a profile's friendly name hides nothing.

## REQ-ASM-002 — The combined plan

The panel assesses the compiled plan: recorder cost over all observation pods separately from per-incident cost over selected pods, so one-pod dumps do not make 100 recorded replicas look cheap. Reservations add up where they coexist and use the peak for serial schedules; percentages with different bases, output caps as expected sizes and latency estimates are never added. Aggregate pressure from other active captures on the same workload or node is shown without revealing another team's targets or settings.

The combined level is at least the highest known action level, and `hasUnknowns` is set if any part is unknown. Conflicts (exclusive profilers, overlapping hooks, low headroom, dump bursts) are shown; hard conflicts and ceilings stay blocked by admission. The panel offers alternatives, at most one per action and dimension (narrower peers, syscalls or processes, shorter windows, fewer incident pods, metadata only, dropping an expensive action), each stating the coverage it loses; none is applied silently.

The assessment is computed at preview and again at submission; a changed plan or new material warning shows up as a changed `plan_digest`, not as a separate consent. Admission ceilings, not the assessment, govern runtime; unchanged policies need no re-approval when metrics change.

### SC-ASM-002

Given two recorders, a dump, 20 observed replicas and one incident pod, when compiled, then recorder costs cover 20 pods and dump costs one. Missing measurements stay explicit; incompatible profilers or insufficient memory stay blocked. A narrower alternative states what it will miss.

## REQ-ASM-003 — Data that may be observed or kept

For each action and the plan, the panel lists the privacy class and the categories that **may be kept** and that are **inspected transiently but not kept**: user content, credentials, personal identifiers, addresses, paths, profile labels, unknown data. "May contain" is a conservative statement about the mechanism, not a finding.

| Mechanism | Shown as |
| --- | --- |
| Core or heap dump | Memory may hold user objects, secrets and credentials; redaction is not assumed |
| Go pprof profile | Sampled stacks or allocations with labels and paths; not a full heap |
| Raw packets, syscall arguments | Payloads may hold user content, credentials and identifiers |
| HTTP-header projection | Bodies and other headers are parsed transiently; kept fields can still identify users; encrypted protocols are not covered |
| Network headers, syscall metadata | No payload or arguments; addresses, timing and process context remain |
| Logs, files, command output | May hold user data or secrets; unknown formats stay unknown |

Encryption, header-only capture and redaction do not make data anonymous. The panel shows the raw source's risk separately from what a recipient of a projection receives, and its text never repeats a discovered value.

### SC-ASM-003

Given projected HTTP headers plus a core, when reviewed, then the parser's transient inspection and the core's memory risk are both visible. Sharing a projection does not relabel the core. A pprof heap profile is described as sampled allocations, and an unknown command keeps its unknown-content warning.

## REQ-ASM-004 — Deletion and handling

Before collection the panel shows each action's access age and deletion age, the administrator maximum and the anchor rule, as relative durations: `accessAgeSeconds` ends access, `deleteAgeSeconds` (access age plus the deletion budget) ends the managed copy, and a shorter requested lifetime brings both forward. A manual capture is anchored at submission (`submissionPreparation`), so waiting uses up its lifetime; a saved recorder window is anchored at its earliest source segment (`firstAcquisitionOrEarlierSource`). After acquisition each artifact shows `expiresAt` and `deleteBy`; mixed plans show the earliest first. Copies and shares never renew retention.

Deletion applies to **Asservat-managed copies**. Artifacts show access ended, deletion pending, deleted (verified) or overdue; expired access is never shown as deleted, and an overdue deletion stays visible. An approved preservation exception is shown to eligible viewers. Before capture, viewing, sharing and agent handoff the panel reminds users to collect the smallest useful scope, prefer extracts and review recipients, and states that copies already delivered to people or agents **cannot be recalled by Asservat**. It links the administrator's handling policy. These notices are operational guidance, not a legal basis or consent.

### SC-ASM-004

Given a six-hour core maximum (default 14 days), a five-minute deletion budget and a recorder source, when previewed, then the ages start at the earliest source segment. After acquisition at 12:00, access ends by 17:55 and deletion is due by 18:00; an outage past 18:00 shows overdue with access denied, and an agent's copy is not claimed deleted.

## REQ-ASM-005 — One panel in browser, MCP and GitOps

The panel puts the combined effect, likely sensitive contents, deletion ages and handling reminder next to Collect/Enable and the approval review; details expand on demand, without scores to decode or one warning per action to dismiss. Edits update it; a repeat recomputes it.

MCP `preview_capture` returns `capture_assessment` with the plan digest, per-action effects, data and retention, combined impact, quantities and alternatives; the summary and warnings come first and details continue through a cursor within the MCP result bound. `get_case`, `list_artifacts` and evidence-query results carry each visible artifact's sensitivity and deletion notice, never for hidden artifacts. Policies applied through Kubernetes get the same assessment in status before they start. Accepted captures store only the assessment's rule and capability digests; the text is recomputed from the plan (ADR-330 D9). Rules ship offline as versioned data; administrators may add stricter rules. No assessment CRD, telemetry or scan of captured data exists ([research](../docs/research/capture-assessment.md)).

For a [recording save](recording-saves.md), the panel describes saving existing recordings: no new recorder, the incremental freeze, encryption and upload cost, and deletion ages from the original segments. For a policy recorder, it states that the source runs while the policy applies (and its grant is unexpired), stops when a revocation event reaches its connector and runs to its hard end while disconnected (REQ-LIF-004), and shows rate and ring ceilings, or rate × duration for a manual sensitive session, apart from measured use.

### SC-ASM-005

Given the same composed plan in browser, MCP and GitOps, when assessed, then the same warnings and retention apply. Changing a ring, batch or data mode updates them; repeated context capture needs no new consent. A share recipient sees only that artifact's notice. A stale assessment is never proof of low impact.
