# Operator and maintainer workflows

First-release requirement. Feature rules live in their owning specs; this file states the task outcomes and acceptance measures. The [review](../docs/ergonomics-review.md) records coverage and rationale.

## REQ-UX-001 — Configure infrastructure once

Installation MUST be one Helm chart ([ADR-058](../docs/decisions/058-official-helm-installation.md)) whose default install works ([ADR-335](../docs/decisions/335-usable-by-default.md) D1), with a `combined` evaluation mode and the small-deployment alternatives of [deployment profiles](deployment-profiles.md). Workload clusters are registered in the hub's values ([ADR-334](../docs/decisions/334-connector-workload-identity.md)). Configured IdP, storage, keys, ceilings and retention defaults apply to every workload; GitOps sync needs no portal action. Uninstall and rollback preserve evidence and retention obligations. See the [installation guide](../docs/installation/helm.md).

A read-only capability report names each missing prerequisite, its effect, the responsible role and the remedy, per action and node pool. It distinguishes configured from verified; a separate synthetic qualification action verifies, and never runs a live dump or command. Missing core support does not disable logs or profiles.

New namespaces covered by an existing binding or source inherit access without an administrator ticket. Maintainers need no hub kubeconfig, node access, registry credentials or per-cluster account to investigate authorized evidence.

### SC-UX-001

Given a configured hub and qualified namespace source, when the normal provisioner creates an eligible application namespace, then its maintainers can select that workload without an Asservat administrator ticket. On a node pool without core support, context capture remains available and the report names the missing core prerequisite.

## REQ-UX-002 — Presets and progressive configuration

The browser MUST offer select workload → choose a goal or diagnostic → review the effective plan → collect or enable. [Guided selection](guidance.md) adds optional discovery and recommendations; the direct path stays. Pods are the unit; there is no container picker. Action DAGs, detector expressions and budgets are optional advanced controls.

A preset is a builtin capture profile: `presetRef: {name, version}` is shorthand for a one-component builtin composition with no edits ([capture profiles](capture-profiles.md)). Versions are immutable; an upgrade never changes a pinned preset; administrators can disable entries. Initial presets:

| Preset | Purpose | Defaults |
| --- | --- | --- |
| `workload-failure/v1` | Automatic context on a restart or liveness failure, optionally a log match | All authorized replicas observed; one pod collected per incident, including unready pods; `basic-context` actions; 5-minute cooldown, burst 2 ([triggers](triggers.md)) |
| `incident-context/v1` | One manual context capture | One pod; `basic-context` actions ([example](../examples/recipe-basic-context.yaml)): Kubernetes state, recent logs, process and network counters |
| `pod-status/v1` | One pod-status snapshot | Exactly one pod via the immutable `builtin-pod-status-v1` recipe ([definition](../examples/recipe-pod-status.json)); no user overrides |

`pod-status/v1` accepts a Deployment, StatefulSet or Pod. A workload resolves one scheduled, non-deleting pod in name order; a direct Pod keeps its real owner for permissions and budgets. Preview names that pod. A missing probe source is Unknown, not successful monitoring. Preview shows monitored pod counts, evidence classes, maximum bytes, approval need and expiry, and never collects. The impact and data-handling panel is the [capture assessment](capture-assessment.md).

The controller resolves cluster, workload, digests and execution identity ([execution](execution.md)); users never compute hashes, UIDs or grant names. Retention requests above the administrator maximum are clamped with a visible explanation.

### SC-UX-002

Given the [short policy example](../examples/policy-preset.yaml) and an eligible multi-container pod, when accepted, then the controller fills the execution plan without a user computing hashes, UIDs or grant names. An unknown preset, unresolved pod or unavailable required capability yields a specific field-level condition. Reapplying the same accepted capture cannot collect twice.

## REQ-UX-003 — Approvals without repeated form filling

Approvals follow [authorization](authorization.md) and [investigation approval](investigation-approval.md). The workflow MUST resolve existing grants and pending requests before offering a new request, show one reviewable plan, and let the approval start the work. A raw-analysis grant covers several queries within its budget. A reviewer renews a policy grant in place; re-applying unchanged YAML keeps it. Metadata-only edits keep approval; target, executor, trigger, recipe, sensitivity and budget changes do not. Authorized context runs while an optional intrusive action waits; a waiting required action makes the result Partial, never silently successful.

### SC-UX-003

Given a case needing three bounded raw queries, when one suitable grant is approved, then the same principal uses it within quota from the console or an MCP client without three approval forms. Changing only a display label preserves the normalized plan; adding a dump invalidates approval. Waiting for optional profiling does not lose already authorized logs.

## REQ-UX-004 — Useful status and recovery

Every blocked or partial item MUST give a stable reason, remedy, responsible role and retryability without exposing unauthorized inventory (for example: missing endpoint → app maintainer; blocked ceiling → cluster admin; expired raw grant → requester; expired evidence → not retryable). Status shows `observedGeneration`, actual history coverage and next eligible capture time. Drafts survive validation errors. A failed optional action never hides successful evidence. An ambiguous intrusive action never gets a Retry button. Support diagnostics carry versions, condition codes and opaque IDs, never evidence, tokens, argv values or user labels.

### SC-UX-004

Given an upload succeeded but symbol acquisition failed, when the user opens the case, then available context is immediately readable, symbolized analysis is marked incomplete with a remedy, and retrying analysis cannot trigger another dump. A disconnected cluster cannot appear freshly monitored.

## REQ-UX-005 — Evidence, sharing and AI handoff

One case URL and one MCP endpoint per installation. Authorized cases across clusters are listed with shared-with-me, workload, time and capability filters. An AI client is registered once; the case page supplies the endpoint and case reference, never a token or download URL. Baselines are offered, not copied by digest.

Sharing starts from selected artifacts, from “Share results with…” on a capture request (default approved extracts), or from “Share future captures” on a policy ([REQ-SHR-004](authorization.md), [REQ-SHR-005](authorization.md)). Recipients are picked by name; the sender sees a recipient-view preview. Recipients need no cluster access. Stop and Revoke are distinct. Evidence views and AI handoff repeat the sensitivity and deletion notice and state that copies already taken cannot be recalled ([privacy](privacy.md)).

### SC-UX-005

Given an extract shared with a colleague lacking workload access, when they open the link or connect their approved agent, then one organization login exposes only that snapshot. They do not need kubectl, artifact hashes, another cluster login or a raw grant to read the shared extract.

## REQ-UX-006 — Measure effort before release

Run the task-based study in [validation](../docs/validation.md) with administrators and app maintainers unfamiliar with the implementation. Observe completion, active time, steps, errors, help requests and ability to explain scope and expiry. Developer walkthroughs do not substitute. Keyboard operation, labels, focus and error handling, contrast, non-color states and screen-reader status updates are acceptance criteria ([REQ-UI-005](user-experience.md)).

Release goals after infrastructure setup: first context capture within 3 minutes of active effort; agent handoff and extract share each within 2 minutes; no administrator interaction per new workload; no hash or UID entered on basic paths. Collection and approval waits are reported separately. These are hypotheses to test; blockers found are fixed before the console is declared complete.

### SC-UX-006

Given a fresh maintainer account and a synthetic eligible workload, when a participant collects context, finds a partial-result explanation and shares an extract, then task metrics and authorization understanding are recorded. A keyboard-only participant can complete the same workflow. Manual digest copying or an unnecessary admin ticket fails the basic-path criterion.

## Workflow entry points

Each workflow is specified by its owner; the console offers it where named.

- **Packet presets** with a Kubernetes peer picker and optional advanced filter: [packets](packets.md).
- **Recent captures** and **Repeat capture**: [capture history](capture-history.md).
- **Add capture profile** and **Save as profile**: [capture profiles](capture-profiles.md).
- **Runs on trigger** versus **Records while armed; saves on trigger**: [action lifecycles](action-lifecycle.md).
- **Save recordings now**, one click: [recording saves](recording-saves.md).
- One review for collection plus result access: [investigation approval](investigation-approval.md).
