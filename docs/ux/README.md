# Asservat user experience

Open the [interactive mockups](../../design/ui/index.html) in a browser. They work as local files; alternatively, from the repository run `python3 -m http.server 8765 --bind 127.0.0.1` and open `http://127.0.0.1:8765/design/ui/`. This serves a local design preview, not a product backend.

The prototype covers **63 screens** in one console, with maintainer, evidence-recipient, independent-approver and operator views. The **Prototype controls** button opens a persona/screen/state inspector. It is closed by default and is not part of the product. The light console uses section navigation, broad evidence tables and optional detail disclosures; [research and rationale](web-design-research.md) explain the overhaul. Every screen supports normal, loading, empty, access-changed, expired, offline and quota scenarios. Some states illustrate a generic boundary; production uses the precise per-workflow rules in [workflows](workflows.md).

Start with these walkthroughs:

1. Workloads → checkout-api → Collect evidence → compose profiles → process/network settings → review → partial results → case.
2. Captures → Recordings → Save existing recordings now → saved packet/syscall windows. This never runs a core action.
3. Monitoring → edit conditions and ongoing/on-trigger evidence → review changes.
4. Case → network/profile/stack viewers → request bounded raw access; switch to Approver for independent review.
5. Case → Share evidence → switch to Share recipient → Shared with me. Hidden workload navigation and artifact counts stay absent.
6. Switch to Operator + maintainer → Administration → readiness/capabilities → permission/retention preview → capacity → overdue deletion.

Representative screenshots (synthetic data): [workspace](../../design/ui/previews/workspace.png), [capture review](../../design/ui/previews/capture-review.png), [mobile review](../../design/ui/previews/mobile-review.png), [evidence](../../design/ui/previews/evidence.png), [administration](../../design/ui/previews/administration.png). The [surface catalog](surfaces.yaml) is the complete screen, persona, dialog and journey inventory.

![Workspace mockup](../../design/ui/previews/workspace.png)

## What is interactive

Section navigation, the prototype inspector and persona/state selection, capture-profile selection and its impact notice, goal selection, ring-size arithmetic, table filtering, one additional trigger, representative action dialogs, capture/save transitions, policy/share state changes, case-reference copy, mobile navigation and reset. Mutations affect only in-memory synthetic state. Collection/save review submits directly; it does not add a second generic confirmation screen.

Other fields demonstrate layout, labels, bounded options and validation placement. They do **not** compile an execution plan, persist edits across routes, resolve a real selector, implement OIDC, approve a grant, export a validated CRD or collect/analyze data. The example charts and qualification states are synthetic. There are no network calls, remote fonts, analytics, application dependencies or localStorage evidence persistence.

This is a functional review artifact alongside [behavior requirements](../../specs/user-experience.md), [design system](design-system.md), [workflows](workflows.md), [domain model](../domain/README.md) and [outward interfaces](../interfaces/README.md). Runtime implementation remains behind the existing review/feasibility gate. Browser checks establish prototype consistency, not authorization enforcement or WCAG certification.

Validation results: [prototype report](prototype-validation.json), [recorded commands](../research/spec-validation.txt). The checked-in report gives the actual assertion count, all 63 screens, seven states, viewport widths, JavaScript errors, external requests and automated WCAG-tagged results. Manual accessibility and participant testing remain pending.

Live-watch walkthrough: Workload → Watch live → choose an existing source → Start live view. Try HTTP headers, packet metadata and syscall metadata, Errors-only filtering, Pause/Resume, and Save recordings. Simulated loss is under Prototype controls → Live-view simulation. The stream is generated locally and rows expire; no cluster is connected. [Live-watch specification](../../specs/live-watch.md) and [live preview](../../design/ui/previews/live-watch.png) explain the approved-projection boundary.

The common native-download mockup is [Download evidence](../../design/ui/index.html#/artifact-download). Packet/core/profile viewers and the common evidence navigation link to it; it covers all native artifact types, missing raw authority, cancellation and external-copy handling. No actual file is produced by the synthetic prototype.


The [user-task review](../reviews/user-task-review.md) separates corrected interactions from open product gaps. The prototype includes optional combined collection/result review, relevant profile settings only, and immediate saving of reviewed recording defaults from the inventory or live viewer. [Combined-review preview](../../design/ui/previews/investigation-approval.png). Real participant and end-to-end production tests remain unrun.
