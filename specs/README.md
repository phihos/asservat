# Behavior specifications

These files define the proposed product. Read [conventions and workflow](../docs/specification-format.md) first.

| Specification | Responsibility |
| --- | --- |
| [User experience](user-experience.md) | Role-aware console, bounded authoring, accessibility and reviewable mockups |
| [Domain foundation](domain-model.md) | Identity, lifecycle, lineage, authority and implementation mapping |
| [Outward interfaces](interfaces.md) | Shared services, typed browser/MCP boundaries, review and integrations |
| [Execution identities](execution.md) | Submission, collection/sharing digests, acceptance and partial progress |
| [Targets](targets.md) | Deployment/StatefulSet ownership, container identity and selection |
| [Triggers](triggers.md) | Dynamic detectors, expressions, deduplication and rate limits |
| [Capture assessment](capture-assessment.md) | Combined workload effects, sensitive contents, deletion notices and alternatives |
| [Live watching](live-watch.md) | Finite approved live views, independent filters, bounds, gaps and privacy |
| [Recording saves](recording-saves.md) | Snapshot existing authorized policy rings through the shared capture workflow |
| [Action lifecycles](action-lifecycle.md) | On-trigger acquisition versus ongoing recording and save-on-trigger windows |
| [Actions](actions.md) | Files, commands, captures, dumps, profiles and safety budgets |
| [Reusable capture profiles](capture-profiles.md) | Versioned catalogs, typed edits, composition and publication |
| [Syscalls](syscalls.md) | Bounded pod-wide metadata/argument traces and analysis |
| [Capture history](capture-history.md) | Selector-scoped request history, private parameter snapshots and repeat with current checks |
| [Guided evidence selection](guidance.md) | Diagnostic goals, process/protocol discovery and executable recommendations for people and agents |
| [Packets](packets.md) | Filters, live peers, segmented rings, protocol profiles and MCP |
| [Hub persistence](persistence.md) | SQL authority, tables, transactions, durable work and recovery |
| [Runtime profiles](profiles.md) | Go pprof, runtime traces, profiling overhead, baselines and comparisons |
| [Ergonomics](ergonomics.md) | Presets, administrator setup, approvals, troubleshooting, sharing and task-based acceptance |
| [Deployment profiles](deployment-profiles.md) | Internal identity/key alternatives, bundled PostgreSQL/evidence storage, bootstrap, backup and provider migration |
| [Capacity isolation](capacity.md) | Trigger storms, impact budgets, fair uploads, protected storage and durable quota accounting |
| [Privacy](privacy.md) | User-data classification, administrator retention maxima, deletion, rights requests and external AI disclosure |
| [Evidence](evidence.md) | Encryption, manifests, cases, retention and indexes |
| [Authorization and sharing](authorization.md) | RBAC, scopes, grants, snapshot/capture-time/recurring sharing, revocation and audit |
| [Permission management](permissions.md) | Kubernetes API, explicit bindings, trusted metadata and Kubernetes permission inheritance |
| [MCP](mcp.md) | Tools, bounded results, authentication and safe analysis queries |
| [Federation and events](federation.md) | Multi-cluster control, disconnects, reconciliation and CloudEvents |
| [APIs](apis.md) | CRD inventory, common types, state machines and API conventions |

`contracts/` contains portable JSON Schema 2020-12 contracts. [Examples](../examples/README.md) include proposed CRDs and hub runtime DTOs. Only the CRD examples are intended for future kubectl use; grants, shares and sharing intents are service records. [Traceability](traceability.yaml) connects every normative requirement to acceptance scenarios and implementation tasks.

The [implementation architecture requirements](implementation-architecture.md) and [architecture package](../docs/architecture/README.md) assign the behavioral requirements to applications/components and internal contracts. Validate that mapping with `make architecture-check` in addition to `make spec-check`.

[Artifact downloads](artifact-downloads.md) define REQ-DLD-001–004: all native evidence types, existing authority reuse, bounded transfer/resume and truthful local-copy handling. Validate with `make download-check` as well as the ordinary contract/design gates.

[Investigation approval](investigation-approval.md) specifies one bounded human review covering manual acquisition and the same developer's selected result inspection/download (REQ-INV-001–003).

Team policy execution and the human/automation authority split refine existing authorization IDs in [policy automation](policy-automation.md).
