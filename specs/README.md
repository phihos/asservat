# Behavior specifications

These files define the product. Read [conventions](../docs/specification-format.md) first. Each rule has one owning spec; other specs link to it instead of restating it.

| Specification | Owns |
| --- | --- |
| [User experience](user-experience.md) | Console structure, states and accessibility |
| [Ergonomics](ergonomics.md) | Presets, setup, task outcomes and the usability study |
| [Domain foundation](domain-model.md) | Core entity glossary and identity boundaries |
| [Outward interfaces](interfaces.md) | Shared browser/MCP services and public API conventions (pagination, idempotency, authority reuse, status waits) |
| [APIs](apis.md) | CRD inventory, capture status, contract bounds |
| [Execution identities](execution.md) | Submission, digests, acceptance and capture progress |
| [Targets](targets.md) | Workload ownership and pod selection |
| [Triggers](triggers.md) | Detectors, expressions, deduplication and rate limits |
| [Action lifecycles](action-lifecycle.md) | On-trigger versus ongoing recording and save windows |
| [Actions](actions.md) | Files, commands, captures, dumps and profiles |
| [Capture assessment](capture-assessment.md) | Workload impact and data-handling notices |
| [Reusable capture profiles](capture-profiles.md) | Catalogs, versions, typed edits and composition |
| [Capture history](capture-history.md) | Request history and repeat |
| [Guided evidence selection](guidance.md) | Goals, discovery and recommendations |
| [Recording saves](recording-saves.md) | Saving existing policy recordings |
| [Live watching](live-watch.md) | Finite approved live views |
| [Packets](packets.md) | Filters, peers, segmented rings and protocol extraction |
| [Syscalls](syscalls.md) | Pod-wide syscall traces |
| [Runtime profiles](profiles.md) | pprof, runtime traces and comparisons |
| [Evidence](evidence.md) | Encryption, manifests, cases and analysis |
| [Artifact downloads](artifact-downloads.md) | Native downloads of all evidence |
| [Privacy](privacy.md) | Classification, retention maximum, deletion and rights requests |
| [Capacity isolation](capacity.md) | Storm protection, budgets and storage isolation |
| [Authorization and sharing](authorization.md) | Roles, grants, approvals, sharing, revocation and audit |
| [Investigation approval](investigation-approval.md) | One review for collection plus result access |
| [Permission management](permissions.md) | AccessBindings, PermissionSources and inheritance |
| [Policy automation](policy-automation.md) | Team policy execution separate from human sessions |
| [MCP](mcp.md) | Tools, bounded results and analysis queries |
| [Federation and events](federation.md) | Multi-cluster connection, work delivery and CloudEvents |
| [Hub persistence](persistence.md) | SQL tables, transactions, outbox and recovery |
| [Deployment profiles](deployment-profiles.md) | Bundled dependencies, backup and restore |
| [Implementation architecture](implementation-architecture.md) | Runtime roles and component ownership |

`contracts/` holds JSON Schema 2020-12 contracts; [examples](../examples/README.md) include CRDs and runtime DTOs. [Traceability](traceability.yaml) links requirements to scenarios and tasks. Gates: `make spec-check`, `make architecture-check`, `make download-check`.
