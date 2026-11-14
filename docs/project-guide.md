# Project guide

Use the [development workflow](development-workflow.md) for implementation,
integration review, staged checks and retained debugging fixtures.

The detailed project orientation that previously opened the repository README:
component status notes, the full reading map, confirmed product decisions and the
validation commands. The [README](../README.md) is the short introduction.

See [product implementation status](implementation-status.md) for the current
feature inventory, verified user outcomes and remaining work. Component tests and
design documents do not establish a completed installed debugging platform. For a source-built pod-status installation, use the [external-services context trial](installation/context-trial.md). The component notes below record historical checkpoints; use the linked implementation status for current qualification.

Asservat is a proposed Kubernetes debugging platform that preserves evidence when a workload behaves suspiciously and makes that evidence available to developers and their AI agents through controlled MCP queries and authenticated native-file downloads for local tools.

The pod is the unit of configuration, permission and collection; container/process identity is retained internally for provenance. Monitor all authorized replicas within administrator limits and bound collection separately.

Point a policy at a Deployment, StatefulSet, or selected pods. Combine log patterns, resource thresholds, probe failures, crashes, and external alerts with bounded evidence recipes: logs, container files and `/proc`, packet captures, pprof and similar runtime profiles, core dumps, bounded syscall traces, and custom commands. Versioned capture profiles let users compose and adapt these collectors. Collection and analysis run close to the workload; one central service manages multiple clusters, cases, approvals, and sharing.

**Current status:** see [product implementation status](implementation-status.md) for verified workflows and remaining gaps, and the [context trial](installation/context-trial.md) for the source-built Helm procedure. The mechanism investigations and component checkpoints below do not establish production support or a supported release.

## Start here

**Official installation method: Helm.** The [chart](../charts/asservat/README.md) renders every object; a secrets hook Job and a setup Job handle live external state ([installation guide](installation/helm.md), ADR-327/328). The current system design is [ADR-330](decisions/330-event-driven-system-design.md).

| Read | Purpose |
| --- | --- |
| [UI mockups and workflows](ux/README.md) | Navigable 63-screen console, desktop/mobile previews and role/failure states |
| [Web GUI design research](ux/web-design-research.md) | Primary-source findings, minimalist overhaul and validation limits |
| [Domain model](domain/README.md) | Entities, relationships, invariants and SQL/CRD/Go boundaries |
| [Outward interfaces](interfaces/README.md) | MCP journeys, browser OpenAPI, configuration, identity and integrations |
| [Full design review](reviews/design-review.md) | Ranked defects, fixes, remaining risks and document coverage |
| [Final correctness review](reviews/final-review.md) | Additional boundary defects, applied corrections and accepted feature priorities |
| [Use-case walkthroughs](reviews/use-case-walkthroughs.md) | Tabletop incident, administrator and agent workflows |
| [Product definition](product.md) | Scope, users, workflows, requirements and boundaries |
| [Research findings](research/findings.md) | Claim-by-claim corrections, source evidence, feasibility and unknowns |
| [Kubeshark comparison](research/kubeshark-comparison.md) | Verified overlap, automation capabilities and the broader evidence scope |
| [Implementation architecture](architecture/README.md) | Applications, component/module ownership, internal protocols, failure walkthroughs and implementation slices |
| [Architecture](architecture.md) | Central multi-cluster design, trust boundaries, storage and failure behavior |
| [PostgreSQL reassessment (ADR-023)](decisions/README.md) | Accepted change: Kubernetes configuration, PostgreSQL hub state, object-store evidence |
| [Technology choices](technology.md) | Selected stack, alternatives, dependency licences and no-call-home review |
| [Small-deployment alternatives](research/small-deployments.md) | Researched internal identity/keys, bundled storage/database, backups, maintenance and migration recommendations |
| [Build or reuse](architecture/build-or-reuse.md) | All 24 component responsibilities, reusable libraries/tools and integration risks |
| [Technology experiments](../experiments/technology-selection/README.md) | Reproducible synthetic dependency tests, failures and remaining qualification |
| [Packet and download feasibility](research/feasibility-packet-downloads.md) | Actual VM capture, filter/compiler findings, endpoint-map updates, ring pressure and a 2 GiB encrypted native-download experiment |
| [SQL and crash-path feasibility](research/feasibility-control-crash.md) | Actual grant/quota races, lost COMMIT reply, expiry defects and bounded native-core handoff with GDB verification |
| [Specification format](specification-format.md) | Research into agent workflows and the format used here |
| [Behavior specifications](../specs/README.md) | Normative behavior, interfaces and acceptance scenarios |
| [Ergonomics review](ergonomics-review.md) | Reduced setup effort, preset workflows, approval/sharing journeys and usability gates |
| [Storm control and quotas](../specs/capacity.md) | Workload-wide admission limits, resource fairness and protected storage allocations |
| [Capture impact and data handling](../specs/capture-assessment.md) | Combined workload effects, uncertainty, sensitive contents and automatic-deletion notices |
| [Live watching](../specs/live-watch.md) | Watch approved packet/HTTP and syscall projections through UI and MCP; save before raw inspection |
| [Save existing recordings](../specs/recording-saves.md) | Preserve authorized packet/syscall history without firing dumps or starting another recorder |
| [Action lifecycles](../specs/action-lifecycle.md) | On-trigger actions, continuously armed recorders and bounded incident saves |
| [Reusable capture profiles](../specs/capture-profiles.md) | Shipped/admin catalogs, typed customization and composition into one bounded plan |
| [Syscall evidence](../specs/syscalls.md) | All pod processes, bounded metadata or approved argument traces, and MCP analysis |
| [Capture history](../specs/capture-history.md) | Find past requests for the same selector and restore their settings into a fresh capture |
| [Guided evidence selection](../specs/guidance.md) | Goal-based playbooks, process/traffic discovery, suggested filters and capture sizing |
| [Packet capture](../specs/packets.md) | Pcap filters, live Service/workload peers, bounded rings and HTTP headers |
| [Hub persistence](../specs/persistence.md) | SQL state, transaction boundaries, outbox, durability and restore |
| [Privacy and retention](../specs/privacy.md) | Administrator maxima, user-data handling, copy deletion and GDPR-related controls |
| [Security model](security.md) | Threats, grants, evidence sharing, isolation and privacy |
| [Permission automation](../specs/permissions.md) | Kubernetes API, GitOps bindings, namespace metadata and inherited exec rights |
| [Operations](operations.md) | Packaging, sizing, retention, recovery, upgrades and air gaps |
| [Validation plan](validation.md) | Experiments, acceptance gates and supported-environment criteria |
| [Implementation plan](implementation-plan.md) | Ordered work packages and review checkpoints |
| [Decision records](decisions/README.md) | User decisions and proposed architectural decisions |
| [Examples](../examples/README.md) | Concrete policies, capture requests, grants, sharing and evidence contracts |

The [original brief](research/original-brief.md) is preserved verbatim for provenance. Where it conflicts with the current design, the findings and decision records explain the change.

## Confirmed product decisions

- One organization per installation, with central management of multiple clusters from the first release. Teams use workload access controls and explicit evidence sharing.
- Reviewed, expiring policy grants may authorize automatic intrusive actions; ad hoc intrusive actions require individual approval. [Team policies](../specs/policy-automation.md) use bounded administrator delegation and survive creator departure; people still need current rights to manage or inspect evidence. Standard OIDC sessions require no directory-reader service account.
- PostgreSQL stores transactional hub state and the catalog. Kubernetes remains the configuration/local-control API; object storage holds encrypted evidence and durable audit. No message broker is required.
- Small installations must have internal users/login, static-key encryption and Helm-provided PostgreSQL alternatives. Dependency providers are independently selectable; bundled evidence storage is planned. Accepted package choices and pending qualification are tracked in [ADR-063](decisions/063-small-deployment-alternatives.md).
- Evidence may be shared with otherwise ineligible users or groups **within the organization**. Owners may select recipients when requesting a capture, or explicitly authorize bounded recurring-policy sharing. Multiple owner teams can manage shares while the creating actor remains auditable. Sharing does not bypass raw-access controls.
- Automate permission management through CRDs and the Kubernetes API. Administrators can enable inheritance from protected namespace/workload metadata or existing Kubernetes permissions, including pod exec rights.
- Low-effort administration and investigation are first-release requirements. Retention maxima are administrator controlled and include derived evidence and managed copies.
- No embedded LLM or agent harness, third-party telemetry, required SaaS, or writes to ticket/chat/wiki systems.
- Encrypt evidence on the collection node. Offline analysis requires operator-qualified encrypted scratch storage. Keep workload namespaces at Pod Security `restricted`.
- Maintainers can save existing packet/syscall recordings under explicitly reviewed policy scope, using normal capture limits, history and sharing.

## Validate this specification

`make spec-check` checks local links, JSON/YAML syntax, schema-backed examples, requirement/scenario/task references, and contract consistency. See [the specification format](specification-format.md) for the development-only validator dependencies. This command is not a runtime or Kubernetes feasibility test.

`make architecture-check` adds component/dependency ownership, internal control-contract examples and synthetic retry/idempotency checks. `make design-check` checks the domain, screens and browser/MCP contract mapping. These gates validate the design. `make go-check` and `make go-architecture-check` validate the implemented Go components; `make context-integration` creates owned real-service fixtures for their integration test. None establishes a complete production investigation.

`make custody-integration` creates owned PostgreSQL/S3 fixtures for storage-accounting races and verified version/multipart cleanup. `make sql-tools` installs pinned development tools; `make sql-check` detects generated query drift. Set `TMPDIR` to a filesystem with adequate space when building Go; on this workstation use `/home/phil/.cache/asservat-build/tmp`.

`make context-integration` also verifies the complete pod-status artifact through Kubernetes, OpenBao, S3 and PostgreSQL in one fixture. `make manifest-schema-check`, included in `go-check`, rejects drift between canonical and embedded schemas. These checks do not provide end-user authority or publish evidence.

`make permission-integration` creates and removes its own Kind cluster for permission observation/RBAC tests. Its permissive test CRDs are not production installation manifests. `make permission-schema-check`, included in `go-check`, validates the reader's embedded schema bundle.

The recorded documentation check is in [spec-validation.txt](research/spec-validation.txt).

Native downloads for every collected artifact and saved derivative are specified in [artifact-downloads.md](../specs/artifact-downloads.md). This supersedes the original raw-file export restriction; managed encryption, current access and raw-download grants still apply.

The [review from user outcomes](reviews/user-task-review.md) records additional task blockers, applied contract corrections and outstanding recommendations. [Combined investigation approval](../specs/investigation-approval.md) implements the accepted one-review decision in the design; no runtime has been built.

`make fleet-integration` owns PostgreSQL/S3/OpenBao fixtures for credential-channel, enrollment and current TLS-registration tests. It does not create Kubernetes clusters or install collectors.

`make helm-check` validates and packages the official chart without a cluster. `make helm-integration` creates and removes its own Kind cluster to test the chart's configuration install/upgrade/rollback/uninstall lifecycle and preserved custom resources. Neither enables collection.

[Native download sessions](architecture/download-sessions.md) describe how the regional reader streams downloads over the connector connection; [implementation progress](implementation-progress.md) records what has been qualified.
