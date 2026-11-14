# Implementation architecture

This package refines the [system architecture](../architecture.md), [domain model](../domain/README.md) and [public interfaces](../interfaces/README.md) into applications, components, interfaces and runtime flows. Mechanisms follow [ADR-330](../decisions/330-event-driven-system-design.md) (events instead of polling, one connector connection, standard identity, long-running regional readers, one authorization per operation, audit rows in SQL, idempotency keys) and the [ADR-328](../decisions/328-administrator-only-namespaces.md) threat model. Implementation status and qualification results are in [implementation progress](../implementation-progress.md), not here.

## Read by question

| Question | Architecture view |
| --- | --- |
| What runs, where, under which identity? | [Applications and deployment](applications.md) |
| Which component owns a feature and its state? | [Components and ownership](components.md) |
| What can cross a boundary? | [Internal interfaces](interfaces.md) and [control-work schema](../../specs/contracts/internal-work.schema.json) |
| What happens during success, retry and failure? | [Runtime walkthroughs](runtime.md) |
| Where should code live, and what may it import? | [Code organization](code-organization.md) |
| What should be implemented and proven first? | [Implementation slices](implementation-slices.md) |
| Which decisions are sourced, selected or still unqualified? | [Research and decisions](research.md) |
| Which technologies and third-party pieces implement each component? | [Build or reuse](build-or-reuse.md), [technology choices](../technology.md) |
| How can small installations avoid separately operated infrastructure? | [Dependency research and recommendations](../research/small-deployments.md), [deployment requirements](../../specs/deployment-profiles.md) |
| How is Asservat installed? | [Helm installation](../installation/helm.md) |
| How does a workload cluster connect? | [Connector identity](connector-credentials.md), [cluster state push](cluster-observations.md) |
| What can an agent check mechanically? | [Architecture catalog](catalog.yaml) and `make architecture-check` |

The vocabulary has four levels. An **application role** is a separately scheduled process/Job or host executable with its own authority. A **component** owns a cohesive responsibility and its state transitions. A **code module** is a package family implementing that component; it is not automatically a separate Go module or network service. An **interface** is a versioned network/IPC contract or a typed in-process port. Diagrams use C4-style levels in Mermaid; “application” avoids confusing the C4 term “container” with Kubernetes containers. Public collection and permission scope remains the whole pod.

## Selected shape

A modular Go hub with separately runnable API and worker roles. Each workload cluster runs a connector with one outbound multiplexed mTLS connection to the hub, privileged node collectors and a long-running regional reader Deployment that serves native downloads and stored-evidence queries. A minimal Rust helper handles the host crash path. Offline analysis uses separate acquisition, analysis and publication Jobs. One reviewed Go codebase and role-selecting binary; images, credentials and network policy separate execution authority. Inspektor Gadget is a pinned external dependency. No component becomes a microservice solely because it appears in a diagram. The React/TypeScript console is a static build served by the Go API role.

PostgreSQL owns hub transactions, audit rows and small metadata; Kubernetes owns configuration (watched by informers) and local execution; regional object storage owns envelope-encrypted evidence. Hub processes signal each other with `LISTEN/NOTIFY`; browsers receive status over Server-Sent Events. Browser and MCP are adapters over the same application services. External effects leave the hub transaction before execution and carry an idempotency key, so a retry returns the recorded outcome.

## Authority of these artifacts

The behavioral requirements and canonical public schemas remain authoritative for user-visible semantics. [REQ-ARC-001–007](../../specs/implementation-architecture.md) specify this decomposition. The catalog is the canonical list of application/component IDs, dependency allowances, entity owners, requirement owners and interface endpoints. Prose explains their contracts; it does not create an independent API vocabulary.

Every requirement has one primary implementation owner in the catalog; collaborators may participate. Each domain entity has one lifecycle owner even when several application roles run its code.

An implementation task should read its requirement, catalog owner, relevant component/interface, runtime flow and slice acceptance tests. Empty package directories, illustrative Go signatures and successful schema validation are not evidence that a collector or security boundary works.

## Feature documents

- [Regional Kubernetes API context](api-context-execution.md)
- [Regional API context execution](api-context-runner.md)
- [Persistent artifact format and commit boundary](artifact-format.md)
- [Browser sessions](browser-sessions.md)
- [Capacity production](capacity-production.md)
- [Cluster state push](cluster-observations.md)
- [Connector identity](connector-credentials.md)
- [Production console](console-runtime.md)
- [Context planning and admission](context-admission.md)
- [Pod-status assessment](context-assessment.md)
- [Collector capability and submission](context-capability.md)
- [Case metadata through browser and MCP](context-case-transport.md)
- [Ordinary context cases](context-cases.md)
- [Context control capacity](context-control-capacity.md)
- [Context evidence deletion](context-deletion.md)
- [Context download control](context-download-control.md)
- [Capture → evidence details → native download](context-evidence-workflow.md)
- [Shared manual context investigation](context-investigation.md)
- [Native content delivery](context-native-content.md)
- [Browser and MCP context operations](context-operations.md)
- [Context capture progress](context-progress.md)
- [Bounded approved context projection](context-projection.md)
- [Context publication](context-publication.md)
- [Stored-evidence query capacity](context-query-capacity.md)
- [Current identity across browser and MCP operations](current-request-identity.md)
- [Initial storage custody transactions](custody-transactions.md)
- [Current context-download authorization](download-authority.md)
- [Current processing and download environment](download-environment.md)
- [Local keys for current downloads](download-key-authority.md)
- [Current recovery fencing for downloads](download-recovery.md)
- [Bounded native response accounting](download-responses.md)
- [Native download sessions and accounting](download-sessions.md)
- [Prepaid Stop lifecycle](download-stop-lifecycle.md)
- [Download worker identity and key access](download-worker-attestation.md)
- [Download worker dispatch and cleanup](download-worker-dispatch.md)
- [Audited connector activation](enrollment-activation.md)
- [One-use connector bootstrap claims](enrollment-claims.md)
- [Protected fleet administration](fleet-administration.md)
- [Protected fleet trust observation](fleet-observation.md)
- [Hub owner discovery and certificate verification](hub-owner-discovery.md)
- [Initial identity and ordinary eligibility boundary](identity-eligibility.md)
- [Keycloak reference identity profile](keycloak-profile.md)
- [Protected local key lifecycle](local-key-lifecycle.md)
- [Private local key service](local-key-service.md)
- [Local key foundation](local-keys.md)
- [Local durable start journal](local-start.md)
- [Initial complete-manifest verification](manifest-verification.md)
- [MCP runtime boundary](mcp-runtime.md)
- [Native download interruption and explicit restart](native-download-retry.md)
- [Approved context native exchange](native-exchange.md)
- [Private native owner serving](native-owner-listener.md)
- [Identity during a native response](native-reader-identity.md)
- [Node collector role and work channel](node-collector.md)
- [Public context operation audit](operation-audit.md)
- [Current peer identity](peer-identity.md)
- [Permission acceptance and durable assignment history](permission-acceptance.md)
- [Kubernetes permission observation boundary](permission-observation.md)
- [Pinned pod resolution](pod-resolution.md)
- [Team automation authority components](policy-automation.md)
- [Processing coverage at context admission](processing-admission.md)
- [Public context endpoint composition](public-context-composition.md)
- [Ordinary context download operations](public-context-download.md)
- [Regional API context start](regional-context-start.md)
- [Applying retained policy history](retention-catchup.md)
- [Durable retention policy checkpoints](retention-checkpoints.md)
- [Retention checks at effect transactions](retention-effects.md)
- [Existing-evidence retention lifecycle](retention-lifecycle.md)
- [Retention policy observation and matching](retention-observation.md)
- [Bounded Go runtime-profile acquisition](runtime-profiles.md)
- [Acquisition worker startup and supervision](worker-startup.md)
- [Named workload target resolution](workload-target-resolution.md)
