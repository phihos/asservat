# Code organization and dependency rules

This is the canonical implementation layout, replacing the earlier independent package sketches. Initial domain/ports/storage/KMS/Kubernetes, identity, ordinary-authorization and configuration-observation packages now exist; other paths remain planned. Permission spec DTOs exist under `api/v1alpha1`; generated structural CRDs and native admission builders now exist; protected bootstrap/source qualification and production composition remain open. No empty implementation directories are required. Keep one Go module for the Go product initially, with a separate Rust crate for the host helper and a locked React/TypeScript workspace for the console. A “module” below means a cohesive package family, not a separately versioned service or `go.mod`.

```text
cmd/asservat/                    role selection; minimal entry point
internal/bootstrap/             composition roots for each allowed runtime role
internal/domain/                C-24: pure typed values and transitions by domain area
internal/application/
  configuration/ identity/ authorization/ fleet/ targets/
  planning/ capacity/ audit/ capture/ monitoring/ execution/
  recording/ live/ evidence/ privacy/ catalog/ sharing/ analysis/ delivery/
internal/transport/             browser, mcp, admission, federation, node, ownerrelay, native
internal/console/               embedded assets, app shell and presentation adapters
web/                            React/TypeScript console; C-20; local styles and generated API types
internal/adapters/
  postgres/ kubernetes/ objectstore/ kms/ oidc/ bleve/
  cri/ linux/ gadget/ diagnostics/ tools/
internal/contracts/             reviewed internal transport DTOs; no business authority
api/v1alpha1/                   Kubernetes structs, generated structural schemas/deepcopies
crash-helper/                   isolated Rust crate and local IPC contract fixtures
runtime-packs/                  pinned tools, projection definitions and manifests
charts/asservat/                hub/cluster install profiles, generated CRDs, values schema
migrations/                    ordered SQL migrations and query contracts
test/                          integration, e2e, fuzz, fixtures and benchmarks
scripts/                       existing design gates and future portable local gates
```

Unit tests live next to packages under normal Go conventions. Production command names are the role entry points in [applications](applications.md); they are not installed commands yet.

## Dependency direction

```mermaid
flowchart LR
  Main[cmd / bootstrap] --> Transport[transport / console]
  Main --> Adapters[concrete adapters]
  Main --> App[application services]
  Transport --> App
  App --> Domain[pure domain types]
  Adapters --> Ports[consumer-owned application ports]
  Ports --> Domain
```

Only bootstrap chooses concrete adapters, credentials and role capabilities. Domain packages import standard-library value utilities and other explicitly allowed domain values only. `net/netip` is allowed for pure canonical IP parsing/classification; `net` sockets/DNS and HTTP remain infrastructure. They do not depend on logging globals, SQL, Kubernetes, HTTP, MCP, clocks, randomness or filesystem I/O. Pass time/identity inputs to pure rules; inject clock/ID generation at the application boundary.

Application packages contain use-case services, state transition orchestration and the interfaces they consume. They may import other application packages only along the catalog's allowed dependency graph; use the smallest public service/facet. Adapters implement those interfaces and may import the consumer's port types. Application code never imports concrete adapters or transport packages. In-memory fakes belong to tests and must obey the same purpose/bound invariants; they are not alternate production storage modes.

Transport packages decode/encode typed DTOs, authenticate at ingress, enforce byte limits and map errors to the existing browser/MCP/peer contract. They call application services. They do not query SQL directly or embed policy logic in a template/tool handler. React renders escaped data from current-authority presentation projections; a DTO copied from a page is never an accepted execution scope.

Shared `internal/contracts` DTOs may be imported by transport/adapters and conversion packages. Domain services receive explicit domain values, not CRD/JSON structures. `api/v1alpha1` represents Kubernetes configuration/local resources only; SQL grant/share/live-watch records do not become CRDs. A value may be represented in several layers with explicit conversion tests.

C-20 owns shared `api/v1alpha1` and `internal/contracts` wire shapes as well as transports. The adapter-to-C-20 edge permits these DTO packages only; the Go gate rejects imports of transport handlers from adapters and imports of internal behavior from shared DTOs. Domain/application packages retain their existing restrictions. This assigns the formerly planned top-level DTO paths without treating Kubernetes representations as pure domain values.

## Transaction and lifecycle boundaries

Keep named transaction ports beside their coordinating application service. For example, `capture.AdmissionTransaction` exposes grant/capacity/registration/operation facets over one SQL transaction. Its PostgreSQL implementation is under `adapters/postgres`; facet mutation rules call owner-domain logic. The callback must be deterministic with respect to provided facts and must not invoke an adapter with remote effects. No generic transaction handle leaks back into services.

Keep local `execution.StartJournal` and `capacity.LocalAdmission` separate from hub transaction interfaces. Their Kubernetes adapter uses CAS and prepaid bundles; it cannot satisfy a hub SQL transaction through the same interface. Collection and snapshot/live/cleanup purposes have disjoint argument types and entry methods. Do not create a generic event bus that loses those distinctions.

Application context carries validated actor/client, region, trace/operation identity and cancellation. It does not carry arbitrary client-supplied authority. Constructors are not cryptographic capabilities; trust comes from the checked ingress and revalidation chain. Avoid exported mutable global registries and service locators. Mechanism registration is a static allowlist assembled by bootstrap, with pinned runtime packs.

## Package size and abstraction

[First-installation activation](initial-installation.md) adds C-04 preparation/activation ports and coordinator, C-08 audit ports/domain record and C-21 PostgreSQL/S3 adapters. Bootstrap owns the distinct temporary credentials; ordinary runtime code receives no activation writer. Migration 00032 and its reviewed table inventory bound the initial-state check.

[Initial-installer execution](initial-installer.md) composes those ports only in A-INSTALL's private bootstrap. C-20 owns its closed public-input DTO, C-21 owns native namespace/Pod proof and inert workload generation, and configuration domain values describe the installation-owned pins. This executable cannot migrate or restore a database.

[Installation witness](installation-witness.md) uses C-04 fleet ports/domain values and the C-21 Kubernetes adapter. Its private wire schema and inert installer helpers grant no SQL activation authority; no separate public entity, service or package family is introduced.

C-21 PostgreSQL authority helpers use SQLC's effective `FleetCurrentTrust` row from migration 00031, never the stored `FleetTrust` projection. This preserves the [database incarnation fence](../decisions/096-database-incarnation-fence.md) across existing C-04/C-14 consumers without introducing another public model or service.

Each component has a package family, not a package per entity. Split a family when it has a coherent independently testable responsibility; do not create one-interface packages or one repository per domain entry. `planning` may have composition/assessment/guidance subpackages; `monitoring` may have detector/expression/correlation subpackages. Public ports and domain types should remain small enough that unrelated callers do not import runtime-heavy tools.

Use tagged finite action/query unions rather than a generic payload map. Mechanisms need bounded writers and cancellation/coverage outcomes, not a universal executor capable of running arbitrary code. Keep collector-specific kernel details inside adapters; user-facing targeting remains pods even when execution pins internal runtime/process identities.

## Architecture checks

**Existing after this design pass:** `make architecture-check` validates catalog IDs/paths, acyclic allowed component dependencies, layer restrictions, complete domain/requirement ownership, application/interface endpoints, strict internal-work examples and negative/semantic cases. It performs bounded synthetic retry/fence checks. It does not inspect production Go imports or validate real distributed execution. The added `make go-architecture-check` now inspects actual Go packages against this catalog.

**Implemented initial code gate:** `make go-architecture-check` derives an import graph with Go tooling and maps each product package to a catalog component. It rejects unmapped packages, forbidden layer imports and undeclared cross-component imports; Go compilation and the design catalog gate reject dependency cycles. Bootstrap is an explicit exception only for wiring. Continue extending adapter conformance, separate role credential wiring, generated schema drift, round-trip/domain-conversion fixtures and canonical scope byte checks as those components appear. Cross-language helper fixtures validate only its narrow IPC; it must not acquire the Go service graph through a subprocess.

Task handoffs name affected component IDs, requirements, changed ports, schema/version effects and actual tests. Use the same portable Make gates locally and in future CI. Code ownership rules and review criteria should follow component responsibilities once a remote/team workflow is selected; this design does not invent a CI provider or team assignments.

The first concrete composition root is [download worker startup](worker-startup.md): `cmd/asservat` selects `download-worker`, `internal/bootstrap` validates fixed inputs/process protections and binds C-21 credentials to the C-14 supervisor. This executable implements credentials only; the remaining role entry points and full acquisition workflow are still planned.

[Owner runtime composition](owner-startup.md) now also lives in `internal/bootstrap`: it creates owned purpose keys and joins renewal, readiness, private listening and forwarding. The [deployment loader](owner-deployment.md) now wires fixed installation inputs and the private hub command; automatic provisioning and native in-Pod qualification remain pending. The composition exception permits wiring existing adapters and transports; it does not permit application/domain packages to import them.

The C-21 [multi-cluster routing adapters](worker-routing.md) implement existing C-14 read ports without widening effect facets. `mtls.WorkerTrustCatalog` owns immutable public control snapshots; bootstrap supplies it to the owner runtime. No domain-to-transport dependency or new public wire is introduced.

[Configuration reconciliation](configuration-reconciliation.md) adds a C-04 serial observer-loop supervisor and C-21 protected fleet/Lease adapters. The private `hub-worker` loader composes them through the same fixed provider connection helpers as owner startup, with separate credentials and no recovery activation port.

C-21 `kubernetes.BuildHubWorkerWorkload` builds installation-owned native Deployment/account/RBAC resources under [ADR-094](../decisions/094-native-hub-worker-projections.md). It does not apply objects, resolve recovery or introduce a public wire; bootstrap remains the role composition root.
