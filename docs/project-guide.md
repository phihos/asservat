# Project guide

The detailed project orientation that previously opened the repository README:
component status notes, the full reading map, confirmed product decisions and the
validation commands. The [README](../README.md) is the short introduction.

See [product implementation status](implementation-status.md) for the current
feature inventory, verified user outcomes and remaining work. Component tests and
design documents do not establish a completed installed debugging platform.

[First-installation activation](architecture/initial-installation.md) now composes the protected Kubernetes witness and fleet source with locked SQL eligibility checks and verified encrypted audit. Native component tests pass; production installer provisioning and restart/restore coordination remain pending. [Implementation progress](implementation-progress.md) records the exact qualification scope.

[The one-use installation witness](architecture/installation-witness.md) now has native Kubernetes qualification. It preserves an irreversible initial-attempt record outside SQL; the runnable installer and restart/restore coordinator remain pending. Implementation has resumed from this component checkpoint; see [implementation progress](implementation-progress.md).

[Database recovery fencing](decisions/096-database-incarnation-fence.md) now binds effective authority to the accepted PostgreSQL process/database. A restored enabled flag alone cannot reopen access. Independent initial/restore activation and the complete installer remain pending; qualification is tracked in [implementation progress](implementation-progress.md).

[Protected configuration reconciliation](architecture/configuration-reconciliation.md) now runs the actual private `hub-worker` executable in a Restricted Pod with [native projected credentials](decisions/094-native-hub-worker-projections.md). The owned native case verifies audited observation, source/Lease loss and [normal foreground deletion](decisions/095-hub-workload-garbage-collection.md). It cannot clear recovery. Full-suite results and limits are in [implementation progress](implementation-progress.md); production provisioning, independent initial/restore activation and public investigation routes remain pending.

[Protected owner deployment](architecture/owner-deployment.md) now loads fixed installation projections, scoped provider credentials and rotating tokens through the private `hub-api` entry point. Automatic provisioning, source/recovery reconciliation and native in-Pod deployment remain pending; public investigation routes are not enabled.

[Multi-cluster worker routing](architecture/worker-routing.md) now selects each worker's stored profile and exact issuer trust, with separate profile-scoped effect permissions. Protected installation synchronization and native deployment qualification remain pending.

[Owner startup composition](architecture/owner-startup.md) now joins credential renewal, private receiving, live forwarding and expiring readiness without a Kubernetes Ready dependency cycle. The protected loader and entry point are described above; native in-Pod qualification remains pending.

[Live owner delivery](architecture/owner-forwarding.md) now keeps the original enrollment operation connected through the final worker response, with bounded cancellation and no protocol replay. Protected startup, native routing and evidence transfer remain pending; [implementation progress](implementation-progress.md) records actual verification.

[Outbound owner transfer](architecture/owner-forwarding.md) now verifies the exact current hub and locator before sending a Pod token, rejects replay/redirects and validates the returned worker certificate. Protected startup and native routing remain pending; [implementation progress](implementation-progress.md) records measured scope.

[The private owner receiver](architecture/owner-relay.md) now connects current hub identity and exact live request ownership to bounded mutual-TLS HTTP handling. Outbound forwarding and protected in-Pod startup remain pending; verification is recorded in [implementation progress](implementation-progress.md).

[Process-owned hub credentials](architecture/owner-credentials.md) now add separate server/client keys, audited enrollment verification, finite renewal and shutdown. Protected startup and private forwarding remain pending; actual qualification is tracked in [implementation progress](implementation-progress.md).

[Current hub peer authentication](architecture/owner-authentication.md) now combines actual TLS, durable registration, workload protection and Ready routing. Native proof-to-activation integration and its remaining bootstrap/transport boundaries are tracked in [implementation progress](implementation-progress.md).

[Durable hub owner enrollment](architecture/owner-registration.md) now adds registration, bounded signing spend, encrypted audit and separate certificate activation/current registry. Verification and remaining runtime composition are tracked in [implementation progress](implementation-progress.md).

[Hub owner enrollment proof](architecture/owner-enrollment-proof.md) now verifies the current Pod token, workload membership and CSR before readiness. Its durable lifecycle is specified in [owner registration](architecture/owner-registration.md); measured scope is in [implementation progress](implementation-progress.md).

The [private hub workload protection](architecture/owner-workload-protection.md) now adds native namespace admission and independent enforcement proof. Owner enrollment and protected installation composition remain pending; see [implementation progress](implementation-progress.md) for measured scope.

Asservat is a proposed Kubernetes debugging platform that preserves evidence when a workload behaves suspiciously and makes that evidence available to developers and their AI agents through controlled MCP queries and authenticated native-file downloads for local tools.

The pod is the unit of configuration, permission and collection; container/process identity is retained internally for provenance. Monitor all authorized replicas within administrator limits and bound collection separately.

Point a policy at a Deployment, StatefulSet, or selected pods. Combine log patterns, resource thresholds, probe failures, crashes, and external alerts with bounded evidence recipes: logs, container files and `/proc`, packet captures, pprof and similar runtime profiles, core dumps, bounded syscall traces, and custom commands. Versioned capture profiles let users compose and adapt these collectors. Collection and analysis run close to the workload; one central service manages multiple clusters, cases, approvals, and sharing.

**Status: reviewed design with Go authority, browser sessions, encrypted pod-context, SQL publication and native-download components; no complete investigation service is implemented or deployed.** Work recorded on 2026-10-09 includes Gadget capture in a disposable Kubernetes VM, encrypted object-storage/native downloads, PostgreSQL concurrency tests and a disposable-VM core helper with local debugger verification. These establish limited mechanism behavior, not production support; broader integration and performance investigations remain release gates. The [artifact foundation](research/artifact-foundation.md), [custody continuation](research/custody-foundation.md) and [full-manifest verification](research/manifest-foundation.md) record implemented packages and their limits; [ADR-048 storage format](architecture/artifact-format.md) fixes the implementation contract. Context verification leaves artifacts unpublished; production authority composition and the user workflow remain pending.

The [identity continuation](research/identity-foundation.md) adds a bounded access-token adapter and ordinary permission evaluator, including current organization/client policy, deny precedence and retained audiences. Its HTTPS/JWT tests use synthetic policy projections. The [Keycloak reference profile](architecture/keycloak-profile.md) and [browser-session flow](architecture/browser-sessions.md) now pass real token/PKCE/refresh, encrypted session and provider logout qualification; operator realm acceptance and end-to-end execution/publication composition remain required before collection or disclosure is enabled. Subsequent protected readers, explicit-binding reconciliation and encrypted intent audit are recorded in [implementation progress](implementation-progress.md).

[Team automation](architecture/policy-automation.md) now has protected administrator envelopes, durable policy acceptance and encrypted audit with current source/delegation checks. Team policies use independent bounded authority without retaining a developer's offline SSO credentials. [Browser settings](decisions/061-current-browser-configuration.md) now have current Kubernetes-to-SQL observation, administrator lifetime ceilings and outage-safe logout. Production signed submissions, protected bootstrap and execution composition remain pending; the [progress record](implementation-progress.md) distinguishes measured component tests from unfinished runtime work.

The [permission observation continuation](research/permission-foundation.md) adds concrete Kubernetes binding/source readers and selected namespace metadata, with real API/RBAC tests. Observed configuration and mapping proposals do not grant access: the [acceptance continuation](research/permission-acceptance-foundation.md) adds SQL assignment history, encrypted authority audit and structural CRD/native admission components; protected source qualification and end-to-end authority wiring remain pending. Ordinary eligibility now separately enforces the specified five-second deny freshness limit.

The [local start journal](architecture/local-start.md) now consumes exact prepaid attempts through Kubernetes CAS; real API tests cover duplicates, restart and role separation. [Peer identity](architecture/peer-identity.md) adds real TLS verification, protected signing-key reads and current SQL connector registration checks. The [enrollment coordinator](architecture/enrollment-activation.md) now composes bounded PKI signing, encrypted claim/certificate audit and atomic activation with real-provider tests. [Fleet administration](architecture/fleet-administration.md) and the [credential channel](architecture/bootstrap-channel.md) are also implemented components. [Audited administrator issuance](architecture/bootstrap-issuance.md) also passes composed provider tests. Protected trust/recovery and public collection remain incomplete.

## Start here

**Official installation method: Helm.** The [chart](../charts/asservat/README.md) installs the configuration foundation and includes an optional initial database/bootstrap hook with a passing packaged real-service test. The [progress record](implementation-progress.md) retains the earlier unexplained hook failure and exact test scope. See the [installation guide](installation/helm.md) for commands, scope and upgrade behavior. Runnable platform services are still in progress; this development chart does not deploy a working debugging service. Keycloak is the first tested external identity provider. [Accepted small-deployment alternatives](research/small-deployments.md) add local users/login, static-key services, bundled PostgreSQL and an evidence-store option; these are not implemented chart features yet.

The first [local wrapping/signing backends](architecture/local-keys.md), provider-neutral credential encryption and [private mTLS key-service components](architecture/local-key-service.md) are implemented. [Protected key lifecycle](architecture/local-key-lifecycle.md) now supplies immutable Secret reads and durable additive-rotation checks. Remaining current-authority providers, source enrollment/issuer/retirement, local login and bundled-service installation remain pending.

The initial [download key resolver](architecture/download-key-authority.md) now checks an audited SQL download batch and its exact acquisition certificate before local unwrap. [Current worker proofs](architecture/download-worker-attestation.md) additionally bind that grant to a Kubernetes Pod-bound token and exact live Job/account/spec identities. [Audited dispatch](architecture/download-worker-dispatch.md) now adds the restricted Job driver and durable launch/retirement accounting. [Protected worker configuration](architecture/worker-configuration.md) adds administrator admission proof, separately audited SQL revisions and original freshness deadlines. [Worker credential enrollment](architecture/worker-enrollment.md) now adds Pod/token/CSR proof, independently audited issuance/activation and bounded renewal. [Process-owned worker credentials and a private enrollment channel](architecture/worker-credential-channel.md) now connect the CSR/token exchange to active control requests. The initial [worker startup](architecture/worker-startup.md) now validates typed immutable trust/configuration and supervises the credential phase. [Active request ownership](architecture/worker-request-routing.md) now adds bounded process-local routing and cancellation through certificate delivery. [Shared worker request locators](architecture/worker-owner-locator.md) now provide finite SQL ownership and exact local receiving. [Hub owner discovery](architecture/hub-owner-discovery.md) now supplies bounded Kubernetes endpoint observations and exact TLS Pod/process identity verification. [Protected owner configuration](architecture/owner-configuration.md) now supplies admission-qualified pool/public-root observations and current route composition. [Durable owner acceptance](decisions/078-owner-configuration-acceptance.md) now records monotonic revisions, failure watermarks and independently verified encrypted audit before current recovery-bound reads. [Hub owner certificate issuance](architecture/owner-issuance.md) now supplies purpose-separated OpenBao signing and exact current-root/CSR verification. [Durable owner enrollment](architecture/owner-registration.md) now adds audited registration/activation and bounded history. Protected recovery/workload/issuer bootstrap, private forwarding, connector proof mediation, actual native transfer, local CA and public download workflows remain pending.

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
| [PostgreSQL reassessment](../specs/changes/postgresql-hub-state/proposal.md) | Accepted change: Kubernetes configuration, PostgreSQL hub state, object-store evidence |
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

`make architecture-check` adds component/dependency ownership, internal control-contract examples and synthetic retry/fencing checks. `make design-check` checks the domain, screens and browser/MCP contract mapping. These gates validate the design. `make go-check` and `make go-architecture-check` validate the implemented Go components; `make context-integration` creates owned real-service fixtures for their integration test. None establishes a complete production investigation.

`make custody-integration` creates owned PostgreSQL/S3 fixtures for storage-accounting races and verified version/multipart cleanup. `make sql-tools` installs pinned development tools; `make sql-check` detects generated query drift. Set `TMPDIR` to a filesystem with adequate space when building Go; on this workstation use `/home/phil/.cache/asservat-build/tmp`.

`make database-recovery-integration` upgrades an enabled synthetic legacy root, restarts its owned PostgreSQL container, and restores a logical backup into a new database. Product authority readers must reject each unaccepted incarnation. Independent activation is fixture-only; this does not qualify production disaster recovery.

`make context-integration` also verifies the complete pod-status artifact through Kubernetes, OpenBao, S3 and PostgreSQL in one fixture. `make manifest-schema-check`, included in `go-check`, rejects drift between canonical and embedded schemas. These checks do not provide end-user authority or publish evidence.

`make permission-integration` creates and removes its own Kind cluster for permission observation/RBAC tests. Its permissive test CRDs are not production installation manifests. `make permission-schema-check`, included in `go-check`, validates the reader's embedded schema bundle.

The recorded documentation check is in [spec-validation.txt](research/spec-validation.txt).

Native downloads for every collected artifact and saved derivative are specified in [artifact-downloads.md](../specs/artifact-downloads.md). This supersedes the original raw-file export restriction; managed encryption, current access and raw-download grants still apply.

The [review from user outcomes](reviews/user-task-review.md) records additional task blockers, applied contract corrections and outstanding recommendations. [Combined investigation approval](../specs/investigation-approval.md) implements the accepted one-review decision in the design; no runtime has been built.

`make fleet-integration` owns PostgreSQL/S3/OpenBao fixtures for credential-channel, enrollment and current TLS-registration tests. It does not create Kubernetes clusters or install collectors.

`make helm-check` validates and packages the official chart without a cluster. `make helm-integration` creates and removes its own Kind cluster to test the chart's configuration install/upgrade/rollback/uninstall lifecycle and preserved custom resources. Neither enables collection.

[Native download sessions](architecture/download-sessions.md) now pass bounded SQL/S3/HTTPS component tests, including current permission fencing, encrypted intent/outcome audit, partial/full file recovery and a checksum-verified synthetic local file. This does not enable public downloads: browser/OAuth ingress, production authority/retention/restore composition and regional relay remain required.
